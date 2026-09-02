"""Tests for TimeBasedSQLiCheck."""
import re
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.sqli import (
    _DELAY_PAYLOADS,
    REPROBE_SAMPLES,
    REPRODUCTION_SAMPLES,
    TimeBasedSQLiCheck,
)
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies
from redveil.validation.control_probe import (
    INCONCLUSIVE,
    RATE_LIMITED,
    TIMING_ANOMALY,
    TIMING_FLAKY,
    TIMING_REPRODUCIBLE,
    WAF_INTERFERENCE,
)


def _resp(body: str = "", status: int = 200, elapsed_ms: float = 10.0):
    return Response(request_id="r1", status_code=status, headers={}, body=body, elapsed_ms=elapsed_ms)


def _bind(check, side_effects, active: bool = True, ack: bool = True,
          allow_destructive: bool = False, gate_approved: bool = True):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active
    cfg.authorization.acknowledged_safety_terms = ack
    cfg.authorization.allow_destructive = allow_destructive
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock(side_effect=side_effects)
    # Mock the gate
    mock_gate = MagicMock()
    decision = MagicMock()
    decision.approved = gate_approved
    decision.plan = MagicMock()
    decision.reason = "test-mock"
    decision.__bool__ = lambda self: self.approved
    mock_gate.ask.return_value = decision
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=mock_gate,
    )
    check.bind(deps)
    return mock_http


def _is_probe_url(url: str) -> bool:
    """Return True if the URL contains one of the time-delay payloads."""
    upper = url.upper()
    return any(
        tok in upper
        for tok in ("SLEEP", "PG_SLEEP", "WAITFOR", "RANDOMBLOB")
    )


def _is_baseline_or_control_url(url: str) -> bool:
    """Baseline/control URLs use the literal token ``redveil_baseline``."""
    return "redveil_baseline" in url or (
        "?" in url and "=" in url and not _is_probe_url(url)
    )


def _make_url_side_effect(
    baseline_ms: float = 50.0,
    baseline_samples: list[float] | None = None,
    probe_ms: float = 3000.0,
    probe_samples: list[float] | None = None,
    control_ms: float = 50.0,
    waf: bool = False,
    rate_limit: bool = False,
    body: str = "ok-response-body",
    baseline_body: str = "ok-response-body",
):
    """Build a side_effect function that returns Responses based on the URL.

    The TimeBasedSQLi check now runs the new control+probe+replay sequence
    per (param, payload) pair. Tests need to return the right timing for
    each URL category. This helper returns a function that:

      - returns ``baseline_samples[i]`` (or ``baseline_ms`` if not given) for
        the i-th baseline call
      - returns ``control_ms`` for control calls
      - returns ``probe_samples[i]`` (or ``probe_ms``) for the i-th probe call

    A single side-effect callable is easier to reason about than a flat
    list of 576 responses. Default body is the same for baseline and probe
    so the WAF detector does not false-positive on body-length deltas.
    """
    base = list(baseline_samples) if baseline_samples is not None else None
    probe = list(probe_samples) if probe_samples is not None else None
    state = {"baseline_i": 0, "control_i": 0, "probe_i": 0}

    def side_effect(req):
        url = req.url
        if waf and _is_probe_url(url):
            state["probe_i"] += 1
            return _resp(
                body=body,
                status=403,
                elapsed_ms=50.0,
            )
        if rate_limit and _is_probe_url(url):
            state["probe_i"] += 1
            return _resp(body=body, status=429, elapsed_ms=10.0)
        if _is_probe_url(url):
            i = state["probe_i"]
            state["probe_i"] += 1
            if probe is not None:
                t = probe[i] if i < len(probe) else probe[-1]
            else:
                t = probe_ms
            return _resp(body=body, elapsed_ms=t)
        if "redveil_baseline" in url:
            i = state["baseline_i"]
            state["baseline_i"] += 1
            if base is not None:
                t = base[i] if i < len(base) else base[-1]
            else:
                t = baseline_ms
            return _resp(body=baseline_body, elapsed_ms=t)
        # control URL (same as baseline in this check)
        i = state["control_i"]
        state["control_i"] += 1
        return _resp(body=baseline_body, elapsed_ms=control_ms)

    return side_effect


@pytest.mark.asyncio
async def test_active_required():
    check = TimeBasedSQLiCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = TimeBasedSQLiCheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_no_timing_delta_no_finding():
    """When probe timing is the same as baseline, all candidates are
    emitted with INCONCLUSIVE verdict (no real finding)."""
    check = TimeBasedSQLiCheck()
    fast = _resp(elapsed_ms=50.0)
    # New pattern runs 9 calls per (param, payload) pair, 64 pairs = 576 calls.
    _bind(check, [fast] * 700)
    cands = await check.discover(MagicMock())
    # Every (param, payload) pair emits a candidate. None should be CONFIRMED.
    assert len(cands) > 0
    for c in cands:
        assert c["verdict"] == INCONCLUSIVE


@pytest.mark.asyncio
async def test_timing_delta_3x_baseline_detected():
    """When the probe triggers a reproducible slow response, at least one
    candidate is emitted with TIMING_REPRODUCIBLE verdict."""
    check = TimeBasedSQLiCheck()
    side_effect = _make_url_side_effect(
        baseline_ms=50.0,
        probe_ms=3000.0,
    )
    _bind(check, side_effect)
    cands = await check.discover(MagicMock())
    # At least one CONFIRMED candidate (the first payload for the first
    # param, where the probe was 3000ms vs 50ms baseline).
    confirmed = [c for c in cands if c["verdict"] == TIMING_REPRODUCIBLE]
    assert len(confirmed) >= 1
    c = confirmed[0]
    ratio = c["probe_median_ms"] / max(c["baseline_median_ms"], 1.0)
    assert ratio >= 3
    assert c["probe_median_ms"] >= 2000


@pytest.mark.asyncio
async def test_validate_confirmed_for_strong_delay():
    check = TimeBasedSQLiCheck()
    candidate = {
        "verdict": TIMING_REPRODUCIBLE,
        "baseline_median_ms": 50.0,
        "probe_median_ms": 3000.0,
        "baseline_cv_pct": 0.0,
        "reproducibility": None,
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = TimeBasedSQLiCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET", "db_family": "mysql",
        "payload": "1' AND SLEEP(3)-- -",
        "verdict": TIMING_REPRODUCIBLE,
        "baseline_median_ms": 50.0,
        "probe_median_ms": 3000.0,
        "baseline_cv_pct": 0.0,
        "reproducibility": None,
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "high"
    assert "CWE-89" in f.cwe
    # CONFIRMED findings do not need a reason — the technical text
    # already covers the reproducible case.
    assert "Inconclusive reason:" not in f.technical_explanation


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verdict,expected_substring",
    [
        (WAF_INTERFERENCE, "WAF or intermediary"),
        (RATE_LIMITED, "rate-limited"),
        (TIMING_FLAKY, "unstable"),
        (TIMING_ANOMALY, "inconsistent"),
        (INCONCLUSIVE, "did not produce a reproducible timing delta"),
    ],
)
async def test_assess_appends_verdict_reason_for_inconclusive(verdict, expected_substring):
    """INCONCLUSIVE findings must carry the specific verdict reason
    in technical_explanation so the UI can render the cause rather
    than a generic badge."""
    check = TimeBasedSQLiCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET", "db_family": "mysql",
        "payload": "1' AND SLEEP(3)-- -",
        "verdict": verdict,
        "baseline_median_ms": 50.0,
        "probe_median_ms": 0.0,
        "baseline_cv_pct": 0.0,
        "reproducibility": None,
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.status.value == "inconclusive"
    assert "Inconclusive reason:" in f.technical_explanation
    assert expected_substring in f.technical_explanation


@pytest.mark.asyncio
async def test_baseline_instability_returns_inconclusive():
    """High-variance baseline (50, 500, 100 ms) → CV > 30% → TIMING_FLAKY."""
    check = TimeBasedSQLiCheck()
    # Build a side_effect so the BASELINE × 3 returns 50, 500, 100 (high
    # variance). All other calls (control, probe) return fast values so we
    # isolate the baseline-instability branch.
    state = {"i": 0}

    def side_effect(req):
        url = req.url
        if _is_probe_url(url):
            # Probe is "slow" but we never get here because baseline
            # gate fails first.
            return _resp(elapsed_ms=3000.0)
        if "redveil_baseline" in url:
            i = state["i"]
            state["i"] += 1
            samples = [50.0, 500.0, 100.0]
            return _resp(elapsed_ms=samples[i] if i < len(samples) else samples[-1])
        # control URL
        return _resp(elapsed_ms=50.0)

    _bind(check, side_effect)
    cands = await check.discover(MagicMock())
    assert len(cands) > 0
    # All candidates should be TIMING_FLAKY because the baseline is unstable
    # for the first param; other params will reuse the same mocked HTTP
    # client and the same high-variance baseline.
    flaky = [c for c in cands if c["verdict"] == TIMING_FLAKY]
    assert len(flaky) >= 1, f"expected TIMING_FLAKY verdicts, got: {[c['verdict'] for c in cands[:5]]}"

    # The first candidate's validate() should return INCONCLUSIVE
    result = await check.validate(MagicMock(), flaky[0])
    assert result.outcome.value == "inconclusive"
    assert result.confidence == "low"


@pytest.mark.asyncio
async def test_waf_interference_returns_inconclusive():
    """Probe returns 403 with a body length very different from baseline
    → WAF_INTERFERENCE → INCONCLUSIVE outcome with medium confidence."""
    check = TimeBasedSQLiCheck()
    side_effect = _make_url_side_effect(
        baseline_ms=50.0,
        probe_ms=3000.0,
        waf=True,
        body="WAF_BLOCK_PAGE_" * 50,  # very different length from baseline
        baseline_body="ok",
    )
    _bind(check, side_effect)
    cands = await check.discover(MagicMock())
    assert len(cands) > 0
    waf_cands = [c for c in cands if c["verdict"] == WAF_INTERFERENCE]
    assert len(waf_cands) >= 1, f"expected WAF verdicts, got: {[c['verdict'] for c in cands[:5]]}"
    result = await check.validate(MagicMock(), waf_cands[0])
    assert result.outcome.value == "inconclusive"
    assert result.confidence == "medium"


@pytest.mark.asyncio
async def test_probe_not_reproducible_returns_anomaly():
    """First probe slow, second probe fast → TIMING_ANOMALY."""
    check = TimeBasedSQLiCheck()
    # Probe samples alternate slow / fast so some > 2s and some < 500ms.
    # The helper has a 2-round × 2-sample probe, so we provide 4 samples.
    side_effect = _make_url_side_effect(
        baseline_ms=50.0,
        probe_samples=[3000.0, 200.0, 3000.0, 200.0],
    )
    _bind(check, side_effect)
    cands = await check.discover(MagicMock())
    assert len(cands) > 0
    anomaly_cands = [c for c in cands if c["verdict"] == TIMING_ANOMALY]
    assert len(anomaly_cands) >= 1, f"expected TIMING_ANOMALY verdicts, got: {[c['verdict'] for c in cands[:5]]}"
    result = await check.validate(MagicMock(), anomaly_cands[0])
    assert result.outcome.value == "inconclusive"
    assert result.confidence == "low"


@pytest.mark.asyncio
async def test_reproducible_probe_with_stable_baseline_returns_confirmed():
    """Stable baseline + consistent slow probe → TIMING_REPRODUCIBLE → CONFIRMED."""
    check = TimeBasedSQLiCheck()
    side_effect = _make_url_side_effect(
        baseline_ms=50.0,
        baseline_samples=[50.0, 50.0, 50.0],
        probe_samples=[3100.0, 3050.0, 3150.0, 3100.0],
    )
    _bind(check, side_effect)
    cands = await check.discover(MagicMock())
    assert len(cands) > 0
    confirmed = [c for c in cands if c["verdict"] == TIMING_REPRODUCIBLE]
    assert len(confirmed) >= 1, f"expected TIMING_REPRODUCIBLE verdicts, got: {[c['verdict'] for c in cands[:5]]}"

    # Validate should return CONFIRMED with high confidence
    result = await check.validate(MagicMock(), confirmed[0])
    assert result.outcome.value == "confirmed"
    assert result.confidence == "high"

    # Assess should produce a Finding with CONFIRMED status
    f = await check.assess(confirmed[0])
    assert f is not None
    assert f.status.value == "confirmed"


@pytest.mark.asyncio
async def test_actionplan_max_requests_covers_worst_case():
    """The ActionPlan should declare enough max_requests for the worst case."""
    check = TimeBasedSQLiCheck()
    # We capture the plan the gate receives.
    captured = {}

    def fake_ask(plan, allow_destructive=False):
        captured["plan"] = plan
        decision = MagicMock()
        decision.approved = True
        decision.__bool__ = lambda self: True
        return decision

    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = True
    cfg.authorization.acknowledged_safety_terms = True
    cfg.authorization.allow_destructive = False
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock(return_value=_resp(elapsed_ms=50.0))
    mock_gate = MagicMock()
    mock_gate.ask = fake_ask

    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=mock_gate,
    )
    check.bind(deps)
    await check.discover(MagicMock())
    plan = captured["plan"]
    # 8 payloads * 8 params * 10 (worst case) = 640
    assert plan.max_requests == 640


def test_safety_no_data_extraction_payloads():
    """Payloads must not contain SELECT/UNION/OR 1=1 (data extraction)."""
    for db, payload in _DELAY_PAYLOADS:
        upper = payload.upper()
        # Sleep-style payloads should NOT have data extraction
        assert "UNION SELECT" not in upper, f"{payload} has UNION SELECT"
        assert "OR '1'='1" not in payload, f"{payload} has OR tautology"
        # '1 AND SLEEP(3)' is OK because it's just AND with SLEEP
        # But cap sleep at 5
        m_sleep = payload.upper().replace("SLEEP(", "").replace("PG_SLEEP(", "")
        # Check no number > 5 follows SLEEP(
        for n in re.findall(r"SLEEP\s*\(\s*(\d+)\s*\)", payload, re.IGNORECASE):
            assert int(n) <= 5, f"SLEEP({n}) exceeds cap of 5"
        for n in re.findall(r"PG_SLEEP\s*\(\s*(\d+)\s*\)", payload, re.IGNORECASE):
            assert int(n) <= 5, f"PG_SLEEP({n}) exceeds cap of 5"
        for m in re.findall(r"WAITFOR DELAY\s*'([^']+)'", payload, re.IGNORECASE):
            # Format: HH:MM:SS
            parts = m.split(":")
            assert int(parts[-1]) <= 5, f"WAITFOR DELAY seconds {parts[-1]} exceeds 5"


def test_safety_no_benchmark_high_count():
    """No BENCHMARK with iteration count > 1,000,000."""
    for db, payload in _DELAY_PAYLOADS:
        for n in re.findall(r"BENCHMARK\s*\(\s*(\d+)", payload, re.IGNORECASE):
            assert int(n) <= 1_000_000, f"BENCHMARK({n}) exceeds 1M cap"


def test_safety_payloads_unchanged():
    """The payload list must not change (no UNION/SELECT/OR data extraction)."""
    expected_signatures = {
        ("mysql", "1' AND SLEEP(3)-- -"),
        ("mysql", "1) AND SLEEP(3)-- -"),
        ("mysql", "1 AND SLEEP(3)"),
        ("postgresql", "1' AND pg_sleep(3)-- -"),
        ("postgresql", "1; SELECT pg_sleep(3)-- -"),
        ("mssql", "1'; WAITFOR DELAY '00:00:03'-- -"),
        ("mssql", "1' WAITFOR DELAY '00:00:03'-- -"),
        ("sqlite", "1' AND 1=randomblob(500000000)-- -"),
    }
    assert set(_DELAY_PAYLOADS) == expected_signatures


def test_safety_repro_constants_preserved():
    """The new repro constants must exist and be sane."""
    assert REPRODUCTION_SAMPLES >= 2
    assert REPROBE_SAMPLES >= 1
