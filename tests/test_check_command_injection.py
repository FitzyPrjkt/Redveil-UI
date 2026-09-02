"""Tests for CommandInjectionCheck — CRITICAL SAFETY TESTS."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.command_injection import (
    _DELAY_PAYLOADS,
    _FORBIDDEN_SUBSTRINGS,
    CommandInjectionCheck,
    _detect_separator,
)
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(body: str = "", status: int = 200, elapsed_ms: float = 10.0,
          headers: dict | None = None):
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
    )


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


@pytest.mark.asyncio
async def test_active_required():
    check = CommandInjectionCheck()
    _bind(check, [], active=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_acknowledgement_required():
    check = CommandInjectionCheck()
    _bind(check, [], active=True, ack=False)
    cands = await check.discover(MagicMock())
    assert cands == []


@pytest.mark.asyncio
async def test_timing_delta_detected():
    """Happy path: stable baseline + reproducibly slow probe → CONFIRMED.

    Per (param, payload) the helper consumes:
      3 baseline + 1 control + 2 probe + 1 control + 2 probe = 9 requests
    For the first (param, payload) we provide 3 stable baseline samples
    (50ms), then 1 control (50ms), 2 probe (3000ms), 1 control (50ms),
    2 probe (3000ms). The first payload matches → early-break per param.
    """
    check = CommandInjectionCheck()
    fast50 = _resp(elapsed_ms=50.0, body="ok" * 200)
    slow = _resp(elapsed_ms=3000.0, body="ok" * 200)
    side_effects = [
        # First (param, payload): 3 baseline + 1 control + 2 probe +
        # 1 control + 2 probe
        fast50, fast50, fast50,                # baseline × 3
        fast50,                                # control round 1
        slow, slow,                            # probe × 2 (round 1)
        fast50,                                # control round 2
        slow, slow,                            # probe × 2 (round 2)
    ] + [fast50] * 500
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    c = cands[0]
    # The early-break per param produces exactly one candidate for the
    # first parameter that matches.
    assert c["verdict"] == "TIMING_REPRODUCIBLE"
    assert c["ratio"] >= 3
    assert c["delay_ms"] >= 2000


@pytest.mark.asyncio
async def test_reproducible_probe_with_stable_baseline_returns_confirmed():
    """Stable baseline + reproducibly slow probe → CONFIRMED in validate()."""
    check = CommandInjectionCheck()
    # Build a candidate that mimics what discover() emits for a
    # reproducible finding. We bypass discover() and call validate()
    # directly to focus the test on the verdict mapping.
    fake_result = MagicMock()
    fake_result.verdict = "TIMING_REPRODUCIBLE"
    fake_result.baseline_median_ms = 50.0
    fake_result.baseline_cv_pct = 5.0
    fake_result.probe_samples = [3000.0, 3100.0, 3050.0, 3000.0]
    fake_result.probe_median_ms = 3000.0
    fake_result.waf_detected = False
    fake_result.rate_limited = False
    fake_result.notes = "baseline=50ms; probe_median=3000ms; ratio=60.0x"

    candidate = {
        "endpoint": "/",
        "parameter": "host",
        "method": "GET",
        "payload": "; sleep 3",
        "separator": ";",
        "baseline_ms": 50.0,
        "delay_ms": 3000.0,
        "ratio": 60.0,
        "request": MagicMock(),
        "response": MagicMock(),
        "reproducibility": fake_result,
        "verdict": "TIMING_REPRODUCIBLE",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "confirmed"
    assert result.confidence == "high"


@pytest.mark.asyncio
async def test_baseline_instability_returns_inconclusive():
    """High-variance baseline (CV > 30%) → TIMING_FLAKY → INCONCLUSIVE.

    The helper short-circuits on baseline CV > 30 % before any probe is
    run, so we only need 3 baseline samples with wild variance.
    """
    check = CommandInjectionCheck()
    # Three samples with a high coefficient of variation.
    fast = _resp(elapsed_ms=50.0, body="ok" * 200)
    medium = _resp(elapsed_ms=400.0, body="ok" * 200)
    slow = _resp(elapsed_ms=1200.0, body="ok" * 200)
    # The helper returns TIMING_FLAKY after the 3 baseline samples and
    # never consumes the control or probe slots. Provide more samples
    # just in case the helper reaches them.
    side_effects = [fast, medium, slow] + [_resp()] * 50
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    # The TIMING_FLAKY branch in discover() is skipped (no probe data),
    # so the candidates list should be empty.
    assert cands == []
    # But the verdict-to-outcome mapping for TIMING_FLAKY must still
    # resolve to INCONCLUSIVE. Build a synthetic candidate that carries
    # a TIMING_FLAKY result and validate it directly.
    fake_result = MagicMock()
    fake_result.verdict = "TIMING_FLAKY"
    fake_result.baseline_median_ms = 200.0
    fake_result.baseline_cv_pct = 85.0
    fake_result.probe_samples = []
    fake_result.probe_median_ms = 0.0
    fake_result.waf_detected = False
    fake_result.rate_limited = False
    fake_result.notes = "baseline CV 85% > 30% threshold"
    candidate = {
        "endpoint": "/",
        "parameter": "host",
        "method": "GET",
        "payload": "; sleep 3",
        "separator": ";",
        "baseline_ms": 200.0,
        "delay_ms": 0.0,
        "ratio": 0.0,
        "reproducibility": fake_result,
        "verdict": "TIMING_FLAKY",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome.value == "inconclusive"


@pytest.mark.asyncio
async def test_waf_interference_returns_inconclusive():
    """403 with a very different body shape → WAF_INTERFERENCE → INCONCLUSIVE."""
    check = CommandInjectionCheck()
    # Baseline: status 200, body length ~600 chars (200 * "ok").
    # Probe: status 403, body length ~9 chars (very different).
    fast = _resp(elapsed_ms=50.0, body="ok" * 200, status=200)
    # 403 with a 5x smaller body is detected as WAF (5x ratio threshold).
    waf_resp = _resp(elapsed_ms=80.0, body="blocked", status=403)
    # Sequence: 3 baseline + round 1 (1 control + 2 probe) → WAF detected
    # on the first probe and the helper short-circuits before round 2.
    side_effects = [
        fast, fast, fast,   # baseline × 3
        fast,               # control round 1
        waf_resp, waf_resp,  # probe × 2 (round 1) — WAF on the first
    ] + [_resp()] * 50
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    # The WAF_INTERFERENCE branch adds a candidate then early-breaks.
    assert len(cands) >= 1
    c = cands[0]
    assert c["verdict"] == "WAF_INTERFERENCE"
    # And validate() maps it to INCONCLUSIVE + medium.
    result = await check.validate(MagicMock(), c)
    assert result.outcome.value == "inconclusive"
    assert result.confidence == "medium"


@pytest.mark.asyncio
async def test_probe_not_reproducible_returns_anomaly():
    """First probe slow, second probe fast → TIMING_ANOMALY → INCONCLUSIVE.

    The helper detects TIMING_ANOMALY when at least one probe sample is
    > 2 s and another is < 500 ms in the same run.
    """
    check = CommandInjectionCheck()
    fast50 = _resp(elapsed_ms=50.0, body="ok" * 200)
    slow = _resp(elapsed_ms=3000.0, body="ok" * 200)
    # Sequence: 3 baseline + 1 control + 2 probe (slow then fast) +
    # 1 control + 2 probe (slow then fast). The first round already
    # produces has_slow AND has_fast, so TIMING_ANOMALY is emitted.
    side_effects = [
        fast50, fast50, fast50,   # baseline × 3
        fast50,                   # control round 1
        slow, fast50,             # probe × 2 (round 1) — slow + fast
        fast50,                   # control round 2
        slow, fast50,             # probe × 2 (round 2) — slow + fast
    ] + [_resp()] * 50
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    c = cands[0]
    assert c["verdict"] == "TIMING_ANOMALY"
    result = await check.validate(MagicMock(), c)
    assert result.outcome.value == "inconclusive"


@pytest.mark.asyncio
async def test_separator_extraction_still_works():
    """The pre-control/probe separator detection is preserved verbatim."""
    assert _detect_separator("; sleep 3") == ";"
    assert _detect_separator("| sleep 3") == "|"
    assert _detect_separator("& sleep 3") == "&"
    assert _detect_separator("&& sleep 3") == "&&"
    assert _detect_separator("|| sleep 3") == "||"
    assert _detect_separator("`sleep 3`") == "backtick"
    assert _detect_separator("$(sleep 3)") == "$()"
    # Unrecognised payload falls through to the catch-all.
    assert _detect_separator("nobinary at all") == "unknown"


@pytest.mark.asyncio
async def test_assess_produces_finding():
    check = CommandInjectionCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "host", "method": "GET",
        "payload": "; sleep 3", "separator": ";",
        "baseline_ms": 50.0, "delay_ms": 3000.0, "ratio": 60.0,
        "verdict": "TIMING_REPRODUCIBLE",
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.severity.value == "critical"
    assert "CWE-78" in f.cwe
    assert f.status.value == "confirmed"
    # CONFIRMED findings do not need a reason — the technical text
    # already covers the reproducible case.
    assert "Inconclusive reason:" not in f.technical_explanation


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verdict,expected_substring",
    [
        ("WAF_INTERFERENCE", "WAF or intermediary"),
        ("RATE_LIMITED", "rate-limited"),
        ("TIMING_FLAKY", "unstable"),
        ("TIMING_ANOMALY", "inconsistent"),
        ("INCONCLUSIVE", "did not produce a reproducible timing delta"),
    ],
)
async def test_assess_appends_verdict_reason_for_inconclusive(verdict, expected_substring):
    """Non-reproducible verdicts must produce INCONCLUSIVE findings
    with the specific verdict reason in technical_explanation."""
    from redveil.validation.control_probe import (
        ReproducibilityResult,
    )
    check = CommandInjectionCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "host", "method": "GET",
        "payload": "; sleep 3", "separator": ";",
        "baseline_ms": 50.0, "delay_ms": 0.0, "ratio": 0.0,
        "verdict": verdict,
        "reproducibility": ReproducibilityResult(verdict=verdict),
    }
    f = await check.assess(candidate)
    assert f is not None
    assert f.status.value == "inconclusive"
    assert "Inconclusive reason:" in f.technical_explanation
    assert expected_substring in f.technical_explanation


def test_safety_no_destructive_payloads():
    """Every payload must be a benign sleep-only command. No destructive commands."""
    for payload in _DELAY_PAYLOADS:
        for bad in _FORBIDDEN_SUBSTRINGS:
            assert bad not in payload, f"payload {payload!r} contains forbidden substring {bad!r}"
        # Cap sleep at 5 seconds
        import re
        for n in re.findall(r"sleep\s+(\d+)", payload):
            assert int(n) <= 5, f"sleep {n} exceeds cap"


def test_safety_only_sleep_command():
    """Every payload should ONLY contain 'sleep N' (no other commands)."""
    for payload in _DELAY_PAYLOADS:
        import re
        # Strip leading/trailing separators and whitespace
        stripped = re.sub(r"^[\s;|&`$()]+", "", payload)
        stripped = re.sub(r"[\s;|&`$()]+$", "", stripped)
        # Should be just "sleep N"
        assert re.match(r"^sleep\s+\d+$", stripped), f"non-sleep payload: {payload!r} (stripped: {stripped!r})"


def test_safety_no_file_references():
    """No payload should reference real files."""
    for payload in _DELAY_PAYLOADS:
        for bad in ["/etc/", "passwd", "shadow", "system32", "boot.ini"]:
            assert bad not in payload, f"payload {payload!r} references {bad!r}"


def test_safety_no_reverse_shell():
    """No reverse shell patterns."""
    for payload in _DELAY_PAYLOADS:
        for bad in ["/dev/tcp", "bash -i", "python -c", "perl -e", "ruby -e", "nc -e", "ncat -e"]:
            assert bad not in payload, f"payload {payload!r} has reverse shell: {bad!r}"


def test_safety_no_disk_wipe():
    """No disk-wiping or destructive write commands."""
    for payload in _DELAY_PAYLOADS:
        for bad in ["dd if=", "mkfs", "fdisk", "rm -rf", "> /dev/", "chmod 777", "chown"]:
            assert bad not in payload, f"payload {payload!r} has destructive: {bad!r}"
