"""Tests for the control+probe+replay validation pattern.

The :func:`run_control_probe_sequence` helper wraps a single timing
measurement with three reproducibility guards: baseline stability,
control sanity, and probe replay across two rounds.

These tests verify each verdict path:

* TIMING_REPRODUCIBLE  — probe reliably slower than baseline
* TIMING_FLAKY         — baseline variance too high
* TIMING_ANOMALY       — probe samples are inconsistent (mix of slow + fast)
* WAF_INTERFERENCE     — probe returns a 403/406/419/501 or body-shape change
* RATE_LIMITED         — probe returns 429/503
* INCONCLUSIVE         — no probe samples, or probe not slow enough

The pattern runs ``BASELINE x N -> CONTROL -> PROBE x N -> CONTROL -> PROBE x N``,
so every test queues enough baseline + (2 * (1 + N)) control/probe responses.
"""
from __future__ import annotations

import pytest

from redveil.http.response import Response
from redveil.validation.control_probe import (
    INCONCLUSIVE,
    RATE_LIMITED,
    ReproducibilityResult,
    TIMING_ANOMALY,
    TIMING_FLAKY,
    TIMING_REPRODUCIBLE,
    WAF_INTERFERENCE,
    run_control_probe_sequence,
)
from redveil.validation.oracle import SignalKind


def _resp(
    status: int = 200,
    body: str = "ok",
    elapsed: float = 10.0,
    headers: dict[str, str] | None = None,
) -> Response:
    """Build a Response with predictable defaults."""
    return Response(
        request_id="r",
        status_code=status,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed,
    )


def _make_request_fn(responses_by_url: dict[str, list[Response]]):
    """Return an async callable that returns the next queued Response per URL.

    Each list is consumed FIFO; once exhausted, the last element is returned
    on subsequent calls (simulates "stable" behaviour).
    """
    cursors = {url: 0 for url in responses_by_url}

    async def _fn(url: str) -> Response:
        queue = responses_by_url[url]
        idx = cursors[url]
        cursors[url] = idx + 1
        if idx >= len(queue):
            return queue[-1]
        return queue[idx]

    return _fn


def _baseline_responses(elapsed: float, n: int = 3, body: str = "ok") -> list[Response]:
    return [_resp(status=200, body=body, elapsed=elapsed) for _ in range(n)]


# ---------------------------------------------------------------------------
# 1. Reproducible probe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reproducible_probe_gives_reproducible_verdict():
    """Stable baseline + slow probe + slow probe replay → TIMING_REPRODUCIBLE.

    Sequence: BASELINE×3 → CONTROL → PROBE×2 → CONTROL → PROBE×2 (n_probe=2).
    All probe samples are ~3000ms; all baseline samples are ~50ms. The
    probe median easily clears both thresholds.
    """
    fn = _make_request_fn({
        "https://x/baseline": _baseline_responses(50.0),
        "https://x/control": [
            # 2 controls (one before each probe round)
            _resp(status=200, body="ok", elapsed=55.0),
            _resp(status=200, body="ok", elapsed=55.0),
        ],
        "https://x/probe": [
            # 4 probes (n_probe=2 × 2 rounds)
            _resp(status=200, body="ok", elapsed=3050.0),
            _resp(status=200, body="ok", elapsed=3100.0),
            _resp(status=200, body="ok", elapsed=3050.0),
            _resp(status=200, body="ok", elapsed=3100.0),
        ],
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
        delay_threshold_ms=2000.0,
        ratio_threshold=3.0,
    )
    assert result.verdict == TIMING_REPRODUCIBLE
    assert result.baseline_median_ms == pytest.approx(50.0, abs=1.0)
    assert len(result.probe_samples) >= 2
    assert all(p >= 3000.0 for p in result.probe_samples)
    assert result.waf_detected is False
    assert result.rate_limited is False
    assert "baseline=" in result.notes
    assert "ratio=" in result.notes


# ---------------------------------------------------------------------------
# 2. Unstable baseline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unstable_baseline_gives_timing_flaky():
    """Baseline CV > 30% → TIMING_FLAKY.

    50ms, 200ms, 80ms has a high CV and short-circuits the sequence
    before any probe is run.
    """
    fn = _make_request_fn({
        "https://x/baseline": [
            _resp(status=200, body="ok", elapsed=50.0),
            _resp(status=200, body="ok", elapsed=200.0),
            _resp(status=200, body="ok", elapsed=80.0),
        ],
        "https://x/control": [_resp()],  # not consumed
        "https://x/probe": [_resp()],     # not consumed
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
    )
    assert result.verdict == TIMING_FLAKY
    assert result.baseline_cv_pct > 30.0
    assert "CV" in result.notes
    # Probe samples should be empty (sequence short-circuited)
    assert result.probe_samples == []


# ---------------------------------------------------------------------------
# 3. Timing anomaly (mix of slow + fast probes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_anomaly_no_repro_gives_timing_anomaly():
    """Probe samples mix slow (>2s) and fast (<500ms) → TIMING_ANOMALY.

    The hardcoded heuristic: ``has_slow and has_fast`` in probe_samples.
    """
    fn = _make_request_fn({
        "https://x/baseline": _baseline_responses(50.0),
        "https://x/control": [
            _resp(status=200, body="ok", elapsed=55.0),
            _resp(status=200, body="ok", elapsed=55.0),
        ],
        "https://x/probe": [
            # Round 1: one slow, one fast
            _resp(status=200, body="ok", elapsed=3050.0),
            _resp(status=200, body="ok", elapsed=60.0),
            # Round 2: one slow, one fast
            _resp(status=200, body="ok", elapsed=3050.0),
            _resp(status=200, body="ok", elapsed=60.0),
        ],
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
    )
    assert result.verdict == TIMING_ANOMALY
    assert "inconsistent" in result.notes or "range=" in result.notes
    # Probe_min/max should be populated
    assert result.probe_min_ms <= 500.0
    assert result.probe_max_ms >= 2000.0


# ---------------------------------------------------------------------------
# 4. WAF interference (status in {403,406,419,501})
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_waf_interference_detected_on_403_with_shape_change():
    """Probe returns 403 → WAF_INTERFERENCE (short-circuits second round)."""
    fn = _make_request_fn({
        "https://x/baseline": _baseline_responses(50.0, body="a" * 100),
        "https://x/control": [
            _resp(status=200, body="a" * 100, elapsed=55.0),
            _resp(status=200, body="a" * 100, elapsed=55.0),
        ],
        "https://x/probe": [
            # First probe is a 403 — WAF detected, early exit
            _resp(status=403, body="<html>blocked</html>", elapsed=80.0),
            # Subsequent probes are not consumed (early exit after round 1)
        ],
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
    )
    assert result.verdict == WAF_INTERFERENCE
    assert result.waf_detected is True
    assert "WAF" in result.notes


@pytest.mark.asyncio
async def test_waf_signal_kind_is_in_oracle_catalog():
    """The WAF signal kinds live in the shared oracle catalog, not a parallel enum."""
    assert SignalKind.WAF_CHALLENGE_PAGE == "waf_challenge_page"
    assert SignalKind.WAF_BLOCK_INDICATOR == "waf_block_indicator"
    assert SignalKind.RATE_LIMIT_HIT == "rate_limit_hit"
    # And they all have a dimension tag
    assert SignalKind.DIMENSION[SignalKind.WAF_CHALLENGE_PAGE] == "response"
    assert SignalKind.DIMENSION[SignalKind.WAF_BLOCK_INDICATOR] == "response"
    assert SignalKind.DIMENSION[SignalKind.RATE_LIMIT_HIT] == "response"


@pytest.mark.asyncio
async def test_waf_detected_on_body_length_change():
    """Body length change >5x or <1/5 is also WAF."""
    fn = _make_request_fn({
        "https://x/baseline": _baseline_responses(50.0, body="a" * 100),
        "https://x/control": [
            _resp(status=200, body="a" * 100, elapsed=55.0),
            _resp(status=200, body="a" * 100, elapsed=55.0),
        ],
        "https://x/probe": [
            # Same status 200 but body is now 6x larger → WAF rewrote response
            _resp(status=200, body="a" * 600, elapsed=3050.0),
            _resp(status=200, body="a" * 600, elapsed=3050.0),
        ],
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
    )
    assert result.verdict == WAF_INTERFERENCE


# ---------------------------------------------------------------------------
# 5. Rate limit (429 or 503)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limit_detected_on_429():
    """Probe returns 429 → RATE_LIMITED (short-circuits second round)."""
    fn = _make_request_fn({
        "https://x/baseline": _baseline_responses(50.0),
        "https://x/control": [
            _resp(status=200, body="ok", elapsed=55.0),
            _resp(status=200, body="ok", elapsed=55.0),
        ],
        "https://x/probe": [
            # 429 → rate-limited, early exit
            _resp(status=429, body="rate limited", elapsed=80.0,
                  headers={"Retry-After": "30"}),
        ],
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
    )
    assert result.verdict == RATE_LIMITED
    assert result.rate_limited is True
    assert "429" in result.notes


@pytest.mark.asyncio
async def test_rate_limit_detected_on_503():
    """503 is also treated as rate-limit by this helper."""
    fn = _make_request_fn({
        "https://x/baseline": _baseline_responses(50.0),
        "https://x/control": [
            _resp(status=200, body="ok", elapsed=55.0),
            _resp(status=200, body="ok", elapsed=55.0),
        ],
        "https://x/probe": [
            _resp(status=503, body="unavailable", elapsed=80.0),
        ],
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
    )
    assert result.verdict == RATE_LIMITED
    assert result.rate_limited is True


# ---------------------------------------------------------------------------
# 6. Network error → INCONCLUSIVE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_error_returns_inconclusive():
    """All baseline requests fail → INCONCLUSIVE."""
    async def _raising_fn(url: str) -> Response:
        raise ConnectionError("target down")

    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=_raising_fn,
    )
    assert result.verdict == INCONCLUSIVE
    assert "failed" in result.notes.lower()


# ---------------------------------------------------------------------------
# 7. Probe not slow enough → INCONCLUSIVE
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_not_slower_than_threshold_is_inconclusive():
    """Stable baseline + fast probe → INCONCLUSIVE (no timing signal)."""
    fn = _make_request_fn({
        "https://x/baseline": _baseline_responses(50.0),
        "https://x/control": [
            _resp(status=200, body="ok", elapsed=55.0),
            _resp(status=200, body="ok", elapsed=55.0),
        ],
        "https://x/probe": [
            # All probes are slow but < 3x baseline median (50*3=150ms)
            _resp(status=200, body="ok", elapsed=120.0),
            _resp(status=200, body="ok", elapsed=130.0),
            _resp(status=200, body="ok", elapsed=120.0),
            _resp(status=200, body="ok", elapsed=130.0),
        ],
    })
    result = await run_control_probe_sequence(
        baseline_url="https://x/baseline",
        probe_url="https://x/probe",
        control_url="https://x/control",
        request_fn=fn,
        n_baseline=3,
        n_probe=2,
        delay_threshold_ms=2000.0,
        ratio_threshold=3.0,
    )
    # Probe didn't clear either threshold → INCONCLUSIVE
    assert result.verdict == INCONCLUSIVE
    assert "not reproducible" in result.notes


# ---------------------------------------------------------------------------
# API smoke tests
# ---------------------------------------------------------------------------


def test_dataclass_is_importable_and_has_expected_fields():
    """ReproducibilityResult exposes the documented fields."""
    r = ReproducibilityResult(verdict=INCONCLUSIVE)
    assert r.verdict == INCONCLUSIVE
    assert r.baseline_samples == []
    assert r.probe_samples == []
    assert r.waf_detected is False
    assert r.rate_limited is False


def test_verdict_string_constants():
    """Each verdict is a stable string for comparison without imports."""
    assert TIMING_REPRODUCIBLE == "TIMING_REPRODUCIBLE"
    assert TIMING_FLAKY == "TIMING_FLAKY"
    assert TIMING_ANOMALY == "TIMING_ANOMALY"
    assert WAF_INTERFERENCE == "WAF_INTERFERENCE"
    assert RATE_LIMITED == "RATE_LIMITED"
    assert INCONCLUSIVE == "INCONCLUSIVE"