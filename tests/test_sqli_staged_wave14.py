"""Tests for Wave 14 SQLi + StagedValidator integration.

Spec deliverable: SQLi's discover() now runs a CHEAP timing probe
first, then escalates to the full control+probe+replay sequence
only for candidates with a meaningful timing anomaly. This matches
the spec's "Discovery → Cheap anomaly detection → Targeted
validation → Reproducibility check" pipeline.

These tests pin the staging behavior so regressions are caught.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.sqli import TimeBasedSQLiCheck
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies
from redveil.validation.staged import (
    AnomalyKind,
    AnomalySignal,
    StagedValidator,
    default_classify,
)


def _resp(body: str = "", status: int = 200, elapsed_ms: float = 50.0,
          headers: dict | None = None):
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {"content-type": "text/html"},
        body=body,
        elapsed_ms=elapsed_ms,
    )


def _bind(check, side_effects):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = True
    cfg.authorization.acknowledged_safety_terms = True
    cfg.authorization.allow_destructive = False
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock(side_effect=side_effects)
    mock_gate = MagicMock()
    decision = MagicMock()
    decision.approved = True
    decision.__bool__ = lambda self: True
    mock_gate.ask.return_value = decision
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=mock_gate,
    )
    check.bind(deps)
    return mock_http


# ---------------------------------------------------------------------------
# 1. SQLi's _cheap_timing_probe helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cheap_timing_probe_returns_drop_signal_when_fast():
    """Baseline 50ms + probe 50ms → delta 0 → DROP signal (negative score)."""
    check = TimeBasedSQLiCheck()
    _bind(check, [_resp(elapsed_ms=50.0), _resp(elapsed_ms=50.0)])
    signal = await check._cheap_timing_probe(
        baseline_url="https://example.com/?q=x",
        probe_url="https://example.com/?q=SLEEP",
        threshold_ms=800.0,
    )
    assert signal is not None
    assert signal.kind == AnomalyKind.TIMING_PROMISE
    assert signal.score < 0
    # The default classifier would DROP this signal.
    assert default_classify(signal).escalation.value == "drop"


@pytest.mark.asyncio
async def test_cheap_timing_probe_returns_escalate_signal_when_slow():
    """Baseline 50ms + probe 3000ms → delta 2950ms → ESCALATE signal."""
    check = TimeBasedSQLiCheck()
    _bind(check, [_resp(elapsed_ms=50.0), _resp(elapsed_ms=3000.0)])
    signal = await check._cheap_timing_probe(
        baseline_url="https://example.com/?q=x",
        probe_url="https://example.com/?q=SLEEP",
        threshold_ms=800.0,
    )
    assert signal is not None
    assert signal.score > 0
    assert default_classify(signal).escalation.value == "escalate"


@pytest.mark.asyncio
async def test_cheap_timing_probe_handles_request_failure():
    """Network error during cheap probe → returns None, no signal.
    The caller (discover) treats None as 'proceed to expensive
    sequence' (safe default) — but the next stage will fail too
    and skip the candidate, which is correct (no false negative)."""
    check = TimeBasedSQLiCheck()

    async def fail(*_):
        raise RuntimeError("network down")

    _bind(check, fail)
    signal = await check._cheap_timing_probe(
        baseline_url="https://example.com/?q=x",
        probe_url="https://example.com/?q=SLEEP",
        threshold_ms=800.0,
    )
    assert signal is None


# ---------------------------------------------------------------------------
# 2. Staged pipeline end-to-end: cheap probe drops noise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_staged_pipeline_drops_no_timing_anomaly_candidates():
    """All 50ms responses → cheap probe drops everything → 0 candidates.

    Spec: "Do not perform expensive validation against every
    parameter unless necessary." Without staging, the SQLi check
    would run 64 × 9 = 576 requests for nothing.
    """
    check = TimeBasedSQLiCheck()
    fast = _resp(elapsed_ms=50.0)
    # 8 params × 8 payloads = 64 (param, payload) pairs. Each needs
    # 1 cheap baseline + 1 cheap probe = 128 requests. But the
    # staged filter drops them all after the cheap probe, so no
    # full control+probe+replay runs. 200 responses is plenty.
    _bind(check, [fast] * 200)
    cands = await check.discover(MagicMock())
    assert cands == []
    # The mock's call_count should be small (one cheap baseline +
    # one cheap probe per (param, payload) pair), NOT 576.
    # Each pair consumes 2 responses; we cap at 128.
    # (Loose check: well below 576.)
    assert mock_http_call_count(check) < 200


def mock_http_call_count(check):
    """Helper: return how many HTTP calls the check made."""
    return check.deps.http.send.call_count


@pytest.mark.asyncio
async def test_staged_pipeline_escalates_real_anomalies():
    """First (param, payload) has a real timing anomaly → at least 1
    candidate emitted. Verifies the cheap probe → full sequence
    escalation works for true positives.
    """
    check = TimeBasedSQLiCheck()
    # URL side effect: baseline=50ms, probe=3000ms. Cheap probe
    # sees 2950ms delta > 800ms threshold → ESCALATE → full
    # control+probe+replay. Cheap probe consumes 2 responses;
    # main sequence consumes the next 9 (3 baseline + 2 control +
    # 4 probe). Total 11. The first match breaks the loop.
    async def side_effect(req):
        url = req.url
        if "SLEEP" in url.upper() or "PG_SLEEP" in url.upper() or "WAITFOR" in url.upper() or "RANDOMBLOB" in url.upper():
            return _resp(elapsed_ms=3000.0, body="ok")
        return _resp(elapsed_ms=50.0, body="ok")
    _bind(check, side_effect)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    # The first candidate's verdict should be reproducible timing
    # (cheap probe escalated, full sequence confirmed).
    from redveil.validation.control_probe import TIMING_REPRODUCIBLE
    assert cands[0]["verdict"] == TIMING_REPRODUCIBLE


# ---------------------------------------------------------------------------
# 3. StagedValidator integration
# ---------------------------------------------------------------------------


def test_sqli_check_has_staged_validator_attribute():
    """The check instantiates a StagedValidator in __init__."""
    check = TimeBasedSQLiCheck()
    assert hasattr(check, "_staged")
    assert isinstance(check._staged, StagedValidator)


def test_anomaly_signal_for_timing_promise_is_escalated_above_threshold():
    """The signal score (0.5) places TIMING_PROMISE above the
    default escalate threshold (0.5), so SQLi time signals
    correctly escalate."""
    s = AnomalySignal(
        candidate=object(),
        kind=AnomalyKind.TIMING_PROMISE,
        score=0.5,
    )
    d = default_classify(s)
    assert d.escalation.value in ("escalate", "defer")
    # 0.5 base + 0.5 score = 1.0 → escalate
    assert d.escalation.value == "escalate"