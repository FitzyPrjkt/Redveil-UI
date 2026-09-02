"""Tests for Wave 14 path-traversal audit fixes.

Spec invariants covered here:

  - WAF / rate-limit status codes → INCONCLUSIVE (don't claim traversal
    from a contaminated probe).
  - 404 → 200 status transition → CONFIRMED (file appeared).
  - Canary reflected in response body → CONFIRMED (server returned the
    canary file content).
  - Length-only change with no canary reflection → LIKELY (could be
    CDN cache miss, error page substitution).
  - Status-only change (not 404→200) → INCONCLUSIVE (could be WAF).
  - No change → FALSE_POSITIVE.
  - ActionPlan max_requests reflects actual execution.
  - Evidence carries Wave 14 fields (oracle_signal, environment_uncertainty,
    waf_detected, rate_limited, test_mode, destructive).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.path_traversal import (
    PathTraversalCheck,
    _outcome_for_traversal,
)
from redveil.findings.finding import FindingStatus
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies, ValidationOutcome


def _resp(body: str = "", status: int = 200, headers: dict | None = None):
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {"content-type": "text/html"},
        body=body,
        elapsed_ms=10.0,
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
    decision.plan = MagicMock()
    decision.reason = "test-mock"
    decision.__bool__ = lambda self: True
    mock_gate.ask.return_value = decision
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=mock_gate,
    )
    check.bind(deps)
    return mock_http


# ---------------------------------------------------------------------------
# 1. Outcome matrix (parametrized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "behavior,status,baseline_status,expected",
    [
        # Canary reflected in body → CONFIRMED (server returned our file)
        ("canary_reflected", 200, 404, ValidationOutcome.CONFIRMED),
        # 404 → 200 transition → CONFIRMED (file appeared)
        ("status_transition_404_to_200", 200, 404, ValidationOutcome.CONFIRMED),
        # Status-only (not 404→200) → INCONCLUSIVE (could be WAF)
        ("different_status", 500, 200, ValidationOutcome.INCONCLUSIVE),
        ("different_status", 302, 200, ValidationOutcome.INCONCLUSIVE),
        # Length-only → LIKELY (CDN noise, error page)
        ("different_length", 200, 200, ValidationOutcome.LIKELY),
        # No change → FALSE_POSITIVE
        ("no_change", 200, 200, ValidationOutcome.FALSE_POSITIVE),
    ],
)
def test_outcome_matrix(behavior, status, baseline_status, expected):
    """Spec-mandated outcome per behavior + status code."""
    assert _outcome_for_traversal(behavior, status, baseline_status) == expected


@pytest.mark.parametrize("status_code", [403, 406, 419, 429, 501, 503])
def test_interference_status_forces_inconclusive(status_code):
    """WAF / rate-limit status → INCONCLUSIVE regardless of behavior."""
    # Even with canary_reflected behavior, if status is 429/403/etc.
    # we cannot conclude traversal from the response — the WAF or
    # rate-limiter may have rewritten the body.
    assert (
        _outcome_for_traversal(
            "canary_reflected", status_code, 404
        )
        == ValidationOutcome.INCONCLUSIVE
    )


# ---------------------------------------------------------------------------
# 2. validate() per-outcome
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_inconclusive_for_waf_status():
    check = PathTraversalCheck()
    candidate = {
        "parameter": "file",
        "behavior": "canary_reflected",
        "canary_status": 429,
        "baseline_status": 200,
        "baseline_length": 100,
        "canary_length": 50,
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome == ValidationOutcome.INCONCLUSIVE
    assert result.confidence == "low"


@pytest.mark.asyncio
async def test_validate_confirmed_for_404_to_200():
    check = PathTraversalCheck()
    candidate = {
        "parameter": "file",
        "behavior": "status_transition_404_to_200",
        "canary_status": 200,
        "baseline_status": 404,
        "baseline_length": 9,
        "canary_length": 100,
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.confidence == "high"


@pytest.mark.asyncio
async def test_validate_likely_for_length_only_change():
    """Spec rule 14: don't claim vuln from environmental noise.

    A length-only change could be a CDN cache miss or error-page
    substitution — downgraded to LIKELY not CONFIRMED.
    """
    check = PathTraversalCheck()
    candidate = {
        "parameter": "file",
        "behavior": "different_length",
        "canary_status": 200,
        "baseline_status": 200,
        "baseline_length": 100,
        "canary_length": 250,
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome == ValidationOutcome.LIKELY
    assert result.confidence == "medium"


# ---------------------------------------------------------------------------
# 3. assess() per-outcome
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_returns_none_for_false_positive():
    """Spec: no finding when behavior is 'no_change' (FALSE_POSITIVE)."""
    check = PathTraversalCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "file", "method": "GET",
        "payload": "../canary", "canary": "canary",
        "baseline_status": 404, "baseline_length": 9,
        "canary_status": 404, "canary_length": 9,
        "behavior": "no_change",
        "request": MagicMock(url="https://example.com/?file=../canary"),
    }
    assert await check.assess(candidate) is None


@pytest.mark.asyncio
async def test_assess_inconclusive_status_for_waf():
    """WAF status → INCONCLUSIVE finding with low severity + confidence."""
    check = PathTraversalCheck()
    _bind(check, [_resp(status=403)])
    candidate = {
        "endpoint": "/", "parameter": "file", "method": "GET",
        "payload": "../canary", "canary": "canary",
        "baseline_status": 200, "baseline_length": 100,
        "canary_status": 403, "canary_length": 9,
        "behavior": "canary_reflected",
        "request": MagicMock(url="https://example.com/?file=../canary"),
        "response": _resp(status=403, body="blocked"),
    }
    finding = await check.assess(candidate)
    assert finding is not None
    assert finding.status == FindingStatus.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 4. ActionPlan budget correctness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_actionplan_budget_reflects_actual_execution():
    """Spec: max_requests must equal actual worst-case execution.

    Per param × (baseline samples + traversal payloads). The check
    uses 2 baseline samples × 8 traversal sequences × N params. We
    just verify the budget is at least len(params) × (2 + 8).
    """
    check = PathTraversalCheck()
    captured = {}
    gate_mock = MagicMock()
    decision = MagicMock()
    decision.approved = True
    decision.__bool__ = lambda self: True
    gate_mock.ask = MagicMock(side_effect=lambda plan, allow_destructive=False: (
        captured.update({"plan": plan}) or decision
    ))
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = True
    cfg.authorization.acknowledged_safety_terms = True
    cfg.authorization.allow_destructive = False
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock(side_effect=Exception("network"))
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=gate_mock,
    )
    check.bind(deps)
    await check.discover(MagicMock())
    plan = captured["plan"]
    # Worst case: 22 params × (2 baseline + 8 traversal) = 220
    assert plan.max_requests == 22 * (2 + 8)
    # Plan should explicitly mention "2 baseline" + "8 traversal"
    assert "2 baseline" in plan.description
    assert "8 traversal" in plan.description


# ---------------------------------------------------------------------------
# 5. Evidence carries Wave 14 fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_carries_wave14_fields_for_waf_response():
    """WAF response → waf_detected=True, environment_uncertainty high."""
    check = PathTraversalCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "file", "method": "GET",
        "payload": "../canary", "canary": "canary",
        "baseline_status": 200, "baseline_length": 100,
        "canary_status": 403, "canary_length": 50,
        "behavior": "canary_reflected",
        "request": Request(method="GET", url="https://example.com/?file=../canary"),
        "response": _resp(status=403, body="blocked"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.waf_detected is True
    assert e.environment_uncertainty is not None
    assert e.environment_uncertainty >= 0.7
    assert e.oracle_signal == "file_existence"
    assert e.validation_outcome == "inconclusive"
    assert e.test_mode == "safe"
    assert e.destructive is False


@pytest.mark.asyncio
async def test_evidence_carries_wave14_fields_for_confirmed_traversal():
    """Confirmed 404→200 → waf_detected=False, low uncertainty."""
    check = PathTraversalCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "file", "method": "GET",
        "payload": "../canary", "canary": "canary",
        "baseline_status": 404, "baseline_length": 9,
        "canary_status": 200, "canary_length": 100,
        "behavior": "status_transition_404_to_200",
        "request": Request(method="GET", url="https://example.com/?file=../canary"),
        "response": _resp(status=200, body="canary content"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.waf_detected is False
    assert e.rate_limited is False
    assert e.environment_uncertainty is not None
    assert e.environment_uncertainty <= 0.2
    assert e.validation_outcome == "confirmed"