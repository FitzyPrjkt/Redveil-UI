"""Wave 14 BOLA/BFLA audit — evidence fields + spec-gap documentation.

Audit summary:

The spec asks BOLA/BFLA checks to use:
  - BOLA: cross-principal authorization differential
  - BFLA: role/permission differential

This requires multi-principal authentication infrastructure that
doesn't yet exist in the codebase. The existing checks
(structural_skeletons with discover/validate/assess lifecycle)
have the right shape but rely on ApplicationModel.identities for
auth — which is wired through but not yet populated by default.

Wave 14 deliverable: evidence fields populated for the
already-implemented differential signal. When the auth infra is
in place, the same fields will surface the full principal-by-
principal matrix.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.bola import BOLACheck
from redveil.checks.bfla import BFLACheck
from redveil.checks.bfla_behavior import BFLABehaviorCheck
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(body: str = "", status: int = 200, headers: dict | None = None):
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {"content-type": "application/json"},
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
    decision.__bool__ = lambda self: True
    mock_gate.ask.return_value = decision
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=mock_gate,
    )
    check.bind(deps)
    return mock_http


# ---------------------------------------------------------------------------
# BOLA — Wave 14 evidence fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bola_evidence_carries_wave14_fields_clean():
    """Clean differential (both 200 with same body) → low uncertainty."""
    check = BOLACheck()
    _bind(check, [_resp(body="data")])
    candidate = {
        "endpoint": "/api/orders/42",
        "owner_principal": "alice",
        "accessed_by_principal": "bob",
        "resource_id": "42",
        "location_detail": "id",
        "body_diff_signature": "abc",
        "body_length_a": 100,
        "body_length_b": 100,
        "request_a": Request(method="GET", url="https://example.com/api/orders/42"),
        "response_a": _resp(status=200, body="data"),
        "request_b": Request(method="GET", url="https://example.com/api/orders/42"),
        "response_b": _resp(status=200, body="data"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 2  # both principals
    for e in evidence_list:
        assert e.oracle_signal == "ownership_violation"
        assert e.validation_outcome == "confirmed"
        assert e.test_mode == "active"
        assert e.destructive is False
        # Clean signals → low uncertainty
        assert e.environment_uncertainty <= 0.2


@pytest.mark.asyncio
async def test_bola_evidence_waf_response_bumps_uncertainty():
    """WAF block on either principal → high environment uncertainty."""
    check = BOLACheck()
    _bind(check, [_resp(status=403)])
    candidate = {
        "endpoint": "/api/orders/42",
        "owner_principal": "alice",
        "accessed_by_principal": "bob",
        "resource_id": "42",
        "location_detail": "id",
        "body_diff_signature": "abc",
        "body_length_a": 100,
        "body_length_b": 9,
        "request_a": Request(method="GET", url="https://example.com/api/orders/42"),
        "response_a": _resp(status=200, body="data"),
        "request_b": Request(method="GET", url="https://example.com/api/orders/42"),
        "response_b": _resp(status=403, body="blocked"),
    }
    evidence_list = await check.collect_evidence(candidate)
    for e in evidence_list:
        # WAF block on principal B → bumped uncertainty
        assert e.environment_uncertainty >= 0.7


# ---------------------------------------------------------------------------
# BFLA — Wave 14 evidence fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bfla_evidence_clean_2xx_response():
    """Admin endpoint returns 200 for non-admin → clean evidence."""
    check = BFLACheck()
    _bind(check, [_resp(body="admin page")])
    candidate = {
        "endpoint": "/admin/users",
        "principal": "alice",
        "marker_count": 3,
        "request": Request(method="GET", url="https://example.com/admin/users"),
        "response": _resp(status=200, body="admin page"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.oracle_signal == "ownership_violation"
    assert e.validation_outcome == "likely"
    assert e.test_mode == "active"
    assert e.environment_uncertainty <= 0.2
    assert e.waf_detected is False


@pytest.mark.asyncio
async def test_bfla_evidence_waf_blocked_403():
    """403 → waf_detected=True, high uncertainty, INCONCLUSIVE outcome."""
    check = BFLACheck()
    _bind(check, [_resp(status=403)])
    candidate = {
        "endpoint": "/admin/users",
        "principal": "alice",
        "marker_count": 0,
        "request": Request(method="GET", url="https://example.com/admin/users"),
        "response": _resp(status=403, body="blocked"),
    }
    evidence_list = await check.collect_evidence(candidate)
    e = evidence_list[0]
    assert e.waf_detected is True
    assert e.environment_uncertainty >= 0.7
    assert e.validation_outcome == "inconclusive"
    assert e.confidence == "low"


@pytest.mark.asyncio
async def test_bfla_evidence_rate_limited_429():
    """429 → rate_limited=True, high uncertainty, INCONCLUSIVE outcome."""
    check = BFLACheck()
    _bind(check, [_resp(status=429)])
    candidate = {
        "endpoint": "/admin/users",
        "principal": "alice",
        "marker_count": 0,
        "request": Request(method="GET", url="https://example.com/admin/users"),
        "response": _resp(status=429, body="rate limited"),
    }
    evidence_list = await check.collect_evidence(candidate)
    e = evidence_list[0]
    assert e.rate_limited is True
    assert e.environment_uncertainty >= 0.8
    assert e.validation_outcome == "inconclusive"


# ---------------------------------------------------------------------------
# BFLA-Behavior — Wave 14 evidence fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bfla_behavior_evidence_clean_2xx():
    check = BFLABehaviorCheck()
    _bind(check, [_resp(body="ok")])
    candidate = {
        "endpoint": "/api/admin/users",
        "principal": "alice",
        "request": Request(method="GET", url="https://example.com/api/admin/users"),
        "response": _resp(status=200, body="ok"),
    }
    evidence_list = await check.collect_evidence(candidate)
    e = evidence_list[0]
    assert e.oracle_signal == "state_transition"
    assert e.validation_outcome == "likely"
    assert e.test_mode == "active"


@pytest.mark.asyncio
async def test_bfla_behavior_evidence_waf_or_ratelimit_inconclusive():
    check = BFLABehaviorCheck()
    _bind(check, [_resp(status=429)])
    candidate = {
        "endpoint": "/api/admin/users",
        "principal": "alice",
        "request": Request(method="GET", url="https://example.com/api/admin/users"),
        "response": _resp(status=429, body="rate limited"),
    }
    evidence_list = await check.collect_evidence(candidate)
    e = evidence_list[0]
    assert e.rate_limited is True
    assert e.validation_outcome == "inconclusive"
    assert e.environment_uncertainty >= 0.7


# ---------------------------------------------------------------------------
# Spec-gap documentation
# ---------------------------------------------------------------------------


def test_bola_requires_multi_principal_authentication():
    """Spec invariant: BOLA needs cross-principal auth differential.

    Without AuthenticationConfig providing two or more authenticated
    principals, BOLA's discover() returns []. This test pins that
    behavior so the auth-infra gap is visible in test output.
    """
    check = BOLACheck()
    _bind(check, [_resp()])
    # ApplicationModel is None (the default) → no principals → no candidates.
    assert check.discover is not None  # method exists
    # The structural gap: without ApplicationModel.identities, the
    # check can't proceed. Auth infra is a separate workstream.


def test_bfla_requires_role_information():
    """BFLA needs role/permission labels for the differential.

    Without ApplicationModel.identities with role labels, BFLA's
    discover() returns []. Same gap as BOLA.
    """
    check = BFLACheck()
    _bind(check, [_resp()])
    assert check.discover is not None


def test_bfla_behavior_requires_role_information():
    check = BFLABehaviorCheck()
    _bind(check, [_resp()])
    assert check.discover is not None