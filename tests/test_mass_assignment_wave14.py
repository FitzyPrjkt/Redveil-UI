"""Wave 14 mass_assignment audit — Phase 2 mutation test.

Spec asks for "controlled field mutation and state differential".
The existing check is purely passive (Phase 1: detect exposed
sensitive fields). This commit adds Phase 2: when active_testing is
enabled, send a POST with a unique canary value for the detected
sensitive field and check if the server accepts + reflects it.

Outcomes:

- 200/201 + canary reflected → CONFIRMED (writable, server echoed
  canary in response)
- 200/201 + canary not reflected → LIKELY (accepted, not echoed)
- 4xx → INCONCLUSIVE (server rejected — likely not writable)
- 401/403 → INCONCLUSIVE (auth required)
- 5xx → INCONCLUSIVE (server error)
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.mass_assignment import MassAssignmentCheck
from redveil.findings.finding import FindingStatus
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies, ValidationOutcome


def _resp(body: str = "", status: int = 200, headers: dict | None = None):
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {"content-type": "application/json"},
        body=body,
        elapsed_ms=10.0,
    )


async def _echo_canary_send(req, *, profile=None, mutation_status: int = 200, mutation_body_extra: str = ""):
    """Smart send: profile response for GET, echo canary back for POST mutation.

    Reads the request body, extracts the ``is_admin`` field (if any), and
    echoes it back in the response so the check sees its own canary
    reflected. Used for Phase 2 CONFIRMED tests.
    """
    if req.method == "GET":
        return _resp(
            body=profile or json.dumps({"is_admin": True, "username": "alice"}),
            status=200,
        )
    # POST: echo back the canary
    try:
        body_data = json.loads(req.body) if isinstance(req.body, str) else {}
    except Exception:
        body_data = {}
    echoed = dict(body_data)
    # Mutation response: include the canary back, plus any extra fields
    echo_body = json.dumps(echoed) + mutation_body_extra
    return _resp(body=echo_body, status=mutation_status)


def _bind(check, side_effects, *, active_testing: bool = False):
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = active_testing
    cfg.authorization.acknowledged_safety_terms = active_testing
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


def _profile_with_sensitive_field(field_name: str = "is_admin"):
    return _resp(
        body=json.dumps({field_name: True, "username": "alice"}),
        status=200,
    )


# ---------------------------------------------------------------------------
# 1. Phase 1 only when active_testing is disabled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_phase1_only_when_active_testing_disabled():
    """No active_testing → no Phase 2 mutation attempt."""
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field()
    _bind(check, [profile], active_testing=False)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    # All candidates are passive-only.
    assert all(not c.get("phase2_attempted") for c in cands)


# ---------------------------------------------------------------------------
# 2. Phase 2: canary reflected → CONFIRMED writable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase2_mutation_confirmed_when_canary_reflected():
    """200 + canary reflected in response body → CONFIRMED."""
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field("is_admin")
    # Mutation POST echoes the canary back so the check sees a
    # CONFIRMED writable field.
    async def send(req):
        return await _echo_canary_send(req, profile=profile.body)
    _bind(check, send, active_testing=True)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    c = next(c for c in cands if c["field"] == "is_admin")
    assert c.get("phase2_attempted") is True
    assert c.get("mutation_outcome") == ValidationOutcome.CONFIRMED
    assert c.get("canary_value", "").startswith("redveil_mass_assignment_canary_")

    # validate() → CONFIRMED
    result = await check.validate(MagicMock(), c)
    assert result.outcome == ValidationOutcome.CONFIRMED

    # assess() → CONFIRMED status
    finding = await check.assess(c)
    assert finding is not None
    assert finding.status == FindingStatus.CONFIRMED


# ---------------------------------------------------------------------------
# 3. Phase 2: 200 + canary NOT reflected → LIKELY (accepted but not echoed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase2_mutation_likely_when_200_without_canary_echo():
    """200 OK but server did not echo the canary → LIKELY (accepted)."""
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field("is_admin")
    # Mutation response: 200 but body does NOT contain the canary.
    mutation = _resp(body=json.dumps({"username": "alice"}), status=200)
    _bind(check, [profile, mutation], active_testing=True)
    cands = await check.discover(MagicMock())
    c = next(c for c in cands if c["field"] == "is_admin")
    assert c.get("phase2_attempted") is True
    assert c.get("mutation_outcome") == ValidationOutcome.LIKELY


# ---------------------------------------------------------------------------
# 4. Phase 2: 4xx → INCONCLUSIVE (server rejected)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase2_mutation_inconclusive_on_4xx():
    """4xx → server rejected the canary write → INCONCLUSIVE."""
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field("is_admin")
    async def send_422(req):
        return await _echo_canary_send(req, profile=profile.body, mutation_status=422)
    _bind(check, send_422, active_testing=True)
    cands = await check.discover(MagicMock())
    c = next(c for c in cands if c["field"] == "is_admin")
    assert c.get("phase2_attempted") is True
    assert c.get("mutation_outcome") == ValidationOutcome.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 5. Phase 2: 401/403 → INCONCLUSIVE (auth required)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase2_mutation_inconclusive_on_401():
    """401 → INCONCLUSIVE (auth required, can't determine writability)."""
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field("is_admin")
    async def send_401(req):
        return await _echo_canary_send(req, profile=profile.body, mutation_status=401)
    _bind(check, send_401, active_testing=True)
    cands = await check.discover(MagicMock())
    c = next(c for c in cands if c["field"] == "is_admin")
    assert c.get("mutation_outcome") == ValidationOutcome.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 6. Wave 14 evidence fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_carries_wave14_fields_for_phase2_confirmed():
    """Phase 2 CONFIRMED → oracle_signal='state_change', low uncertainty."""
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field("is_admin")
    async def send(req):
        return await _echo_canary_send(req, profile=profile.body)
    _bind(check, send, active_testing=True)
    cands = await check.discover(MagicMock())
    c = next(c for c in cands if c["field"] == "is_admin")
    evidence_list = await check.collect_evidence(c)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.oracle_signal == "state_change"
    assert e.validation_outcome == "confirmed"
    assert e.test_mode == "active"
    assert e.destructive is False
    assert e.environment_uncertainty <= 0.2


@pytest.mark.asyncio
async def test_evidence_carries_wave14_fields_for_phase1_only():
    """Phase 1 only → oracle_signal='reflection', medium uncertainty."""
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field("is_admin")
    _bind(check, [profile], active_testing=False)
    cands = await check.discover(MagicMock())
    c = next(c for c in cands if c["field"] == "is_admin")
    evidence_list = await check.collect_evidence(c)
    e = evidence_list[0]
    assert e.oracle_signal == "reflection"
    assert e.validation_outcome == "likely"
    assert e.test_mode == "passive"
    assert e.environment_uncertainty is not None
    assert e.environment_uncertainty >= 0.3


# ---------------------------------------------------------------------------
# 7. Canary is unique per request (no collision with real data)
# ---------------------------------------------------------------------------


def test_canary_value_format_is_unique():
    """The canary prefix is recognizable; the hex tail is random."""
    from redveil.checks.mass_assignment import _build_canary_value
    v1 = _build_canary_value()
    v2 = _build_canary_value()
    assert v1.startswith("redveil_mass_assignment_canary_")
    assert v2.startswith("redveil_mass_assignment_canary_")
    assert v1 != v2  # random tail differs


# ---------------------------------------------------------------------------
# 8. Assess returns INCONCLUSIVE finding when mutation inconclusive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_returns_inconclusive_finding_for_phase2_inconclusive():
    check = MassAssignmentCheck()
    profile = _profile_with_sensitive_field("is_admin")
    mutation = _resp(body="unauthorized", status=401)
    _bind(check, [profile, mutation], active_testing=True)
    cands = await check.discover(MagicMock())
    c = next(c for c in cands if c["field"] == "is_admin")
    finding = await check.assess(c)
    assert finding is not None
    assert finding.status == FindingStatus.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 9. Phase 2 mutation request body includes the original field values
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase2_mutation_preserves_original_fields():
    """The mutation POST includes the original GET response fields
    plus the canary value, so required fields stay populated."""
    from redveil.http.request import Request as Req

    check = MassAssignmentCheck()
    profile = _resp(
        body=json.dumps({"is_admin": True, "username": "alice", "email": "a@b"}),
        status=200,
    )
    # Capture the request sent for the mutation test.
    captured_requests = []

    async def capture_send(req):
        captured_requests.append(req)
        if req.method == "GET":
            return profile
        # POST: echo canary back so this looks CONFIRMED
        try:
            sent_data = json.loads(req.body) if isinstance(req.body, str) else {}
        except Exception:
            sent_data = {}
        return _resp(
            body=json.dumps(sent_data),
            status=200,
        )

    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = True
    cfg.authorization.acknowledged_safety_terms = True
    cfg.authorization.allow_destructive = False
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock(side_effect=capture_send)
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
    await check.discover(MagicMock())
    # Find the POST mutation request (sent after the GET that returned profile)
    mutations = [r for r in captured_requests if r.method == "POST"]
    assert len(mutations) >= 1
    body = json.loads(mutations[0].body)
    # Canary is_admin present
    assert "is_admin" in body
    assert body["is_admin"].startswith("redveil_mass_assignment_canary_")
    # Original fields preserved
    assert body["username"] == "alice"
    assert body["email"] == "a@b"