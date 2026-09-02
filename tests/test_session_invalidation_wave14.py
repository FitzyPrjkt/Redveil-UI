"""Tests for Wave 14 session_invalidation audit fixes.

Audit summary: the existing session_invalidation check is largely
spec-compliant (state-transition oracle: auth OK → logout → re-auth
should fail). Gaps addressed in this commit:

- WAF / rate-limit on the post-logout probe is flagged in evidence
  with high environment_uncertainty so the ConfidenceScorer can
  downgrade.
- Evidence carries Wave 14 fields (oracle_signal, validation_outcome,
  waf_detected, rate_limited, test_mode, destructive).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.session_invalidation import SessionInvalidationCheck
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


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
    decision.__bool__ = lambda self: True
    mock_gate.ask.return_value = decision
    deps = CheckDependencies(
        http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock(),
        gate=mock_gate,
    )
    check.bind(deps)
    return mock_http


@pytest.mark.asyncio
async def test_evidence_waf_status_when_post_logout_blocked():
    """WAF block on post-logout probe → waf_detected=True, high uncertainty."""
    check = SessionInvalidationCheck()
    _bind(check, [_resp(status=403)])
    candidate = {
        "principal": "alice",
        "logout_path": "/logout",
        "probe_path": "/api/profile/me",
        "status_after_logout": 403,
        "request": Request(method="GET", url="https://example.com/api/profile/me"),
        "response": _resp(status=403, body="blocked"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.waf_detected is True
    assert e.environment_uncertainty >= 0.5
    assert e.validation_outcome == "inconclusive"
    assert e.test_mode == "active"
    assert e.destructive is False


@pytest.mark.asyncio
async def test_evidence_clean_session_leak():
    """200 OK on post-logout probe → confirmed, low uncertainty."""
    check = SessionInvalidationCheck()
    _bind(check, [_resp()])
    candidate = {
        "principal": "alice",
        "logout_path": "/logout",
        "probe_path": "/api/profile/me",
        "status_after_logout": 200,
        "request": Request(method="GET", url="https://example.com/api/profile/me"),
        "response": _resp(status=200, body="user info"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.waf_detected is False
    assert e.rate_limited is False
    assert e.environment_uncertainty == 0.0
    assert e.validation_outcome == "confirmed"
    assert e.oracle_signal == "state_transition"


@pytest.mark.asyncio
async def test_evidence_rate_limit_status():
    """Rate-limit (429) on post-logout probe → rate_limited=True, high uncertainty."""
    check = SessionInvalidationCheck()
    _bind(check, [_resp(status=429)])
    candidate = {
        "principal": "bob",
        "logout_path": "/logout",
        "probe_path": "/api/profile/me",
        "status_after_logout": 429,
        "request": Request(method="GET", url="https://example.com/api/profile/me"),
        "response": _resp(status=429, body="rate limited"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.rate_limited is True
    assert e.environment_uncertainty >= 0.5
    assert e.validation_outcome == "inconclusive"