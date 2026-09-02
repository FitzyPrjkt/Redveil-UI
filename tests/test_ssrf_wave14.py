"""Wave 14 SSRF audit — OOB callback oracle + evidence fields.

Audit summary: the SSRF check already follows spec's OOB evidence
requirement (callback to operator-controlled domain, no internal IP
targets, manual OOB log review required). Gaps addressed here:

- Evidence carries Wave 14 fields (oracle_signal, validation_outcome,
  environment_uncertainty, waf_detected, rate_limited, test_mode,
  destructive).
- environment_uncertainty is per-indicator: "successful_fetch" is
  the strongest (low uncertainty), "redirect" moderate, "body_reference"
  weakest (could just be input reflection).
- WAF / rate-limit status codes bump the uncertainty further so the
  ConfidenceScorer downgrades accordingly.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.ssrf import SSRFCheck
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies


def _resp(
    body: str = "",
    status: int = 200,
    headers: dict | None = None,
):
    return Response(
        request_id="r1",
        status_code=status,
        headers=headers or {"content-type": "text/json"},
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
    cfg.authorization.out_of_band_callback_domain = "oob.example"
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


def _candidate(indicator: str, status: int = 200, body: str = "") -> dict:
    return {
        "endpoint": "/api/proxy",
        "method": "GET",
        "parameter": "url",
        "canary": "abc123def",
        "oob_url": "https://abc123def.oob.example/",
        "oob_domain": "oob.example",
        "indicator": indicator,
        "request": Request(method="GET", url="https://example.com/api/proxy?url=x"),
        "response": _resp(status=status, body=body),
    }


# ---------------------------------------------------------------------------
# 1. Indicator strength drives uncertainty
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "indicator,expected_uncertainty",
    [
        ("successful_fetch", 0.2),  # strongest signal
        ("redirect", 0.4),           # moderate
        ("body_reference", 0.6),    # weakest (could be reflection)
    ],
)
async def test_environment_uncertainty_per_indicator(indicator, expected_uncertainty):
    check = SSRFCheck()
    _bind(check, [_resp()])
    evidence_list = await check.collect_evidence(_candidate(indicator))
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.environment_uncertainty is not None
    assert abs(e.environment_uncertainty - expected_uncertainty) < 0.01


# ---------------------------------------------------------------------------
# 2. WAF / rate-limit detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 406, 419, 429, 501, 503])
async def test_waf_or_rate_limit_status_bumps_uncertainty(status):
    check = SSRFCheck()
    _bind(check, [_resp(status=status)])
    evidence_list = await check.collect_evidence(_candidate("redirect", status=status))
    e = evidence_list[0]
    waf_or_rl = status in (403, 406, 419, 501, 429, 503)
    assert waf_or_rl is True
    assert e.waf_detected or e.rate_limited
    assert e.environment_uncertainty >= 0.7


@pytest.mark.asyncio
async def test_clean_status_no_waf_or_rate_limit():
    check = SSRFCheck()
    _bind(check, [_resp()])
    evidence_list = await check.collect_evidence(_candidate("successful_fetch"))
    e = evidence_list[0]
    assert e.waf_detected is False
    assert e.rate_limited is False
    assert e.environment_uncertainty < 0.3  # strongest indicator, low uncertainty


# ---------------------------------------------------------------------------
# 3. Wave 14 fields always populated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_carries_wave14_fields():
    """All Wave 14 fields populated for SSRF evidence."""
    check = SSRFCheck()
    _bind(check, [_resp()])
    evidence_list = await check.collect_evidence(_candidate("body_reference"))
    assert len(evidence_list) == 1
    e = evidence_list[0]
    # oracle_signal = oob_callback (SSRF uses OOB oracle per spec)
    assert e.oracle_signal == "oob_callback"
    # validation_outcome: SSRF always LIKELY because OOB log
    # confirmation is required (spec: "We do NOT verify that the OOB
    # service received the callback")
    assert e.validation_outcome == "likely"
    assert e.test_mode == "active"
    assert e.destructive is False
    assert e.destructive_level is None


# ---------------------------------------------------------------------------
# 4. Assess still returns a finding for any non-None indicator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_returns_finding_with_status_likely():
    """Spec invariant: SSRF findings are LIKELY (manual OOB confirmation
    required). assess() must still produce a finding."""
    check = SSRFCheck()
    _bind(check, [_resp()])
    candidate = _candidate("redirect")
    finding = await check.assess(candidate)
    assert finding is not None
    from redveil.findings.finding import FindingStatus
    assert finding.status == FindingStatus.LIKELY
    assert "CWE-918" in finding.cwe


@pytest.mark.asyncio
async def test_assess_returns_finding_for_body_reference():
    check = SSRFCheck()
    _bind(check, [_resp()])
    candidate = _candidate("body_reference")
    finding = await check.assess(candidate)
    assert finding is not None


@pytest.mark.asyncio
async def test_assess_returns_finding_for_successful_fetch():
    check = SSRFCheck()
    _bind(check, [_resp()])
    candidate = _candidate("successful_fetch")
    finding = await check.assess(candidate)
    assert finding is not None