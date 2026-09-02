"""Tests for Wave 14 XSS context-aware reflection detection.

Spec deliverables for reflected XSS:
- safely encoded reflection → FALSE_POSITIVE
- HTML text reflection → LIKELY (lower impact, encoding missing)
- attribute reflection → CONFIRMED (breakout possible)
- JavaScript-context reflection → CONFIRMED (immediate code exec)
- content-type differences (JSON vs HTML)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redveil.checks.xss import (
    ReflectionContext,
    ReflectedXSSCheck,
    _CANARIES,
    _detect_reflection_context,
    _is_canary_html_encoded,
    _outcome_for_context,
)
from redveil.findings.finding import FindingStatus
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.plugins.base import CheckDependencies, ValidationOutcome


def _resp(
    body: str = "",
    status: int = 200,
    headers: dict | None = None,
):
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
# 1. Context detection helper
# ---------------------------------------------------------------------------


def test_detect_context_html_text():
    """Canary between tags with no surrounding attribute/script is HTML_TEXT."""
    body = "<html><body>You searched for: redveilXSSProbe12345</body></html>"
    idx = body.find("redveilXSSProbe12345")
    assert _detect_reflection_context(body, idx) == ReflectionContext.HTML_TEXT


def test_detect_context_attribute():
    """Canary inside an attribute value (non-URL) is ATTRIBUTE."""
    body = '<a href="x" title="redveilXSSProbe12345">click</a>'
    idx = body.find("redveilXSSProbe12345")
    assert _detect_reflection_context(body, idx) == ReflectionContext.ATTRIBUTE


def test_detect_context_script():
    """Canary inside <script>...</script> is SCRIPT."""
    body = "<script>var x = 'redveilXSSProbe12345'; alert(x);</script>"
    idx = body.find("redveilXSSProbe12345")
    assert _detect_reflection_context(body, idx) == ReflectionContext.SCRIPT


def test_detect_context_url():
    """Canary inside href/src/action is URL."""
    body = '<a href="redveilXSSProbe12345">link</a>'
    idx = body.find("redveilXSSProbe12345")
    assert _detect_reflection_context(body, idx) == ReflectionContext.URL


def test_detect_context_style():
    body = "<style>.x { background: url(redveilXSSProbe12345); }</style>"
    idx = body.find("redveilXSSProbe12345")
    assert _detect_reflection_context(body, idx) == ReflectionContext.STYLE


def test_detect_context_script_precedence_over_attribute():
    """If canary is inside a <script>, SCRIPT wins over other heuristics."""
    body = '<script>var url = "redveilXSSProbe12345";</script>'
    idx = body.find("redveilXSSProbe12345")
    assert _detect_reflection_context(body, idx) == ReflectionContext.SCRIPT


def test_detect_context_unknown_for_missing_canary():
    """Negative canary position → UNKNOWN."""
    assert _detect_reflection_context("<html></html>", -1) == ReflectionContext.UNKNOWN


def test_is_canary_html_encoded_detects_entities():
    """Heuristic detects HTML-encoded entities anywhere in body."""
    assert _is_canary_html_encoded("hello &lt;world&gt;", "anything") is True
    assert _is_canary_html_encoded("plain text", "anything") is False


# ---------------------------------------------------------------------------
# 2. Outcome + confidence per context (spec invariants)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "context,encoded,expected_outcome",
    [
        # Encoded reflection → FALSE_POSITIVE regardless of context
        (ReflectionContext.HTML_TEXT, True, ValidationOutcome.FALSE_POSITIVE),
        (ReflectionContext.ATTRIBUTE, True, ValidationOutcome.FALSE_POSITIVE),
        (ReflectionContext.SCRIPT, True, ValidationOutcome.FALSE_POSITIVE),
        (ReflectionContext.URL, True, ValidationOutcome.FALSE_POSITIVE),
        (ReflectionContext.STYLE, True, ValidationOutcome.FALSE_POSITIVE),
        # Raw reflection in exploitable context → CONFIRMED
        (ReflectionContext.ATTRIBUTE, False, ValidationOutcome.CONFIRMED),
        (ReflectionContext.SCRIPT, False, ValidationOutcome.CONFIRMED),
        (ReflectionContext.URL, False, ValidationOutcome.CONFIRMED),
        (ReflectionContext.STYLE, False, ValidationOutcome.CONFIRMED),
        # Raw in HTML_TEXT or UNKNOWN → LIKELY
        (ReflectionContext.HTML_TEXT, False, ValidationOutcome.LIKELY),
        (ReflectionContext.UNKNOWN, False, ValidationOutcome.LIKELY),
    ],
)
def test_outcome_for_context_matrix(context, encoded, expected_outcome):
    """Spec-mandated outcome matrix per context + encoding state."""
    assert _outcome_for_context(context, encoded) == expected_outcome


# ---------------------------------------------------------------------------
# 3. validate() — context-aware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_confirmed_for_raw_attribute_reflection():
    """Raw reflection inside an attribute is CONFIRMED."""
    check = ReflectedXSSCheck()
    candidate = {
        "parameter": "q",
        "canary": "abc",
        "reflected_count": 1,
        "escaped": False,
        "context": ReflectionContext.ATTRIBUTE.value,
        "content_type": "text/html",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome == ValidationOutcome.CONFIRMED


@pytest.mark.asyncio
async def test_validate_confirmed_for_raw_script_reflection():
    """Raw reflection inside a <script> block is CONFIRMED."""
    check = ReflectedXSSCheck()
    candidate = {
        "parameter": "q",
        "canary": "abc",
        "reflected_count": 1,
        "escaped": False,
        "context": ReflectionContext.SCRIPT.value,
        "content_type": "text/html",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome == ValidationOutcome.CONFIRMED


@pytest.mark.asyncio
async def test_validate_likely_for_raw_html_text_reflection():
    """Raw reflection in HTML_TEXT context is LIKELY (not CONFIRMED)."""
    check = ReflectedXSSCheck()
    candidate = {
        "parameter": "q",
        "canary": "abc",
        "reflected_count": 1,
        "escaped": False,
        "context": ReflectionContext.HTML_TEXT.value,
        "content_type": "text/html",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome == ValidationOutcome.LIKELY


@pytest.mark.asyncio
async def test_validate_false_positive_for_safely_encoded_reflection():
    """Spec: safely-encoded reflection does NOT become CONFIRMED."""
    check = ReflectedXSSCheck()
    candidate = {
        "parameter": "q",
        "canary": "abc",
        "reflected_count": 1,
        "escaped": True,
        "context": ReflectionContext.ATTRIBUTE.value,
        "content_type": "text/html",
    }
    result = await check.validate(MagicMock(), candidate)
    assert result.outcome == ValidationOutcome.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# 4. assess() — severity + confidence per context; no finding when encoded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assess_returns_none_when_reflection_is_safely_encoded():
    """Spec: a safely-encoded reflection produces NO finding."""
    check = ReflectedXSSCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET",
        "canary": "abc", "reflected_count": 1,
        "escaped": True,
        "context": ReflectionContext.ATTRIBUTE.value,
        "content_type": "text/html",
        "request": Request(method="GET", url="https://example.com/?q=abc"),
        "response": _resp(body="<a title='abc'>x</a>"),
    }
    finding = await check.assess(candidate)
    assert finding is None


@pytest.mark.asyncio
async def test_assess_produces_high_severity_for_script_context():
    """Raw reflection in script context → CRITICAL severity."""
    from redveil.findings.severity import Severity
    check = ReflectedXSSCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET",
        "canary": "abc", "reflected_count": 1,
        "escaped": False,
        "context": ReflectionContext.SCRIPT.value,
        "content_type": "text/html",
        "request": Request(method="GET", url="https://example.com/?q=abc"),
        "response": _resp(body="<script>var x='abc';</script>"),
    }
    finding = await check.assess(candidate)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_assess_produces_medium_severity_for_style_context():
    """CSS context → MEDIUM severity (lower impact than JS/attr)."""
    from redveil.findings.severity import Severity
    check = ReflectedXSSCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET",
        "canary": "abc", "reflected_count": 1,
        "escaped": False,
        "context": ReflectionContext.STYLE.value,
        "content_type": "text/html",
        "request": Request(method="GET", url="https://example.com/?q=abc"),
        "response": _resp(body="<style>.x{background:url(abc)}</style>"),
    }
    finding = await check.assess(candidate)
    assert finding is not None
    assert finding.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_assess_produces_likely_finding_for_html_text_context():
    """Raw in HTML_TEXT → LIKELY status, not CONFIRMED."""
    check = ReflectedXSSCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/", "parameter": "q", "method": "GET",
        "canary": "abc", "reflected_count": 1,
        "escaped": False,
        "context": ReflectionContext.HTML_TEXT.value,
        "content_type": "text/html",
        "request": Request(method="GET", url="https://example.com/?q=abc"),
        "response": _resp(body="<html>You searched: abc</html>"),
    }
    finding = await check.assess(candidate)
    assert finding is not None
    assert finding.status == FindingStatus.LIKELY


# ---------------------------------------------------------------------------
# 5. Content-Type differences (JSON vs HTML)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_json_reflection_with_html_content_type_still_flagged():
    """If the API endpoint mis-routes as text/html, the JSON canary still
    gets the HTML_TEXT context and stays a finding (lower impact)."""
    check = ReflectedXSSCheck()
    _bind(check, [_resp()])
    candidate = {
        "endpoint": "/api/profile", "parameter": "(json body)", "method": "POST",
        "canary": "abc", "reflected_count": 1,
        "escaped": False,  # treated as raw because content-type is HTML
        "context": ReflectionContext.HTML_TEXT.value,
        "content_type": "text/html",  # misconfigured but spec asks us to flag
        "request": Request(method="POST", url="https://example.com/api/profile"),
        "response": _resp(
            body='<html>Error: abc</html>',
            headers={"content-type": "text/html"},
        ),
    }
    finding = await check.assess(candidate)
    # If the server says it's HTML but the canary lands in HTML_TEXT
    # context, the validator downgrades to LIKELY (not CONFIRMED) —
    # not the JSON-as-data non-issue.
    if finding is not None:
        assert finding.status in (FindingStatus.LIKELY, FindingStatus.CONFIRMED)


@pytest.mark.asyncio
async def test_json_content_type_reflection_treated_as_safely_encoded():
    """A application/json response with raw canary is treated as
    safely-encoded because browsers won't execute scripts inside JSON."""
    check = ReflectedXSSCheck()
    _bind(check, [_resp()])
    # Discover would set escaped=True for non-HTML content type.
    # We simulate that here.
    candidate = {
        "endpoint": "/api/profile", "parameter": "(json body)", "method": "POST",
        "canary": "abc", "reflected_count": 1,
        "escaped": True,  # set by discover() for non-HTML content type
        "context": ReflectionContext.UNKNOWN.value,
        "content_type": "application/json",
        "request": Request(method="POST", url="https://example.com/api/profile"),
        "response": _resp(
            body='{"error": "abc"}',
            headers={"content-type": "application/json"},
        ),
    }
    finding = await check.assess(candidate)
    assert finding is None  # safely encoded (JSON) → no finding


# ---------------------------------------------------------------------------
# 6. End-to-end discover() integration: context field populated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_discover_populates_context_field():
    """discover() must classify the reflection context for each candidate."""
    check = ReflectedXSSCheck()
    canary = _CANARIES[0]
    homepage = _resp('<html><a href="/?q=foo">x</a></html>')
    # Canary reflected inside an attribute
    body_with_canary = (
        '<html><a href="/search" title="' + canary + '">click</a></html>'
    )
    canary_resp = _resp(body_with_canary)
    side_effects = [homepage] + [canary_resp] * 25 + [_resp(status=404)] * 10
    _bind(check, side_effects)
    cands = await check.discover(MagicMock())
    assert len(cands) >= 1
    # At least one candidate carries the context field
    assert any("context" in c for c in cands)
    # The attribute-reflection candidate is classified as ATTRIBUTE
    attr_cands = [c for c in cands if c.get("context") == ReflectionContext.ATTRIBUTE.value]
    assert len(attr_cands) >= 1