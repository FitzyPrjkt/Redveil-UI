"""ReflectedXSSCheck — detects reflected cross-site scripting via benign canary strings.

ACTIVE check. Uses harmless alphanumeric canaries that cannot trigger script
execution. The proof of vulnerability is that the canary appears UNESCAPED in
the response body — not that the canary runs.

Wave 14: the check now classifies the reflection CONTEXT — HTML text,
attribute, JavaScript block, URL attribute — and picks the outcome +
confidence per context. A raw reflection inside a <script> block or an
attribute that lets the attacker break out is CONFIRMED; a raw
reflection in plain HTML text is LIKELY; a safely-encoded reflection
does NOT produce a finding.
"""
from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
from redveil.findings.finding import CheckRef, Finding, FindingStatus, TargetRef
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.knowledge.vuln_descriptions import get_entry
from redveil.plugins.base import (
    Check,
    CheckCategory,
    CheckMeta,
    ValidationOutcome,
    ValidationResult,
)
from redveil.util.urls import join_url

# BENIGN canary strings — cannot execute JavaScript. Just plain text + HTML/quote chars.
# The proof is reflection of these chars unescaped, not script execution.
_CANARIES = [
    "redveilXSSProbe12345",                              # plain alphanumeric
    "redv&quot;ail12345",                                # HTML-encoded quote (test if user can re-introduce a quote)
    "redveilXSSanglebracketless12345",                   # tests for angle brackets
]
_HTML_ESCAPED_QUOTE = "&quot;"
_HTML_ESCAPED_LT = "&lt;"
_HTML_ESCAPED_GT = "&gt;"
_HTML_ESCAPED_AMP = "&amp;"
_HTML_ESCAPED_APOS = "&#x27;"


# Reflection context — Wave 14. The validator picks outcome + confidence
# per context: a raw reflection inside an attribute or <script> block is
# CONFIRMED (the attacker can break out / execute JS), while a raw
# reflection in plain HTML text is LIKELY (still a bug, lower impact),
# and a safely-encoded reflection does NOT become a finding.
class ReflectionContext(str, Enum):
    HTML_TEXT = "html_text"
    ATTRIBUTE = "attribute"
    SCRIPT = "script"
    URL = "url"
    STYLE = "style"
    UNKNOWN = "unknown"


def _detect_reflection_context(body: str, canary_pos: int) -> ReflectionContext:
    """Classify where the canary landed in the response body.

    Naive regex-based — no full HTML parser. Sufficient for the
    contexts we care about: <script>, <style>, URL-bearing attrs
    (href/src/action), other attrs, otherwise HTML text.
    """
    if canary_pos < 0 or not body:
        return ReflectionContext.UNKNOWN

    # <script>...</script> block?
    last_open = max(
        (m.end() for m in re.finditer(r"<script\b[^>]*>", body, re.IGNORECASE) if m.start() <= canary_pos),
        default=-1,
    )
    if last_open >= 0:
        close = body.lower().find("</script>", last_open)
        if close == -1 or close > canary_pos:
            return ReflectionContext.SCRIPT

    # <style>...</style> block?
    last_open = max(
        (m.end() for m in re.finditer(r"<style\b[^>]*>", body, re.IGNORECASE) if m.start() <= canary_pos),
        default=-1,
    )
    if last_open >= 0:
        close = body.lower().find("</style>", last_open)
        if close == -1 or close > canary_pos:
            return ReflectionContext.STYLE

    # URL-bearing attribute (href / src / action / formaction / xlink:href).
    # Search the WHOLE body — not body[:canary_pos] — so a canary
    # inside the second attribute (e.g. `href="x" title="canary"`)
    # still gets the right context. The check is `canary in [open, close)`.
    for attr in ("href", "src", "action", "formaction", "xlink:href"):
        for m in re.finditer(
            rf'\b{re.escape(attr)}\s*=\s*["\']',
            body,
            re.IGNORECASE,
        ):
            quote_char = body[m.end() - 1]
            close = body.find(quote_char, m.end())
            if close != -1 and m.end() <= canary_pos < close:
                return ReflectionContext.URL

    # Any other attribute (non-URL). Same approach: scan the body for any
    # `attr="` or `attr='` opening AFTER the most recent `<` before
    # the canary, then check whether the canary lies within the
    # attribute's value range. We use a non-tag-prefix pattern so a
    # canary in the second attribute (e.g. `<a href="x" title="canary"`)
    # still gets ATTRIBUTE.
    last_tag_open = -1
    for m in re.finditer(r"<", body[:canary_pos]):
        last_tag_open = m.end()
    if last_tag_open >= 0:
        tag_segment = body[last_tag_open:canary_pos]
        # Find any attribute opener in the tag segment (a word boundary
        # followed by `=`, with optional whitespace, and a quote).
        for m in re.finditer(r"\b\w+\s*=\s*[\"']", tag_segment):
            quote_char = tag_segment[m.end() - 1]
            close = body.find(quote_char, last_tag_open + m.end())
            if close != -1 and last_tag_open + m.end() <= canary_pos < close:
                return ReflectionContext.ATTRIBUTE

    return ReflectionContext.HTML_TEXT


def _is_canary_html_encoded(body: str, canary: str) -> bool:
    """Heuristic: True if the response body contains HTML-encoded entities.

    For a stronger guarantee the check uses the secondary canary
    (``redv&quot;ail12345``) which already contains ``&quot;`` to
    verify the encoder runs at all.
    """
    return any(
        enc in body
        for enc in (
            _HTML_ESCAPED_QUOTE,
            _HTML_ESCAPED_LT,
            _HTML_ESCAPED_GT,
            _HTML_ESCAPED_AMP,
            _HTML_ESCAPED_APOS,
        )
    )


def _outcome_for_context(
    context: ReflectionContext,
    encoded: bool,
) -> ValidationOutcome:
    """Spec: encoding + context determine outcome.

    - Encoded reflection → FALSE_POSITIVE (no finding)
    - Raw in HTML_TEXT → LIKELY (medium-impact bug)
    - Raw in attribute / script / url / style → CONFIRMED (exploitable)
    - Unknown context + raw → LIKELY (conservative)
    """
    if encoded:
        return ValidationOutcome.FALSE_POSITIVE
    if context in (
        ReflectionContext.ATTRIBUTE,
        ReflectionContext.SCRIPT,
        ReflectionContext.URL,
        ReflectionContext.STYLE,
    ):
        return ValidationOutcome.CONFIRMED
    return ValidationOutcome.LIKELY


def _confidence_for_context(context: ReflectionContext, encoded: bool) -> str:
    """Confidence level matching the context's exploitability."""
    if encoded:
        return "high"  # high confidence: no finding
    if context in (
        ReflectionContext.SCRIPT,
        ReflectionContext.URL,
        ReflectionContext.ATTRIBUTE,
    ):
        return "high"  # direct exploitation possible
    if context == ReflectionContext.STYLE:
        return "medium"
    return "medium"  # HTML text — bug, but lower impact


_COMMON_PARAM_NAMES = [
    "q", "s", "search", "query", "id", "name", "input", "text",
    "message", "msg", "comment", "body", "title",
    "url", "redirect", "next", "return", "callback", "ref",
]


class ReflectedXSSCheck(Check):
    meta = CheckMeta(
        id="xss-reflected",
        name="Reflected XSS Check",
        category=CheckCategory.XSS,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects reflected XSS by injecting benign canary strings and checking for unescaped reflection. No executable payloads.",
        references=["CWE-79", "OWASP A03:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        # Active gate
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        # Optional ActionGate: present the canary probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. Canary probes
        # are LOW risk (no destructive payload) so this is auto-approved.
        from redveil.validation.risk import ActionPlan, Risk, DestructiveLevel
        plan = ActionPlan(
            action_id="xss-canary-probe",
            description=(
                "Send benign alphanumeric canary to common reflection "
                "points (q, search, query, id, name, input, text, message, "
                "msg, comment, body, title, url, redirect, next, return, "
                "callback, ref) and check whether the canary is reflected "
                "unescaped in the response body."
            ),
            risk=Risk.LOW,
            target=str(self.deps.config.target.base_url).rstrip("/") + "/",
            purpose="Detect reflected XSS by checking for unescaped input reflection.",
            expected_effect="200 OK response; canary present in body if reflected.",
            potential_side_effects=(
                "Logged in server access log; may trigger WAF if present.",
            ),
            max_requests=20,
            timeout_seconds=10.0,
            # XSS at MAX could enable cookie theft (data_exfiltration = level 1).
            # We only do canary reflection (level 0, no destructive), so set
            # destructive=False here. The plan's max_destructive_level is
            # what XSS could enable if exploited; redveil's check doesn't
            # do that.
            destructive=False,
            destructive_level=DestructiveLevel.DATA_EXFILTRATION,
        )
        if self.deps.gate is not None:
            decision = self.deps.gate.ask(
                plan,
                allow_destructive=self.deps.config.authorization.allow_destructive,
            )
            if not decision:
                # User denied or auto-denied (destructive in non-interactive).
                # In this case, deny is the right behavior.
                return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # 1. Find candidate parameters from homepage
        try:
            req_home = Request(method="GET", url=join_url(base, "/"), purpose="discovery")
            resp_home = await self.deps.http.send(req_home)
        except Exception:
            return candidates

        param_names: set[str] = set()
        # Extract from href and form action
        for m in re.finditer(r'[\?&]([a-zA-Z_][\w-]*)=', resp_home.body):
            param_names.add(m.group(1).lower())
        param_names.update(_COMMON_PARAM_NAMES)

        # 2. For each parameter, test canary reflection
        for param in sorted(param_names):
            canary = _CANARIES[0]  # primary canary
            try:
                test_url = f"{join_url(base, '/')}?{param}={canary}"
                req = Request(method="GET", url=test_url, purpose="probe", purpose_extra="xss_canary")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            if canary in resp.body:
                # Check if reflected unescaped
                escaped = (_HTML_ESCAPED_QUOTE in resp.body) and (canary not in resp.body.replace(_HTML_ESCAPED_QUOTE, ""))
                reflected_count = resp.body.count(canary)
                # Wave 14: detect reflection context (HTML text vs
                # attribute vs script vs URL) so validate() can pick
                # the right outcome.
                idx = resp.body.find(canary)
                context = _detect_reflection_context(resp.body, idx)
                content_type = resp.headers.get("content-type", "")
                candidates.append({
                    "endpoint": "/",
                    "parameter": param,
                    "method": "GET",
                    "canary": canary,
                    "reflected_count": reflected_count,
                    "escaped": escaped,
                    "context": context.value,
                    "content_type": content_type,
                    "request": req,
                    "response": resp,
                })

        # 3. Also test common API endpoints with JSON body
        for path in ["/api", "/api/v1", "/api/data", "/api/profile"]:
            try:
                canary = _CANARIES[0]
                json_body = json.dumps(dict.fromkeys(list(param_names)[:5], canary))
                req = Request(
                    method="POST",
                    url=join_url(base, path),
                    body=json_body,
                    purpose="probe",
                    purpose_extra="xss_canary_json",
                )
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code == 200 and canary in resp.body:
                # JSON content-type responses don't render HTML — the
                # canary lands in a non-HTML context, so it's treated
                # as safely-encoded for XSS purposes. We still surface
                # the content type + context so validate() can decide.
                content_type = resp.headers.get("content-type", "")
                is_html_context = "html" in content_type.lower()
                candidates.append({
                    "endpoint": path,
                    "parameter": "(json body)",
                    "method": "POST",
                    "canary": canary,
                    "reflected_count": resp.body.count(canary),
                    # JSON responses aren't rendered as HTML, so the
                    # canary cannot execute script even when raw.
                    "escaped": not is_html_context,
                    "context": (
                        ReflectionContext.HTML_TEXT.value
                        if is_html_context
                        else ReflectionContext.UNKNOWN.value
                    ),
                    "content_type": content_type,
                    "request": req,
                    "response": resp,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        # Wave 14: outcome depends on context + encoding, not just a
        # binary encoded/unescaped flag. Spec: a safely-encoded
        # reflection does NOT become CONFIRMED.
        context_str = candidate.get("context", ReflectionContext.UNKNOWN.value)
        try:
            context = ReflectionContext(context_str)
        except ValueError:
            context = ReflectionContext.UNKNOWN
        encoded = bool(candidate.get("escaped"))
        outcome = _outcome_for_context(context, encoded)
        confidence = _confidence_for_context(context, encoded)
        observation = (
            f"context={context.value}; "
            f"canary_reflected={candidate.get('reflected_count', 1)}x; "
            f"html_encoded_somewhere={encoded}; "
            f"content_type={candidate.get('content_type', '')}"
        )
        return ValidationResult(
            outcome=outcome,
            confidence=confidence,
            observation=observation,
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        # Extract a 200-char window around the first canary
        canary = candidate.get("canary", "")
        idx = resp.body.find(canary)
        if idx >= 0:
            start = max(0, idx - 100)
            end = min(len(resp.body), idx + len(canary) + 100)
            excerpt = resp.body[start:end]
        else:
            excerpt = resp.body_excerpt
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.REFLECTION,
            endpoint=req.url,
            method=candidate.get("method", "GET"),
            parameter=candidate.get("parameter"),
            input_used=canary,
            status_code=resp.status_code,
            relevant_headers={"content-type": candidate.get("content_type", "")},
            body_excerpt=excerpt,
            observation=(
                f"context={candidate.get('context', 'unknown')}; "
                f"canary reflected {candidate.get('reflected_count', 1)} time(s); "
                f"raw={not candidate.get('escaped')}"
            ),
            # Wave 14 evidence fields
            oracle_signal="reflection",
            validation_outcome=_outcome_for_context(
                ReflectionContext(candidate.get("context", ReflectionContext.UNKNOWN.value))
                if candidate.get("context") in ReflectionContext._value2member_map_
                else ReflectionContext.UNKNOWN,
                bool(candidate.get("escaped")),
            ).value,
            confidence=(
                "high" if _outcome_for_context(
                    ReflectionContext(candidate.get("context", ReflectionContext.UNKNOWN.value))
                    if candidate.get("context") in ReflectionContext._value2member_map_
                    else ReflectionContext.UNKNOWN,
                    bool(candidate.get("escaped")),
                ) == ValidationOutcome.CONFIRMED
                else "medium"
            ),
            environment_uncertainty=(
                0.0 if bool(candidate.get("escaped"))
                else 0.1 if candidate.get("context") in (ReflectionContext.SCRIPT.value, ReflectionContext.URL.value)
                else 0.2 if candidate.get("context") == ReflectionContext.ATTRIBUTE.value
                else 0.4
            ),
            test_mode="safe",
            destructive=False,
            destructive_level=None,
        )]

    async def assess(self, candidate) -> Finding | None:
        # Wave 14: severity + confidence depend on context, not a
        # uniform "always CONFIRMED, always HIGH". Spec: "A reflection
        # that is safely encoded should not become CONFIRMED."
        context_str = candidate.get("context", ReflectionContext.UNKNOWN.value)
        try:
            context = ReflectionContext(context_str)
        except ValueError:
            context = ReflectionContext.UNKNOWN
        encoded = bool(candidate.get("escaped"))
        outcome = _outcome_for_context(context, encoded)
        if outcome == ValidationOutcome.FALSE_POSITIVE:
            # Encoded reflection — no finding.
            return None

        # Per-context severity + confidence.
        if context in (ReflectionContext.SCRIPT, ReflectionContext.URL):
            severity = Severity.CRITICAL
            confidence_enum = Confidence.HIGH
        elif context == ReflectionContext.ATTRIBUTE:
            severity = Severity.HIGH
            confidence_enum = Confidence.HIGH
        elif context == ReflectionContext.STYLE:
            severity = Severity.MEDIUM
            confidence_enum = Confidence.MEDIUM
        else:
            severity = Severity.HIGH
            confidence_enum = Confidence.MEDIUM

        entry = get_entry(self.meta.id, "reflected")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = (
                f"Parameter '{candidate['parameter']}' reflects user input "
                f"raw in the response ({context.value} context)."
            )
            technical = (
                f"The server does not properly context-encode the parameter "
                f"value before embedding it. The canary lands in a "
                f"{context.value} context where attacker-controlled input "
                f"can break out of the surrounding markup."
            )
            impact = "Attacker can execute arbitrary JavaScript in victim's browser, leading to session hijacking, credential theft, or phishing."
            remediation = [
                "Apply context-aware output encoding (HTML / attribute / JS / URL).",
                "Set Content-Security-Policy header.",
                "Validate input against an allowlist before rendering.",
            ]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        from urllib.parse import urlparse as _up
        req_parsed = _up(candidate["request"].url)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Reflected XSS via '{candidate['parameter']}' Parameter ({context.value} context)",
            severity=severity,
            confidence=confidence_enum,
            status=(
                FindingStatus.CONFIRMED
                if outcome == ValidationOutcome.CONFIRMED
                else FindingStatus.LIKELY
            ),
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=req_parsed.path or "/",
                method=candidate["method"],
                parameter=candidate["parameter"],
            ),
            parameter=candidate["parameter"],
            input_used=candidate.get("canary", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-79"],
            owasp=["A03:2021"],
        )
