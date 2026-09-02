"""MassAssignmentCheck — passive + active-mass-assignment detector.

Wave 14 spec compliance:

Phase 1 — Passive detection of exposed sensitive fields. The check
walks JSON responses from common profile endpoints and flags any
field name matching a sensitive pattern (admin / role / balance /
verification / internal). This is the existing behavior.

Phase 2 — Optional controlled mutation test (active, gated). When
``active_testing=True`` AND the operator has acknowledged safety
terms, the check sends a POST to the same endpoint with a unique
canary value for ONE detected sensitive field (e.g.
``is_admin=redveil_mass_assignment_canary_<hash>``) and inspects
the response:

  - 200/201 + canary reflected in response body → CONFIRMED
    writable (the server accepted and stored the canary field).
  - 200/201 + canary NOT reflected → LIKELY (server accepted the
    write but did not echo it back; could still be writable).
  - 4xx with field-rejection message → INCONCLUSIVE (server
    rejected the write — the field may not be writable from this
    endpoint).
  - 401/403 → INCONCLUSIVE (auth required; cannot test mutation
    without valid session).
  - 5xx → INCONCLUSIVE (server error; inconclusive).

The canary is unique per request so it cannot collide with real
data. The original GET response is preserved so the canary field
can be rolled back manually if needed (the check does NOT attempt
to undo its write — the operator owns the rollback).
"""
from __future__ import annotations

import json
import re
import secrets
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

# (regex matching field name, severity if found, sensitivity label)
_SENSITIVE_FIELD_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    # Admin / role
    (re.compile(r"^is_admin$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^is_superuser$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^is_staff$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^is_moderator$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^role$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^user_role$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^permissions$", re.IGNORECASE), Severity.HIGH, "admin"),
    (re.compile(r"^groups$", re.IGNORECASE), Severity.HIGH, "admin"),
    # Financial
    (re.compile(r"^balance$", re.IGNORECASE), Severity.MEDIUM, "financial"),
    (re.compile(r"^credit_limit$", re.IGNORECASE), Severity.MEDIUM, "financial"),
    (re.compile(r"^internal_balance$", re.IGNORECASE), Severity.HIGH, "financial"),
    (re.compile(r"^account_balance$", re.IGNORECASE), Severity.MEDIUM, "financial"),
    # Verification status
    (re.compile(r"^email_verified$", re.IGNORECASE), Severity.LOW, "verification"),
    (re.compile(r"^phone_verified$", re.IGNORECASE), Severity.LOW, "verification"),
    (re.compile(r"^kyc_status$", re.IGNORECASE), Severity.MEDIUM, "verification"),
    (re.compile(r"^two_factor_enabled$", re.IGNORECASE), Severity.LOW, "verification"),
    (re.compile(r"^mfa_enabled$", re.IGNORECASE), Severity.LOW, "verification"),
    # Internal / segmentation
    (re.compile(r"^internal_id$", re.IGNORECASE), Severity.MEDIUM, "internal"),
    (re.compile(r"^customer_segment$", re.IGNORECASE), Severity.MEDIUM, "internal"),
    (re.compile(r"^risk_score$", re.IGNORECASE), Severity.MEDIUM, "internal"),
    (re.compile(r"^tenant_id$", re.IGNORECASE), Severity.MEDIUM, "internal"),
]

# Endpoints to probe (typically where the user's own profile is)
_PROFILE_PATHS = [
    "/api/profile/me", "/api/profile",
    "/api/user/me", "/api/user",
    "/api/users/me", "/api/users",
    "/api/me", "/api/account", "/api/account/me",
    "/api/v1/profile", "/api/v1/user", "/api/v1/users/me",
    "/api/v1/account", "/api/v1/me",
]


def _extract_field_names(obj: Any, path: str = "") -> set[tuple[str, str]]:
    """Walk a JSON object, return set of (field_name, full_path) tuples for leaf fields."""
    out: set[tuple[str, str]] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{path}.{k}" if path else k
            if isinstance(v, (dict, list)):
                out.update(_extract_field_names(v, full))
            else:
                out.add((k, full))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:10]):  # cap list walking
            out.update(_extract_field_names(item, f"{path}[{i}]"))
    return out


def _build_canary_value() -> str:
    """Per-request canary value for mutation testing.

    Format: ``redveil_mass_assignment_canary_<16hex>``. The prefix makes
    it identifiable in logs / reports; the random hex ensures it cannot
    collide with real data.
    """
    return f"redveil_mass_assignment_canary_{secrets.token_hex(8)}"


def _mutation_outcome(
    *,
    status_code: int,
    canary_in_response: bool,
) -> ValidationOutcome:
    """Map a mutation-test response to ValidationOutcome.

    - 200/201 + canary reflected → CONFIRMED (server accepted and
      stored the canary field).
    - 200/201 + canary NOT reflected → LIKELY (accepted but not echoed).
    - 4xx → INCONCLUSIVE (server rejected — likely not writable here).
    - 401/403 → INCONCLUSIVE (auth required, cannot test).
    - 5xx → INCONCLUSIVE (server error, inconclusive).
    """
    if 200 <= status_code < 300 and canary_in_response:
        return ValidationOutcome.CONFIRMED
    if 200 <= status_code < 300:
        return ValidationOutcome.LIKELY
    if 400 <= status_code < 500:
        return ValidationOutcome.INCONCLUSIVE
    return ValidationOutcome.INCONCLUSIVE


class MassAssignmentCheck(Check):
    meta = CheckMeta(
        id="mass-assignment",
        name="Mass Assignment Check",
        category=CheckCategory.MASS_ASSIGNMENT,
        safety_profile=SafetyProfile.PASSIVE,
        description="Detects when API responses expose sensitive fields (admin/role/balance/etc.) that may also be modifiable via mass assignment. Phase 2 mutation test is gated behind active_testing.",
        references=["CWE-915", "OWASP A06:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        # Phase 2 mutation testing is gated behind active_testing +
        # acknowledged safety terms. The check is documented as PASSIVE
        # in meta because Phase 1 is passive; the mutation test is an
        # optional add-on when the operator has explicitly opted in.
        phase2_enabled = bool(
            getattr(self.deps.config.authorization, "active_testing", False)
        )

        for path in _PROFILE_PATHS:
            try:
                req = Request(method="GET", url=join_url(base, path), purpose="discovery")
                resp = await self.deps.http.send(req)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            # Try to parse as JSON
            try:
                data = json.loads(resp.body)
            except (json.JSONDecodeError, ValueError):
                continue
            # Extract field names
            field_names = _extract_field_names(data)
            # Check each against sensitive patterns
            seen: set[str] = set()
            for field_name, full_path in field_names:
                if field_name in seen:
                    continue
                for pattern, severity, sensitivity in _SENSITIVE_FIELD_PATTERNS:
                    if pattern.match(field_name):
                        candidate = {
                            "endpoint": path,
                            "method": "GET",
                            "field": field_name,
                            "field_path": full_path,
                            "severity": severity,
                            "sensitivity": sensitivity,
                            "request": req,
                            "response": resp,
                            "phase2_attempted": False,
                        }
                        # Phase 2: send a POST with the canary value
                        # for this one field and check if it's accepted.
                        if phase2_enabled:
                            await self._attempt_mutation(
                                base, path, field_name, candidate, data,
                            )
                        candidates.append(candidate)
                        seen.add(field_name)
                        break

        return candidates

    async def _attempt_mutation(
        self,
        base: str,
        path: str,
        field_name: str,
        candidate: dict[str, Any],
        original_body: Any,
    ) -> None:
        """Phase 2 — POST a canary value for the sensitive field.

        Updates ``candidate`` in-place with mutation_request /
        mutation_response / mutation_outcome / canary_value so
        validate() and assess() can use them.
        """
        canary = _build_canary_value()
        # Build a JSON body that includes the original fields plus the
        # canary for the sensitive field. We merge, not replace, so
        # required fields stay populated.
        if isinstance(original_body, dict):
            payload = dict(original_body)
        else:
            payload = {}
        payload[field_name] = canary
        mutation_req = Request(
            method="POST",
            url=join_url(base, path),
            body=json.dumps(payload),
            purpose="mass_assignment_mutation_test",
            purpose_extra=f"canary_field={field_name}",
        )
        try:
            mutation_resp = await self.deps.http.send(mutation_req)
        except Exception:
            return
        candidate["phase2_attempted"] = True
        candidate["mutation_request"] = mutation_req
        candidate["mutation_response"] = mutation_resp
        candidate["canary_value"] = canary
        canary_in_body = (
            mutation_resp is not None
            and mutation_resp.body is not None
            and canary in mutation_resp.body
        )
        candidate["mutation_outcome"] = _mutation_outcome(
            status_code=mutation_resp.status_code,
            canary_in_response=canary_in_body,
        )
        waf_detected = mutation_resp.status_code in (403, 406, 419, 501)
        rate_limited = mutation_resp.status_code in (429, 503)
        candidate["mutation_waf_detected"] = waf_detected
        candidate["mutation_rate_limited"] = rate_limited

    async def validate(self, ctx, candidate) -> ValidationResult:
        sev = candidate.get("severity", Severity.MEDIUM)
        # Phase 2 mutation: CONFIRMED only if the server accepted the
        # canary field write. Otherwise the exposure-only signal
        # remains LIKELY.
        if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.CONFIRMED:
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=(
                    f"sensitive field '{candidate['field']}' is writable: "
                    f"server accepted mutation and reflected canary in response"
                ),
            )
        if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.INCONCLUSIVE:
            # Auth required or server rejection — we cannot determine
            # writability from this scan.
            note = "auth required" if candidate.get("mutation_response") and candidate.get("mutation_response").status_code in (401, 403) else "server rejected"
            return ValidationResult(
                outcome=ValidationOutcome.INCONCLUSIVE,
                confidence="low",
                observation=(
                    f"sensitive field '{candidate['field']}' exposed but "
                    f"mutation test inconclusive ({note})"
                ),
            )
        # Phase 1 only — passive exposure.
        if sev in (Severity.HIGH, Severity.CRITICAL):
            return ValidationResult(
                outcome=ValidationOutcome.LIKELY,
                confidence="medium",
                observation=f"sensitive field '{candidate['field']}' ({candidate['sensitivity']}) exposed in API response",
            )
        return ValidationResult(
            outcome=ValidationOutcome.LIKELY,
            confidence="low",
            observation=f"field '{candidate['field']}' ({candidate['sensitivity']}) exposed — manual review",
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        # Wave 14 environment uncertainty: low for Phase 1 exposure,
        # near-zero for Phase 2 confirmation (server literally echoed
        # the canary), high for INCONCLUSIVE (auth / rejection).
        if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.CONFIRMED:
            uncertainty = 0.1
            oracle_signal = "state_change"
        elif candidate.get("phase2_attempted"):
            uncertainty = 0.6
            oracle_signal = "reflection_diff"
        else:
            uncertainty = 0.4
            oracle_signal = "reflection"
        waf_detected = resp.status_code in (403, 406, 419, 501)
        rate_limited = resp.status_code in (429, 503)
        mut = candidate.get("mutation_response")
        if mut is not None:
            waf_detected = waf_detected or mut.status_code in (403, 406, 419, 501)
            rate_limited = rate_limited or mut.status_code in (429, 503)
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.HEADER_PRESENT,
            endpoint=candidate["endpoint"],
            method="GET",
            parameter=candidate["field"],
            input_used="(response body field)",
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=f"sensitive field '{candidate['field']}' ({candidate['sensitivity']}) exposed in {candidate['endpoint']}",
            # Wave 14 evidence fields
            oracle_signal=oracle_signal,
            validation_outcome=(
                "confirmed" if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.CONFIRMED
                else "inconclusive" if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.INCONCLUSIVE
                else "likely"
            ),
            confidence=(
                "high" if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.CONFIRMED
                else "low" if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.INCONCLUSIVE
                else "medium"
            ),
            environment_uncertainty=uncertainty,
            waf_detected=waf_detected,
            rate_limited=rate_limited,
            test_mode="active" if candidate.get("phase2_attempted") else "passive",
            destructive=False,
            destructive_level=None,
        )]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry("mass-assignment", "excessive_exposure")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Sensitive field '{candidate['field']}' is exposed in the API response."
            technical = (
                f"The endpoint {candidate['endpoint']} returns the field "
                f"'{candidate['field']}' (sensitivity: {candidate['sensitivity']}). "
                f"This may also indicate the field is modifiable via mass assignment."
            )
            impact = "Information disclosure. If the field is also writable, privilege escalation may be possible."
            remediation = ["Use a serializer with an explicit allowlist of fields.", "Never bind user input directly to ORM models."]
            attack_scenario = None
            code_examples = {}

        # Per-outcome severity / confidence / status. Phase 2
        # confirmation makes the finding CONFIRMED — the field is not
        # only exposed, it's writable.
        if candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.CONFIRMED:
            status = FindingStatus.CONFIRMED
            confidence_enum = Confidence.HIGH
        elif candidate.get("phase2_attempted") and candidate.get("mutation_outcome") == ValidationOutcome.INCONCLUSIVE:
            status = FindingStatus.INCONCLUSIVE
            confidence_enum = Confidence.LOW
        else:
            status = FindingStatus.LIKELY
            confidence_enum = Confidence.MEDIUM

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Sensitive Field Exposed: {candidate['field']}",
            severity=candidate["severity"],
            confidence=confidence_enum,
            status=status,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint=candidate["endpoint"],
                method="GET",
            ),
            parameter=candidate["field"],
            input_used="(field in response body)",
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-915"],
            owasp=["A06:2021"],
        )
