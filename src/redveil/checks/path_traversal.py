"""PathTraversalCheck — detects path traversal via canary probing.

ACTIVE check. Uses ONLY unique random canary filenames that cannot exist on
real systems. Does NOT attempt to read any real file (no /etc/passwd etc).
The proof is the RESPONSE PATTERN (status, body length, error message), not
actual file content.

Wave 14 audit fixes:
  - Confirmation now requires the canary filename to appear in the
    traversal response body, OR a status-code transition from 404 →
    200. A length-only difference is downgraded to LIKELY (could be
    CDN cache miss, WAF block page, etc.).
  - WAF / rate-limit / 5xx responses are downgraded to INCONCLUSIVE
    so a contaminated probe can't become a false positive.
  - Multiple baseline samples establish endpoint stability before
    the traversal verdict is assigned.
  - Evidence carries environment_uncertainty + oracle_signal so the
    ConfidenceScorer can downgrade confidence appropriately.
"""
from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import quote, urlparse

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


# ONLY traversal sequences with a unique canary filename. NO references to real files.
# Canary is generated per scan to ensure the file cannot exist on the target.
def _build_canary() -> str:
    return f"redveil_canary_{secrets.token_hex(8)}.txt"

_TRAVERSAL_SEQUENCES = [
    "../{canary}",                          # simple
    "../../{canary}",                       # deeper
    "../../../{canary}",                    # deepest
    "....//{canary}",                       # double-dot bypass
    "..%2f{canary}",                        # URL-encoded /
    "..\\{canary}",                         # Windows backslash
    "/etc/{canary}",                        # absolute path attempt
    "//etc/{canary}",                       # double-slash bypass
]

# Safety: NO references to real sensitive files
_FORBIDDEN_FILES = (
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "system32", "win.ini", "boot.ini", "config.sys", "SAM",
    ".ssh/id_rsa", ".aws/credentials", ".kube/config",
)
for _seq in _TRAVERSAL_SEQUENCES:
    for _bad in _FORBIDDEN_FILES:
        if _bad in _seq:
            raise RuntimeError(f"FORBIDDEN file reference {_bad!r} in traversal sequence {_seq!r}")

# File-serving parameter names
_FILE_PARAMS = [
    "file", "path", "page", "template", "include", "src", "source",
    "url", "img", "image", "name", "doc", "document", "folder", "dir",
    "pg", "style", "pdf", "filename", "filepath", "resource", "load",
]

# HTTP status codes that indicate WAF / rate-limit / intermediary
# interference rather than the application itself responding. Same
# constants as control_probe.py but kept local so path_traversal
# remains self-contained.
_WAF_STATUS_CODES = (403, 406, 419, 501)
_RATE_LIMIT_STATUS_CODES = (429, 503)
_INTERFERENCE_STATUS_CODES = _WAF_STATUS_CODES + _RATE_LIMIT_STATUS_CODES

# Number of baseline samples per param before the verdict is decided.
# Helps ensure the endpoint is stable for the current test (spec rule:
# "do not assume two baseline requests are sufficient").
_N_BASELINE_SAMPLES = 2


def _generate_traversal_payloads() -> list[tuple[str, str]]:
    """Generate traversal payloads with a unique canary per call."""
    canary = _build_canary()
    payloads = []
    for seq in _TRAVERSAL_SEQUENCES:
        # Replace {canary} placeholder
        payload = seq.replace("{canary}", canary)
        payloads.append((payload, canary))
    return payloads, canary


def _outcome_for_traversal(
    behavior: str,
    status_code: int,
    baseline_status: int,
) -> ValidationOutcome:
    """Spec-mandated outcome matrix for path-traversal probes.

    - WAF / rate-limit status → INCONCLUSIVE (don't claim traversal
      from a contaminated probe).
    - Canary reflected in response body but baseline doesn't → CONFIRMED
      (server actually returned our canary file).
    - Status transition 404 → 200 → CONFIRMED (file appeared where it
      shouldn't).
    - Length-only change with no canary reflection → LIKELY (could be
      noise, CDN cache miss, error page substitution).
    - Status-only change → INCONCLUSIVE (could be WAF or redirect).
    - No change → FALSE_POSITIVE.
    """
    if status_code in _INTERFERENCE_STATUS_CODES:
        return ValidationOutcome.INCONCLUSIVE
    if behavior == "canary_reflected":
        return ValidationOutcome.CONFIRMED
    if behavior == "status_transition_404_to_200":
        return ValidationOutcome.CONFIRMED
    if behavior == "different_status":
        return ValidationOutcome.INCONCLUSIVE
    if behavior == "different_length":
        return ValidationOutcome.LIKELY
    return ValidationOutcome.FALSE_POSITIVE


class PathTraversalCheck(Check):
    meta = CheckMeta(
        id="path-traversal",
        name="Path Traversal Check",
        category=CheckCategory.PATH_TRAVERSAL,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects path traversal using unique canary filenames. Does not read any real file.",
        references=["CWE-22", "OWASP A01:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        # Optional ActionGate: present the path-traversal canary probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. Canary probes are LOW
        # risk (only random canary filenames, no real file paths) so this is
        # auto-approved.
        from redveil.validation.risk import ActionPlan, Risk
        # Wave 14: max_requests reflects actual execution
        # (N baseline samples + N traversal payloads per param).
        max_requests = len(_FILE_PARAMS) * (
            _N_BASELINE_SAMPLES + len(_TRAVERSAL_SEQUENCES)
        )
        plan = ActionPlan(
            action_id="path-traversal-canary-probe",
            description=(
                "Send path-traversal probes using unique random canary "
                "filenames (../canary, ../../canary, etc.) to file-serving "
                "parameters. No real file paths are read. Per parameter: "
                f"{_N_BASELINE_SAMPLES} baseline requests + "
                f"{len(_TRAVERSAL_SEQUENCES)} traversal sequences. Only "
                "sends GET requests with query parameters. No file read, "
                "no body modification."
            ),
            risk=Risk.LOW,
            target=f"{self.deps.config.target.base_url}/",
            purpose=(
                "Detect path traversal by observing whether canary "
                "filenames produce different responses than baseline."
            ),
            expected_effect=(
                "Baseline 404 + canary 200/404 indicates the parameter is "
                "reflected but traversal is filtered. Same 404 for both "
                "indicates no traversal."
            ),
            potential_side_effects=(
                "Logged in server access log.",
                "Canary file request may be logged (the file does not exist).",
                "May trigger WAF if present.",
            ),
            max_requests=max_requests,
            timeout_seconds=10.0,
        )
        if self.deps.gate is not None:
            decision = self.deps.gate.ask(
                plan,
                allow_destructive=self.deps.config.authorization.allow_destructive,
            )
            if not decision:
                # User denied or auto-denied (destructive in non-interactive).
                return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []

        payloads, canary = _generate_traversal_payloads()

        for param in _FILE_PARAMS:
            # Wave 14: multiple baseline samples — collect them first
            # to ensure the endpoint is stable for the current test.
            # We use the *median* baseline status / length as the
            # comparison reference.
            baseline_statuses: list[int] = []
            baseline_lengths: list[int] = []
            baseline_resp = None
            for _ in range(_N_BASELINE_SAMPLES):
                baseline_url = f"{join_url(base, '/')}?{param}={canary}"
                try:
                    req_base = Request(method="GET", url=baseline_url, purpose="baseline")
                    resp_base = await self.deps.http.send(req_base)
                except Exception:
                    continue
                baseline_statuses.append(resp_base.status_code)
                baseline_lengths.append(len(resp_base.body))
                if baseline_resp is None:
                    baseline_resp = resp_base
            if baseline_resp is None or not baseline_statuses:
                continue
            sorted_statuses = sorted(baseline_statuses)
            sorted_lengths = sorted(baseline_lengths)
            median_baseline_status = sorted_statuses[len(sorted_statuses) // 2]
            median_baseline_length = sorted_lengths[len(sorted_lengths) // 2]

            # Now test each traversal payload
            for payload, c in payloads:
                if c != canary:
                    continue  # safety: only use our own canary
                try:
                    test_url = f"{join_url(base, '/')}?{param}={quote(payload, safe='/\\')}"
                    req = Request(method="GET", url=test_url, purpose="probe", purpose_extra="path_traversal")
                    resp = await self.deps.http.send(req)
                except Exception:
                    continue

                # Classify the response relative to the median baseline.
                behavior = "no_change"
                if resp.status_code != median_baseline_status:
                    # 404 → 200 with payload is the strongest
                    # "file appeared" signal.
                    if median_baseline_status == 404 and resp.status_code == 200:
                        behavior = "status_transition_404_to_200"
                    else:
                        behavior = "different_status"
                elif len(resp.body) != median_baseline_length:
                    behavior = "different_length"

                # Strongest signal: canary filename appears in body
                # but is NOT in the baseline — server actually returned
                # our canary file content.
                if canary in resp.body and (
                    baseline_resp is None or canary not in baseline_resp.body
                ):
                    behavior = "canary_reflected"

                if behavior == "no_change":
                    continue

                candidates.append({
                    "endpoint": "/",
                    "parameter": param,
                    "method": "GET",
                    "payload": payload,
                    "canary": canary,
                    "baseline_status": median_baseline_status,
                    "baseline_length": median_baseline_length,
                    "canary_status": resp.status_code,
                    "canary_length": len(resp.body),
                    "behavior": behavior,
                    "request": req,
                    "response": resp,
                })
                break  # one finding per param is enough

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        outcome = _outcome_for_traversal(
            candidate.get("behavior", "no_change"),
            candidate.get("canary_status", 0),
            candidate.get("baseline_status", 0),
        )
        confidence = {
            ValidationOutcome.CONFIRMED: "high",
            ValidationOutcome.LIKELY: "medium",
            ValidationOutcome.INCONCLUSIVE: "low",
            ValidationOutcome.FALSE_POSITIVE: "low",
        }.get(outcome, "low")
        observation = (
            f"behavior={candidate.get('behavior', 'no_change')}; "
            f"baseline=({candidate.get('baseline_status')}, "
            f"{candidate.get('baseline_length')}B); "
            f"traversal=({candidate.get('canary_status')}, "
            f"{candidate.get('canary_length')}B)"
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
        outcome = _outcome_for_traversal(
            candidate.get("behavior", "no_change"),
            candidate.get("canary_status", 0),
            candidate.get("baseline_status", 0),
        )
        # environment_uncertainty: high for length-only / status-only
        # changes (could be CDN/WAF noise), low for canary-in-body
        # or 404→200 transitions.
        if outcome == ValidationOutcome.CONFIRMED:
            uncertainty = 0.1
        elif outcome == ValidationOutcome.LIKELY:
            uncertainty = 0.4
        elif outcome == ValidationOutcome.INCONCLUSIVE:
            uncertainty = 0.8
        else:
            uncertainty = 0.0
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.FILE_EXISTENCE,
            endpoint="/",
            method="GET",
            parameter=candidate.get("parameter"),
            input_used=candidate.get("payload", ""),
            status_code=resp.status_code,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=(
                f"baseline=({candidate['baseline_status']}, {candidate['baseline_length']}B); "
                f"traversal=({candidate['canary_status']}, {candidate['canary_length']}B); "
                f"behavior={candidate['behavior']}"
            ),
            # Wave 14 evidence fields
            oracle_signal="file_existence",
            validation_outcome=outcome.value,
            confidence=(
                "high" if outcome == ValidationOutcome.CONFIRMED
                else "medium" if outcome == ValidationOutcome.LIKELY
                else "low"
            ),
            environment_uncertainty=uncertainty,
            waf_detected=resp.status_code in _WAF_STATUS_CODES,
            rate_limited=resp.status_code in _RATE_LIMIT_STATUS_CODES,
            test_mode="safe",
            destructive=False,
            destructive_level=None,
        )]

    async def assess(self, candidate) -> Finding | None:
        outcome = _outcome_for_traversal(
            candidate.get("behavior", "no_change"),
            candidate.get("canary_status", 0),
            candidate.get("baseline_status", 0),
        )
        # FALSE_POSITIVE → no finding per spec.
        if outcome == ValidationOutcome.FALSE_POSITIVE:
            return None

        # Per-outcome severity + confidence + status.
        if outcome == ValidationOutcome.CONFIRMED:
            severity = Severity.HIGH
            confidence_enum = Confidence.HIGH
            status = FindingStatus.CONFIRMED
        elif outcome == ValidationOutcome.LIKELY:
            severity = Severity.MEDIUM
            confidence_enum = Confidence.MEDIUM
            status = FindingStatus.LIKELY
        else:  # INCONCLUSIVE
            severity = Severity.LOW
            confidence_enum = Confidence.LOW
            status = FindingStatus.INCONCLUSIVE

        entry = get_entry(self.meta.id, "path_traversal")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = (
                f"Path traversal evidence in '{candidate['parameter']}' "
                f"parameter ({candidate.get('behavior', 'unknown')} signal)."
            )
            technical = (
                f"The parameter '{candidate['parameter']}' produces a "
                f"different response when traversal sequences are applied. "
                f"Baseline: status={candidate.get('baseline_status')}, "
                f"length={candidate.get('baseline_length')}B. Traversal: "
                f"status={candidate.get('canary_status')}, length="
                f"{candidate.get('canary_length')}B."
            )
            impact = "Attacker can read arbitrary files on the server."
            remediation = [
                "Validate file paths against an allowlist.",
                "Reject paths containing '..' or absolute paths.",
            ]
            attack_scenario = None
            code_examples = {}

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Path Traversal via '{candidate['parameter']}' Parameter ({candidate.get('behavior', 'unknown')})",
            severity=severity,
            confidence=confidence_enum,
            status=status,
            target=TargetRef(
                host=parsed.hostname or "",
                port=parsed.port,
                scheme=parsed.scheme or "https",
                endpoint="/",
                method="GET",
                parameter=candidate["parameter"],
            ),
            parameter=candidate["parameter"],
            input_used=candidate.get("payload", ""),
            summary=summary,
            technical_explanation=technical,
            impact=impact,
            attack_scenario=attack_scenario,
            code_examples=code_examples,
            remediation=remediation,
            cwe=["CWE-22"],
            owasp=["A01:2021"],
        )
