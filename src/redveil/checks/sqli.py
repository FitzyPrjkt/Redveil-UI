"""TimeBasedSQLiCheck — detects time-based blind SQL injection.

ACTIVE check. Uses ONLY time-delay payloads (SLEEP/pg_sleep/WAITFOR DELAY).
No data extraction. No SELECT/UNION/OR 1=1 exploitation. The proof is the
OBSERVED response delay, not data exfiltration.
"""
from __future__ import annotations

import statistics
from typing import Any
from urllib.parse import quote, urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.finding import CheckRef, Finding, FindingStatus, TargetRef
from redveil.findings.severity import Severity
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.knowledge.vuln_descriptions import get_entry
from redveil.plugins.base import (
    Check,
    CheckCategory,
    CheckMeta,
    ValidationOutcome,
    ValidationResult,
)
from redveil.util.urls import join_url
from redveil.validation.confidence import ConfidenceScorer
from redveil.validation.control_probe import (
    INCONCLUSIVE,
    RATE_LIMITED,
    TIMING_ANOMALY,
    TIMING_FLAKY,
    TIMING_REPRODUCIBLE,
    WAF_INTERFERENCE,
    reason_for_verdict,
    run_control_probe_sequence,
)
from redveil.validation.oracle import Oracle, Signal, SignalKind

# Time-delay payloads (NO data extraction, NO SELECT/UNION/OR)
# Capped at 3 seconds delay — observable but bounded.
_DELAY_PAYLOADS = [
    ("mysql", "1' AND SLEEP(3)-- -"),
    ("mysql", "1) AND SLEEP(3)-- -"),
    ("mysql", "1 AND SLEEP(3)"),
    ("postgresql", "1' AND pg_sleep(3)-- -"),
    ("postgresql", "1; SELECT pg_sleep(3)-- -"),
    ("mssql", "1'; WAITFOR DELAY '00:00:03'-- -"),
    ("mssql", "1' WAITFOR DELAY '00:00:03'-- -"),
    ("sqlite", "1' AND 1=randomblob(500000000)-- -"),  # CPU delay, not data extraction
]

_COMMON_PARAM_NAMES = [
    "q", "s", "search", "query", "id", "name", "input", "user", "username",
    "email", "page", "cat", "category", "filter", "sort", "order",
    "from", "to", "date", "year", "month",
]

_BASELINE_SAMPLES = 2
_DELAY_THRESHOLD_MS = 2000.0
_DELAY_RATIO = 3.0

# New control+probe+replay validation parameters. These drive the
# reproducibility check and the ActionPlan budget. They are intentionally
# distinct from the legacy _BASELINE_SAMPLES so the ActionPlan
# max_requests reflects the actual worst-case request count under the
# new pattern.
REPRODUCTION_SAMPLES = 3   # baseline samples
REPROBE_SAMPLES = 2        # probe samples per round (2 rounds)
# Per (param, payload) worst-case request budget. The actual sequence
# under run_control_probe_sequence is 3 baseline + 2 control + 4 probe = 9
# requests. The spec over-budgets to 10 to absorb the WAF / rate-limit
# early-exit overhead and to match the documented formula
# REPRODUCTION_SAMPLES * 2 + REPROBE_SAMPLES * 2 = 3*2 + 2*2 = 10.
_REQUESTS_PER_PAIR = 10
_PARAMS_TESTED = 8  # cap of _COMMON_PARAM_NAMES[:8]


class TimeBasedSQLiCheck(Check):
    meta = CheckMeta(
        id="sqli-time-based",
        name="Time-Based Blind SQL Injection Check",
        category=CheckCategory.SQLI,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects time-based blind SQL injection via bounded SLEEP/pg_sleep/WAITFOR DELAY probes. No data extraction.",
        references=["CWE-89", "OWASP A03:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        # Optional ActionGate: present the time-based probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. Time-based
        # canary probes (SLEEP/pg_sleep/WAITFOR DELAY) are LOW risk
        # (no data extraction, no SELECT/UNION/OR tautology) so this is
        # auto-approved. Only GET requests; no body modification; bounded
        # by max_requests and timeout.
        from redveil.validation.risk import ActionPlan, Risk
        # Worst-case budget under the new control+probe+replay pattern:
        # for each (param, payload) pair we run baseline (3) + control (1)
        # + probe (2) + control (1) + probe (2) = 9 requests. With
        # 8 payloads x 8 params = 64 pairs, the worst case is
        # 64 * _REQUESTS_PER_PAIR = 640 requests. We use 640 as the
        # ActionPlan cap (slight slack over 64*9=576 to account for the
        # WAF/rate-limit early-exit overhead on the first control).
        max_requests = len(_DELAY_PAYLOADS) * _PARAMS_TESTED * _REQUESTS_PER_PAIR
        plan = ActionPlan(
            action_id="sqli-time-based-probe",
            description=(
                "Send time-based blind SQLi probes (SLEEP, pg_sleep, "
                "WAITFOR DELAY) to the base URL parameters and measure "
                "response time. Per-parameter baseline + controlled "
                "timing comparison with reproducibility check "
                "(baseline x 3, control, probe x 2, control, probe x 2). "
                "Bounded by max_requests and timeout. Only GET requests, "
                "no body modification. No data extraction, no "
                "SELECT/UNION/OR tautology."
            ),
            risk=Risk.LOW,
            target=str(self.deps.config.target.base_url).rstrip("/") + "/",
            purpose="Detect time-based blind SQL injection by measuring response time differences.",
            expected_effect="200 OK responses; slow responses (>1s) when SLEEP-equivalent payload is processed.",
            potential_side_effects=(
                "Logged in server access log.",
                "May trigger WAF if present.",
                "Slight increase in response time for the affected request.",
            ),
            max_requests=max_requests,
            timeout_seconds=10.0,
            destructive=False,
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

        # Test a few common parameter names
        params_to_test = _COMMON_PARAM_NAMES[:_PARAMS_TESTED]  # cap to keep scan bounded
        endpoint = join_url(base, "/")

        for param in params_to_test:
            baseline_url = f"{endpoint}?{param}=redveil_baseline"
            control_url = baseline_url  # control is the same legitimate request

            for db_family, payload in _DELAY_PAYLOADS:
                probe_url = f"{endpoint}?{param}={quote(payload, safe='')}"

                # Adapter: URL string -> Response. The helper takes a
                # RequestFn that accepts a URL; the existing HttpClient
                # takes a Request, so we wrap it here.
                async def request_fn(url: str) -> Response:
                    req = Request(
                        method="GET",
                        url=url,
                        purpose="reproducibility-test",
                    )
                    return await self.deps.http.send(req)

                try:
                    result = await run_control_probe_sequence(
                        baseline_url=baseline_url,
                        probe_url=probe_url,
                        control_url=control_url,
                        request_fn=request_fn,
                        n_baseline=REPRODUCTION_SAMPLES,
                        n_probe=REPROBE_SAMPLES,
                        delay_threshold_ms=_DELAY_THRESHOLD_MS,
                        ratio_threshold=_DELAY_RATIO,
                    )
                except Exception:
                    continue

                # Build a representative request/response pair for the
                # candidate so evidence can render a cURL. We use the
                # probe URL + the first probe response if available.
                probe_req = Request(
                    method="GET",
                    url=probe_url,
                    purpose="probe",
                    purpose_extra=f"sqli_{db_family}",
                )
                probe_resp: Response | None = None
                # We don't have direct access to the inner responses; we
                # synthesize a minimal Response object for evidence. The
                # helper exposed the timings and verdict, which is what
                # drives the verdict mapping; the body is not needed for
                # the Evidence shape.
                probe_resp = Response(
                    request_id=probe_req.request_id,
                    status_code=200,
                    headers={},
                    body="",
                    elapsed_ms=result.probe_median_ms or 0.0,
                )

                candidates.append({
                    "endpoint": "/",
                    "parameter": param,
                    "method": "GET",
                    "payload": payload,
                    "db_family": db_family,
                    "reproducibility": result,
                    "verdict": result.verdict,
                    "baseline_median_ms": result.baseline_median_ms,
                    "baseline_cv_pct": result.baseline_cv_pct,
                    "probe_median_ms": result.probe_median_ms,
                    "probe_min_ms": result.probe_min_ms,
                    "probe_max_ms": result.probe_max_ms,
                    "waf_detected": result.waf_detected,
                    "rate_limited": result.rate_limited,
                    "request": probe_req,
                    "response": probe_resp,
                })

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        verdict = candidate.get("verdict", INCONCLUSIVE)
        result = candidate.get("reproducibility")
        baseline_median = candidate.get("baseline_median_ms", 0.0)
        probe_median = candidate.get("probe_median_ms", 0.0)
        ratio = (
            probe_median / baseline_median if baseline_median > 0 else 0.0
        )
        observation = (
            f"baseline={baseline_median:.0f}ms; "
            f"probe_median={probe_median:.0f}ms; "
            f"ratio={ratio:.1f}x; verdict={verdict}"
        )
        if result is not None and result.notes:
            observation = f"{observation} — {result.notes}"

        if verdict == TIMING_REPRODUCIBLE:
            return ValidationResult(
                outcome=ValidationOutcome.CONFIRMED,
                confidence="high",
                observation=observation,
            )
        if verdict == TIMING_FLAKY:
            return ValidationResult(
                outcome=ValidationOutcome.INCONCLUSIVE,
                confidence="low",
                observation=observation,
                evidence=self._evidence_for_candidate(candidate, signal_kind=SignalKind.FLAKY_ENDPOINT),
            )
        if verdict == TIMING_ANOMALY:
            return ValidationResult(
                outcome=ValidationOutcome.INCONCLUSIVE,
                confidence="low",
                observation=observation,
            )
        if verdict == WAF_INTERFERENCE:
            return ValidationResult(
                outcome=ValidationOutcome.INCONCLUSIVE,
                confidence="medium",
                observation=observation,
            )
        if verdict == RATE_LIMITED:
            return ValidationResult(
                outcome=ValidationOutcome.INCONCLUSIVE,
                confidence="low",
                observation=observation,
            )
        return ValidationResult(
            outcome=ValidationOutcome.INCONCLUSIVE,
            confidence="low",
            observation=observation,
        )

    async def collect_evidence(self, candidate) -> list[Evidence]:
        return self._evidence_for_candidate(candidate)

    def _evidence_for_candidate(
        self,
        candidate: dict[str, Any],
        signal_kind: str = SignalKind.TIMING_DELTA,
    ) -> list[Evidence]:
        resp = candidate.get("response")
        req = candidate.get("request")
        if not resp or not req:
            return []
        result = candidate.get("reproducibility")
        baseline_median = candidate.get("baseline_median_ms", 0.0)
        probe_median = candidate.get("probe_median_ms", 0.0)
        ratio = (
            probe_median / baseline_median if baseline_median > 0 else 0.0
        )
        verdict = candidate.get("verdict", INCONCLUSIVE)

        # Populate Wave 14 evidence fields from the ReproducibilityResult.
        # The mapping preserves operator-facing traceability: every
        # environment indicator the check observed surfaces as a
        # concrete field on the Evidence, not just prose in the
        # observation string.
        waf_indicators: list[str] = []
        rate_limit_indicators: list[str] = []
        environment_uncertainty = 0.0
        if result is not None:
            if result.waf_detected:
                waf_indicators.append("probe_response_waf_pattern")
                if resp.status_code in (403, 406, 419, 501):
                    waf_indicators.append(f"status_{resp.status_code}")
                if result.interference_body_length is not None:
                    waf_indicators.append("body_length_change")
                environment_uncertainty = max(environment_uncertainty, 0.7)
            if result.rate_limited:
                rate_limit_indicators.append(f"status_{resp.status_code}")
                if resp.status_code in (429, 503):
                    rate_limit_indicators.append("throttle_status")
                environment_uncertainty = max(environment_uncertainty, 0.8)
            if verdict == TIMING_FLAKY:
                environment_uncertainty = max(environment_uncertainty, 0.6)
            elif verdict == TIMING_ANOMALY:
                environment_uncertainty = max(environment_uncertainty, 0.5)
            elif verdict == TIMING_REPRODUCIBLE:
                environment_uncertainty = max(environment_uncertainty, 0.1)
            else:
                environment_uncertainty = max(environment_uncertainty, 0.3)

        # control_input: the legitimate request URL (baseline URL is the
        # same endpoint without the payload).
        control_input = (
            f"{candidate.get('endpoint', '/')}?{candidate.get('parameter')}="
            "redveil_baseline"
        )

        # control_timing_ms: median of the control samples if collected.
        control_timing_ms = None
        if result is not None and result.control_samples:
            control_timing_ms = statistics.median(result.control_samples)

        # validation_outcome: map verdict → ValidationOutcome.
        if verdict == TIMING_REPRODUCIBLE:
            validation_outcome = ValidationOutcome.CONFIRMED.value
        else:
            validation_outcome = ValidationOutcome.INCONCLUSIVE.value

        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.TIMING_DELTA,
            endpoint=candidate.get("endpoint", "/"),
            method="GET",
            parameter=candidate.get("parameter"),
            input_used=candidate.get("payload", ""),
            status_code=resp.status_code,
            timing_ms=resp.elapsed_ms,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=(
                f"verdict={verdict}; "
                f"baseline={baseline_median:.0f}ms; "
                f"probe={probe_median:.0f}ms; "
                f"ratio={ratio:.1f}x"
            ),
            # Wave 14 evidence fields
            control_input=control_input,
            baseline_timing_ms=baseline_median if baseline_median > 0 else None,
            control_timing_ms=control_timing_ms,
            oracle_signal=signal_kind,
            validation_outcome=validation_outcome,
            confidence="high" if verdict == TIMING_REPRODUCIBLE else "low",
            environment_uncertainty=environment_uncertainty,
            waf_detected=bool(result and result.waf_detected),
            waf_indicators=waf_indicators,
            rate_limited=bool(result and result.rate_limited),
            rate_limit_indicators=rate_limit_indicators,
            test_mode="safe",
            destructive=False,
            destructive_level=None,
        )]

    async def assess(self, candidate) -> Finding | None:
        verdict = candidate.get("verdict", INCONCLUSIVE)
        result = candidate.get("reproducibility")
        baseline_median = candidate.get("baseline_median_ms", 0.0)
        probe_median = candidate.get("probe_median_ms", 0.0)

        # Compute environment uncertainty from the verdict + result so
        # the ConfidenceScorer can downgrade confidence for non-clean
        # signals (WAF / rate-limit / flaky / anomaly). Mirrors the
        # scoring used by _evidence_for_candidate so the Evidence and
        # Finding agree on the same uncertainty number.
        waf_observed = bool(result and result.waf_detected)
        rate_observed = bool(result and result.rate_limited)
        environment_uncertainty = 0.0
        if waf_observed:
            environment_uncertainty = max(environment_uncertainty, 0.7)
        if rate_observed:
            environment_uncertainty = max(environment_uncertainty, 0.8)
        if verdict == TIMING_FLAKY:
            environment_uncertainty = max(environment_uncertainty, 0.6)
        elif verdict == TIMING_ANOMALY:
            environment_uncertainty = max(environment_uncertainty, 0.5)
        elif verdict == TIMING_REPRODUCIBLE:
            environment_uncertainty = max(environment_uncertainty, 0.1)
        else:
            environment_uncertainty = max(environment_uncertainty, 0.3)

        # Build signals for the ConfidenceScorer. The signal kinds map to
        # dimensions: timing-related evidence lives in the "response"
        # dimension, while flakiness / WAF / rate-limit live in "behavior"
        # or "replay" so the multi-signal scorer can treat them as
        # independent dimensions.
        signals: list[Signal] = [
            Signal(
                kind=SignalKind.TIMING_DELTA,
                description=(
                    f"baseline={baseline_median:.0f}ms; "
                    f"probe_median={probe_median:.0f}ms"
                ),
                weight=1.0,
                dimension="response",
            ),
        ]
        if verdict == TIMING_FLAKY:
            signals.append(Signal(
                kind=SignalKind.FLAKY_ENDPOINT,
                description=(
                    f"baseline CV {candidate.get('baseline_cv_pct', 0.0):.1f}%"
                ),
                weight=0.3,
                dimension="replay",
            ))
        elif verdict == WAF_INTERFERENCE:
            signals.append(Signal(
                kind="waf_interference",
                description="probe response indicates WAF block",
                weight=0.5,
                dimension="behavior",
            ))
        elif verdict == RATE_LIMITED:
            signals.append(Signal(
                kind="rate_limited",
                description="target rate-limited the probe",
                weight=0.2,
                dimension="behavior",
            ))

        # Time-based blind SQLi with reproducible delay is a strong
        # behavioral oracle: the application actually executed the
        # injected statement (SLEEP / pg_sleep). Reproducibility across
        # two rounds pushes it to STATE_TRANSITION.
        if verdict == TIMING_REPRODUCIBLE:
            oracle = Oracle.STATE_TRANSITION
        elif verdict == TIMING_ANOMALY:
            oracle = Oracle.STATUS_CODE_ONLY
        else:
            oracle = Oracle.STATUS_CODE_ONLY

        scorer = ConfidenceScorer()
        confidence = scorer.confidence(signals, oracle, uncertainty=environment_uncertainty)

        # Map verdict to FindingStatus. Reproducible timing is the
        # only path to CONFIRMED — every other verdict (WAF,
        # rate-limit, anomaly, flaky baseline, or no detectable
        # delta) surfaces as INCONCLUSIVE so the UI can render the
        # specific verdict reason rather than a misleading
        # CONFIRMED/LIKELY badge.
        if verdict == TIMING_REPRODUCIBLE:
            status = FindingStatus.CONFIRMED
        else:
            status = FindingStatus.INCONCLUSIVE

        entry = get_entry(self.meta.id, "time_based")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Time-based SQL injection detected in '{candidate['parameter']}' parameter ({candidate['db_family']} family)."
            technical = (
                f"Injecting a SLEEP-equivalent payload causes a "
                f"{probe_median:.0f}ms delay (baseline {baseline_median:.0f}ms)."
            )
            impact = "Attacker can extract database content character-by-character via timing differences."
            remediation = ["Use parameterized queries.", "Use an ORM.", "Apply input validation."]
            attack_scenario = None
            code_examples = {}

        # Surface the specific reason for INCONCLUSIVE findings so the UI
        # can render "baseline unstable" / "WAF detected" / "rate-limited"
        # instead of a generic badge. CONFIRMED findings don't need this —
        # the technical text above already covers the reproducible case.
        if verdict != TIMING_REPRODUCIBLE:
            technical = (
                f"{technical}\n\n"
                f"Inconclusive reason: {reason_for_verdict(verdict)}"
            )

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Time-Based Blind SQL Injection via '{candidate['parameter']}' Parameter",
            severity=Severity.HIGH,
            confidence=confidence,
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
            cwe=["CWE-89"],
            owasp=["A03:2021"],
        )
