"""CommandInjectionCheck — detects command injection via time-based observation.

ACTIVE check. Uses ONLY `sleep` payloads (a benign binary that just waits).
NO destructive commands, NO file reads, NO data exfiltration. The proof is
the OBSERVED response delay, not exploitation.

ABSOLUTELY FORBIDDEN payloads (anywhere in this file or its tests):
- rm, cat, ls, wget, curl, nc, ncat, ssh, scp, rsync (any side-effect binary)
- Reading files: /etc/passwd, /etc/shadow, system32, SAM, boot.ini
- Writing files: >, >>, tee, dd of=
- Reverse shells: /dev/tcp, bash -i, python -c '...'
- Disk wiping: dd if=/dev/zero, mkfs, fdisk

Validation pattern: control + probe + replay.
Every (parameter, payload) pair is validated with the
``run_control_probe_sequence`` helper, which performs::
    BASELINE × N → CONTROL → PROBE × N → CONTROL → PROBE × N
The combined verdict is mapped to a ValidationOutcome and a
confidence level, and the signals feed the ConfidenceScorer in
``assess()``.
"""
from __future__ import annotations

import statistics
from typing import Any
from urllib.parse import quote, urlparse

from redveil.config import SafetyProfile
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.findings.confidence import Confidence
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
    ReproducibilityResult,
    TIMING_ANOMALY,
    TIMING_FLAKY,
    TIMING_REPRODUCIBLE,
    WAF_INTERFERENCE,
    reason_for_verdict,
    run_control_probe_sequence,
)
from redveil.validation.oracle import Oracle, Signal

# ONLY safe sleep-based payloads. NO destructive commands.
# Each payload is just a sleep call with a separator, capped at 3 seconds.
_DELAY_PAYLOADS = [
    "; sleep 3",
    "| sleep 3",
    "& sleep 3",
    "&& sleep 3",
    "|| sleep 3",
    "`sleep 3`",
    "$(sleep 3)",
]

# Safety assertion — fail loudly if anyone tries to add a destructive payload
_FORBIDDEN_SUBSTRINGS = (
    "rm ", "rm\t", "cat ", "wget", "curl ", "nc ", "ncat",
    "/etc/passwd", "/etc/shadow", "system32", "SAM",
    "> /", ">>", "tee ", "dd if=", "mkfs", "fdisk",
    "/dev/tcp", "bash -i", "python -c", "perl -e", "ruby -e",
    "chmod 777", "chmod -R", "chown",
    "uname -a",  # not destructive but exposes system info
)
for _payload in _DELAY_PAYLOADS:
    for _bad in _FORBIDDEN_SUBSTRINGS:
        if _bad in _payload:
            raise RuntimeError(f"FORBIDDEN payload fragment {_bad!r} in {_payload!r}")

_COMMON_PARAM_NAMES = [
    "q", "s", "search", "query", "id", "name", "input", "host", "ip",
    "target", "addr", "address", "domain", "file", "path", "url",
]

# Control+probe+replay sampling budgets.
# Per (param, payload) pair: 3 baseline + 1 control + 2 probe + 1 control
# + 2 probe = 9 requests (two rounds, early-exit on WAF / rate-limit).
_N_BASELINE = 3
_N_PROBE = 2
# Worst case: 7 payloads × 17 params × 10 (per-pair upper bound) = 1190.
# The helper exits early on WAF/rate-limit and the outer loop breaks
# after a reproducible per-param match, so the realistic count is far
# lower, but the plan declares the full worst case.
_MAX_REQUESTS = 1190

# Per-payload separator extraction (preserved from the pre-control/probe
# implementation). Pure string detection on the payload — no destructive
# parsing, no execution.
_SEPARATOR_MAP: tuple[tuple[str, str], ...] = (
    ("`", "backtick"),
    ("$(", "$()"),
    ("&&", "&&"),
    ("||", "||"),
    (";", ";"),
    ("|", "|"),
    ("&", "&"),
)


def _detect_separator(payload: str) -> str:
    """Return the canonical name of the shell separator in ``payload``.

    Mirrors the pre-control/probe logic — pure substring match in a
    fixed order, so each payload maps to exactly one separator.
    """
    for marker, name in _SEPARATOR_MAP:
        if marker in payload:
            return name
    return "unknown"


def _outcome_for_verdict(verdict: str) -> tuple[ValidationOutcome, str]:
    """Map a ``ReproducibilityResult.verdict`` to a ``ValidationOutcome``
    + confidence string.

    - TIMING_REPRODUCIBLE -> CONFIRMED + high
    - WAF_INTERFERENCE   -> INCONCLUSIVE + medium (WAF block is evidence
      of a security boundary, not proof of a vulnerability)
    - RATE_LIMITED       -> INCONCLUSIVE + medium
    - TIMING_FLAKY       -> INCONCLUSIVE + low
    - TIMING_ANOMALY     -> INCONCLUSIVE + low
    - INCONCLUSIVE       -> INCONCLUSIVE + low
    """
    if verdict == TIMING_REPRODUCIBLE:
        return ValidationOutcome.CONFIRMED, "high"
    if verdict == WAF_INTERFERENCE:
        return ValidationOutcome.INCONCLUSIVE, "medium"
    if verdict == RATE_LIMITED:
        return ValidationOutcome.INCONCLUSIVE, "medium"
    if verdict == TIMING_FLAKY:
        return ValidationOutcome.INCONCLUSIVE, "low"
    if verdict == TIMING_ANOMALY:
        return ValidationOutcome.INCONCLUSIVE, "low"
    return ValidationOutcome.INCONCLUSIVE, "low"


def _build_signals(result: ReproducibilityResult) -> list[Signal]:
    """Build Signal objects from a ``ReproducibilityResult``.

    Each signal records one observable dimension of evidence. The
    ConfidenceScorer de-duplicates within a dimension so multiple
    signals on the same dimension don't inflate confidence.
    """
    signals: list[Signal] = []
    verdict = result.verdict
    if verdict == TIMING_REPRODUCIBLE:
        signals.append(Signal(
            kind="timing_delta",
            description=(
                f"probe median {result.probe_median_ms:.0f}ms vs "
                f"baseline {result.baseline_median_ms:.0f}ms "
                f"(cv {result.baseline_cv_pct:.1f}%)"
            ),
            weight=0.7,
            dimension="response",
        ))
    if result.waf_detected or verdict == WAF_INTERFERENCE:
        signals.append(Signal(
            kind="waf_challenge_page",
            description="WAF returned a 403/406/419/501 challenge or block page",
            weight=0.9,
            dimension="response",
        ))
    if result.rate_limited or verdict == RATE_LIMITED:
        signals.append(Signal(
            kind="rate_limit_hit",
            description="rate-limited (429/503 or Retry-After header)",
            weight=0.9,
            dimension="response",
        ))
    return signals


class CommandInjectionCheck(Check):
    meta = CheckMeta(
        id="command-injection",
        name="Command Injection Check (Time-Based)",
        category=CheckCategory.COMMAND_INJECTION,
        safety_profile=SafetyProfile.ACTIVE,
        description="Detects command injection via time-based observation using only `sleep` payloads. No destructive commands.",
        references=["CWE-78", "OWASP A03:2021"],
    )

    async def discover(self, ctx) -> list[dict[str, Any]]:
        if not self.deps:
            return []
        if not self.deps.config.authorization.active_testing:
            return []
        if not self.deps.config.authorization.acknowledged_safety_terms:
            return []

        # Optional ActionGate: present the sleep-probe plan to the user.
        # The gate only blocks MEDIUM+ in interactive mode. Sleep probes are
        # LOW risk (only `sleep N` payloads, no destructive commands), so this
        # is auto-approved. Per-parameter baseline + controlled comparison.
        # Only GET requests, no body modification. Capped at sleep 3-5s max.
        # No shell metacharacters that do anything besides delay.
        from redveil.validation.risk import ActionPlan, Risk
        plan = ActionPlan(
            action_id="cmdi-time-based-probe",
            description=(
                "Send time-based command-injection probes (only `sleep N` payloads, "
                "capped at sleep 3-5 seconds) to base URL parameters and measure "
                "response time. Per-parameter baseline + controlled comparison. "
                "Only GET requests, no body modification. No shell metacharacters "
                "that do anything besides delay. No destructive commands — only "
                "the sleep binary."
            ),
            risk=Risk.LOW,
            target=str(self.deps.config.target.base_url).rstrip("/") + "/",
            purpose="Detect command injection by measuring response time after sleep payloads.",
            expected_effect=(
                "200 OK responses; delayed (>1s) responses when sleep-equivalent "
                "payload is interpreted by a shell."
            ),
            potential_side_effects=(
                "Logged in server access log.",
                "May trigger WAF if present.",
                "Slight increase in response time for affected requests.",
            ),
            # Worst-case request budget for the control+probe+replay
            # pattern: 7 payloads × 17 params × 10 (per-pair upper
            # bound) = 1190. The helper exits early on WAF/rate-limit
            # and the outer loop breaks after a reproducible per-param
            # match, so the realistic count is far lower.
            max_requests=_MAX_REQUESTS,
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
                return []

        base = str(self.deps.config.target.base_url).rstrip("/")
        candidates: list[dict[str, Any]] = []
        endpoint = join_url(base, "/")

        # Per (param, payload) pair, run the control+probe+replay sequence.
        # Early-break after the first reproducible per-param match — one
        # confirmed CMDi per parameter is enough evidence.
        for param in _COMMON_PARAM_NAMES:
            for payload in _DELAY_PAYLOADS:
                baseline_url = endpoint
                probe_url = f"{endpoint}?{param}={quote(payload, safe='')}"
                control_url = f"{endpoint}?{param}=redveil_baseline"

                # The helper's RequestFn is a closure that captures
                # the URLs and tracks the last probe response so we
                # can attach it to the candidate for evidence.
                last_probe_response: list[Response] = []

                async def request_fn(url: str, _purl: str = probe_url) -> Response:
                    req = Request(
                        method="GET",
                        url=url,
                        purpose="probe",
                        purpose_extra="cmdi_sleep",
                    )
                    resp = await self.deps.http.send(req)
                    if url == _purl:
                        last_probe_response.append(resp)
                    return resp

                try:
                    result: ReproducibilityResult = await run_control_probe_sequence(
                        baseline_url=baseline_url,
                        probe_url=probe_url,
                        control_url=control_url,
                        request_fn=request_fn,
                        n_baseline=_N_BASELINE,
                        n_probe=_N_PROBE,
                    )
                except Exception:
                    continue

                # Decide whether this (param, payload) result is
                # meaningful enough to attach a candidate to.
                # - TIMING_FLAKY: baseline unstable for this endpoint;
                #   abandon the whole param (other payloads will see the
                #   same noise).
                # - INCONCLUSIVE with no probe samples: control drift or
                #   network failure; abandon the whole param.
                # - INCONCLUSIVE with probe samples but no delay: no
                #   timing signal at all; skip without adding a candidate
                #   (try the next payload).
                # - TIMING_REPRODUCIBLE / WAF_INTERFERENCE /
                #   RATE_LIMITED: add a candidate, break to the next
                #   parameter (one confirmed-or-blocked finding per
                #   parameter is enough evidence).
                # - TIMING_ANOMALY: add a candidate (anomalies are
                #   evidence) but keep trying payloads in case a
                #   different separator produces a reproducible delay.
                if result.verdict == TIMING_FLAKY:
                    break
                if result.verdict == INCONCLUSIVE and not result.probe_samples:
                    break
                if result.verdict == INCONCLUSIVE:
                    # Probe ran but no meaningful timing delta. Skip.
                    continue

                # Build a synthetic request for the evidence record.
                # The response (if captured) is the real last-probe
                # response, which carries the observed status/body.
                evidence_req = Request(
                    method="GET",
                    url=probe_url,
                    purpose="probe",
                    purpose_extra="cmdi_sleep",
                )

                # Probe median (or 0 if no probes collected) drives
                # the candidate's delay_ms/ratio for the legacy shape.
                probe_median = (
                    statistics.median(result.probe_samples)
                    if result.probe_samples
                    else 0.0
                )
                ratio = probe_median / max(result.baseline_median_ms, 1.0)

                last_resp = last_probe_response[-1] if last_probe_response else None

                candidates.append({
                    "endpoint": "/",
                    "parameter": param,
                    "method": "GET",
                    "payload": payload,
                    "separator": _detect_separator(payload),
                    "baseline_ms": result.baseline_median_ms,
                    "delay_ms": probe_median,
                    "ratio": ratio,
                    "request": evidence_req,
                    "response": last_resp,
                    "reproducibility": result,
                    "verdict": result.verdict,
                })

                # Early-break after a reproducible finding per param:
                # one confirmed CMDi per parameter is enough evidence.
                # WAF and rate-limit verdicts also short-circuit — if
                # the WAF blocks the first probe, further payloads are
                # unlikely to produce different signal.
                if result.verdict in (
                    TIMING_REPRODUCIBLE,
                    WAF_INTERFERENCE,
                    RATE_LIMITED,
                ):
                    break

        return candidates

    async def validate(self, ctx, candidate) -> ValidationResult:
        # The verdict is set by discover() from the
        # ``run_control_probe_sequence`` result. Map it to a
        # ValidationOutcome + confidence string.
        result: ReproducibilityResult | None = candidate.get("reproducibility")
        if result is None:
            # Backwards-compatibility: legacy candidates (from
            # earlier scans or fixtures) only carry baseline/delay/ratio.
            ratio = candidate.get("ratio", 0)
            delay = candidate.get("delay_ms", 0)
            baseline = candidate.get("baseline_ms", 0)
            if ratio >= 3 and delay >= 2000:
                return ValidationResult(
                    outcome=ValidationOutcome.CONFIRMED,
                    confidence="high",
                    observation=(
                        f"baseline={baseline:.0f}ms; delay={delay:.0f}ms; "
                        f"ratio={ratio:.1f}x — strong indicator"
                    ),
                )
            if ratio >= 2 and delay >= 1500:
                return ValidationResult(
                    outcome=ValidationOutcome.LIKELY,
                    confidence="medium",
                    observation=(
                        f"baseline={baseline:.0f}ms; delay={delay:.0f}ms; "
                        f"ratio={ratio:.1f}x"
                    ),
                )
            return ValidationResult(
                outcome=ValidationOutcome.FALSE_POSITIVE,
                confidence="low",
                observation="delay below threshold",
            )

        outcome, confidence = _outcome_for_verdict(result.verdict)
        probe_median = (
            statistics.median(result.probe_samples)
            if result.probe_samples
            else 0.0
        )
        observation = (
            f"verdict={result.verdict}; "
            f"baseline={result.baseline_median_ms:.0f}ms; "
            f"probe_median={probe_median:.0f}ms; "
            f"cv={result.baseline_cv_pct:.1f}%; "
            f"{result.notes}"
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
        return [Evidence(
            request=req,
            response=resp,
            kind=ObservationKind.TIMING_DELTA,
            endpoint="/",
            method="GET",
            parameter=candidate.get("parameter"),
            input_used=candidate.get("payload", ""),
            status_code=resp.status_code,
            timing_ms=resp.elapsed_ms,
            relevant_headers={"content-type": resp.headers.get("content-type", "")},
            body_excerpt=resp.body_excerpt,
            observation=(
                f"time-based cmdi via '{candidate['separator']}' separator; "
                f"baseline={candidate['baseline_ms']:.0f}ms; "
                f"delay={candidate['delay_ms']:.0f}ms"
            ),
        )]

    async def assess(self, candidate) -> Finding | None:
        entry = get_entry(self.meta.id, "time_based")
        if entry:
            summary = entry["summary"]
            technical = entry["technical"]
            impact = entry["impact"]
            remediation = list(entry["remediation"])
            attack_scenario = entry["attack_scenario"]
            code_examples = dict(entry["code_examples"])
        else:
            summary = f"Time-based command injection detected in '{candidate['parameter']}' parameter."
            technical = f"Injecting a shell command separator caused the response to delay by {candidate['delay_ms']:.0f}ms."
            impact = "Attacker can execute arbitrary commands on the server."
            remediation = ["Avoid invoking shell commands with user input.", "Use parameterized APIs."]
            attack_scenario = None
            code_examples = {}

        # ConfidenceScorer replaces the hard-coded Confidence.HIGH.
        # We use Oracle.STATE_TRANSITION because a reproducible
        # time-based CMDi demonstrates a state change (the server
        # spent real time waiting for the sleep), and we feed the
        # scorer the signals derived from the ReproducibilityResult.
        result: ReproducibilityResult | None = candidate.get("reproducibility")
        verdict = candidate.get("verdict", INCONCLUSIVE)
        if result is not None:
            signals = _build_signals(result)
            scorer = ConfidenceScorer(environmental_penalty=0.0)
            confidence = scorer.confidence(signals, Oracle.STATE_TRANSITION)
        else:
            # Legacy candidate path: keep the historical HIGH confidence.
            confidence = Confidence.HIGH

        # Status mirrors validate()'s verdict mapping: only a reproducible
        # timing pattern is CONFIRMED. WAF / rate-limit / flaky / anomaly /
        # generic-INCONCLUSIVE verdicts produce INCONCLUSIVE findings so the
        # UI can render the specific cause rather than a false-positive
        # CONFIRMED badge.
        if verdict == TIMING_REPRODUCIBLE:
            status = FindingStatus.CONFIRMED
        else:
            status = FindingStatus.INCONCLUSIVE
            technical = (
                f"{technical}\n\n"
                f"Inconclusive reason: {reason_for_verdict(verdict)}"
            )

        base = str(self.deps.config.target.base_url)
        parsed = urlparse(base)
        return Finding(
            check=CheckRef(id=self.meta.id, name=self.meta.name, category=self.meta.category.value, version=self.meta.version),
            title=f"Command Injection via '{candidate['parameter']}' Parameter (Time-Based)",
            severity=Severity.CRITICAL,
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
            cwe=["CWE-78"],
            owasp=["A03:2021"],
        )
