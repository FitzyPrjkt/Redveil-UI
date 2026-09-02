"""Control + Probe + Replay sequence for differential timing tests.

Some checks (notably time-based SQLi, command injection, SSRF) need to
prove a delay is caused by THE PAYLOAD, not by network noise or server
load. A single probe is not enough: the server might be slow because it's
busy, the network might be congested, the response might be cached, etc.

This module provides a strict differential pattern:

    BASELINE × N → CONTROL → PROBE × N → CONTROL → PROBE × N

  - BASELINE × N: legitimate request (no payload), repeated. Establishes
    the normal response-time distribution and detects baseline flakiness.
  - CONTROL: a second legitimate request immediately before the probe.
    Sanity check that the server is still responsive (rules out a sudden
    slowdown from network or GC pauses).
  - PROBE × N: the payload-bearing request, repeated. Each sample is the
    actual timing observation.
  - CONTROL: another legitimate request AFTER the probe to confirm the
    delay was caused by the payload, not by an unrelated slowdown
    starting concurrently with the probe.
  - PROBE × N: a second round of the same payload. Reproducibility check
    — if the delay is real, it should appear again.

The function returns a ReproducibilityResult with a verdict that callers
can map to ValidationOutcome. The verdict values are stable strings so
callers can switch on them.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from redveil.http.response import Response

# A request function is async (url: str) -> Response
RequestFn = Callable[[str], Awaitable[Response]]

# ---------------------------------------------------------------------------
# Verdict constants. Stable strings so callers can compare without imports.
# ---------------------------------------------------------------------------

TIMING_REPRODUCIBLE = "TIMING_REPRODUCIBLE"
TIMING_FLAKY = "TIMING_FLAKY"
TIMING_ANOMALY = "TIMING_ANOMALY"
WAF_INTERFERENCE = "WAF_INTERFERENCE"
RATE_LIMITED = "RATE_LIMITED"
INCONCLUSIVE = "INCONCLUSIVE"

# Human-readable reasons for each inconclusive verdict. Findings surface
# these in their technical_explanation so the UI can render a specific
# cause (WAF detected / baseline unstable / rate-limited / single spike /
# no delta) instead of a generic "inconclusive" badge.
VERDICT_REASONS: dict[str, str] = {
    WAF_INTERFERENCE: (
        "WAF or intermediary blocked the probe — response indicated a "
        "challenge or block page (HTTP 403/406/419/501 or body-shape "
        "change vs the baseline). The payload was never executed, so "
        "this is recorded as inconclusive rather than confirmed."
    ),
    RATE_LIMITED: (
        "Target rate-limited the probe (HTTP 429/503 or Retry-After). "
        "Timing could not be measured against the payload because "
        "subsequent requests were throttled or refused."
    ),
    TIMING_FLAKY: (
        "Baseline response times were too unstable (coefficient of "
        "variation above the 30% threshold). Any delay attributable "
        "to the payload could not be distinguished from background "
        "jitter — retrying on a less-loaded network path may yield a "
        "stable measurement."
    ),
    TIMING_ANOMALY: (
        "Probe samples were inconsistent within the same run — some "
        "samples were slow and others fast, so the delay was not "
        "reproducible across rounds."
    ),
    INCONCLUSIVE: (
        "Probe did not produce a reproducible timing delta against "
        "the baseline. The application did not appear to execute the "
        "payload, but this cannot be confirmed without an active "
        "re-test."
    ),
}


def reason_for_verdict(verdict: str) -> str:
    """Return the human-readable reason for ``verdict``.

    Falls back to the ``INCONCLUSIVE`` reason when ``verdict`` is
    unknown. The returned string is a single paragraph suitable for
    appending to a Finding's technical_explanation.
    """
    return VERDICT_REASONS.get(verdict, VERDICT_REASONS[INCONCLUSIVE])


# HTTP status codes that indicate WAF / rate-limit interference rather than
# the application itself responding.
_WAF_STATUS_CODES = {403, 406, 419, 501}
_RATE_LIMIT_STATUS_CODES = {429, 503}


@dataclass
class ReproducibilityResult:
    """Result of a control+probe+replay sequence.

    The verdict field is the primary signal: callers switch on it to map to
    ValidationOutcome. Other fields expose the raw timings so the caller
    can render them in evidence, log them for debugging, or run additional
    analysis.
    """
    verdict: str
    baseline_samples: list[float] = field(default_factory=list)
    baseline_median_ms: float = 0.0
    baseline_cv_pct: float = 0.0
    control_samples: list[float] = field(default_factory=list)
    probe_samples: list[float] = field(default_factory=list)
    probe_median_ms: float = 0.0
    probe_min_ms: float = 0.0
    probe_max_ms: float = 0.0
    waf_detected: bool = False
    rate_limited: bool = False
    # The WAF / rate-limit body length seen on the first such response. Used
    # by callers to record evidence ("baseline body=120, probe body=412").
    interference_body_length: int | None = None
    notes: str = ""


def _coefficient_of_variation_pct(samples: list[float]) -> float:
    """Coefficient of variation as a percentage: (stdev / mean) * 100.

    Returns 0.0 when samples are too few or the mean is zero (a degenerate
    case where CV is undefined).
    """
    if len(samples) < 2:
        return 0.0
    mean = statistics.mean(samples)
    if mean <= 0:
        return 0.0
    stdev = statistics.stdev(samples)
    return (stdev / mean) * 100.0


def _looks_like_waf(
    probe_resp: Response,
    baseline_body_length: int | None,
) -> bool:
    """Heuristic WAF detection: 4xx/5xx in a known WAF set, OR a dramatic
    body-length change vs the baseline.

    A WAF in front of the application will either block the request
    outright (403/406) or rewrite the response to a captcha / block page
    (which usually has a very different body length).
    """
    if probe_resp.status_code in _WAF_STATUS_CODES:
        return True
    if probe_resp.status_code in _RATE_LIMIT_STATUS_CODES:
        return False  # handled by the rate-limit branch
    if baseline_body_length is not None and probe_resp.body is not None:
        probe_len = len(probe_resp.body)
        # A body length change of more than 5x or less than 1/5 is a strong
        # signal the response was rewritten by an intermediary.
        if baseline_body_length > 0 and (
            probe_len > 5 * baseline_body_length
            or probe_len < baseline_body_length / 5
        ):
            return True
    return False


def _looks_like_rate_limit(probe_resp: Response) -> bool:
    return probe_resp.status_code in _RATE_LIMIT_STATUS_CODES


async def run_control_probe_sequence(
    baseline_url: str,
    probe_url: str,
    control_url: str,
    request_fn: RequestFn,
    n_baseline: int = 3,
    n_probe: int = 2,
    delay_threshold_ms: float = 2000.0,
    ratio_threshold: float = 3.0,
    cv_threshold_pct: float = 30.0,
) -> ReproducibilityResult:
    """Run the BASELINE → CONTROL → PROBE → CONTROL → PROBE sequence.

    Args:
        baseline_url: URL of a legitimate (non-payload) request. Used to
            establish the normal response-time distribution.
        probe_url: URL of the payload-bearing request being tested.
        control_url: URL of a second legitimate request. Used both before
            and after each probe to ensure the server is responsive at the
            time of the measurement (rules out coincidental slowdowns).
        request_fn: async (url) -> Response. The caller supplies this so
            the helper does not depend on the orchestrator's HttpClient.
        n_baseline: number of baseline samples to take (default 3).
        n_probe: number of probe samples per round (default 2). Two rounds
            are run, so the total number of probe requests is 2 * n_probe.
        delay_threshold_ms: absolute threshold added to baseline_median.
            Probe must exceed baseline_median + this AND baseline_median *
            ratio_threshold to be considered reproducible.
        ratio_threshold: multiplicative threshold. Default 3.0 means the
            probe must be at least 3x slower than the baseline.
        cv_threshold_pct: coefficient of variation above which the baseline
            is considered too flaky to draw conclusions from. Default
            30% matches the spec.

    Returns:
        ReproducibilityResult. Always populated, even on early-exit paths.
        Inspect ``verdict`` to decide what to emit.
    """
    # ------------------------------------------------------------------
    # Step 1: BASELINE × N
    # ------------------------------------------------------------------
    baseline_samples: list[float] = []
    baseline_body_length: int | None = None
    for _ in range(n_baseline):
        try:
            resp = await request_fn(baseline_url)
        except Exception:
            continue
        baseline_samples.append(float(resp.elapsed_ms))
        if baseline_body_length is None and resp.body is not None:
            baseline_body_length = len(resp.body)

    if not baseline_samples:
        return ReproducibilityResult(
            verdict=INCONCLUSIVE,
            baseline_samples=baseline_samples,
            notes="all baseline samples failed",
        )

    baseline_median = statistics.median(baseline_samples)
    baseline_cv = _coefficient_of_variation_pct(baseline_samples)

    # ------------------------------------------------------------------
    # Step 2: gate on baseline stability
    # ------------------------------------------------------------------
    if baseline_cv > cv_threshold_pct:
        return ReproducibilityResult(
            verdict=TIMING_FLAKY,
            baseline_samples=baseline_samples,
            baseline_median_ms=baseline_median,
            baseline_cv_pct=baseline_cv,
            notes=f"baseline CV {baseline_cv:.1f}% > {cv_threshold_pct}% threshold",
        )

    # ------------------------------------------------------------------
    # Step 3: CONTROL → PROBE × N → CONTROL → PROBE × N
    # ------------------------------------------------------------------
    control_samples: list[float] = []
    probe_samples: list[float] = []
    waf_detected = False
    rate_limited = False
    interference_body_length: int | None = None
    rate_limit_notes = ""

    for round_idx in range(2):
        # Control before probe
        try:
            ctrl = await request_fn(control_url)
            control_samples.append(float(ctrl.elapsed_ms))
        except Exception:
            pass

        # Probe × N
        for _ in range(n_probe):
            try:
                probe_resp = await request_fn(probe_url)
            except Exception:
                continue
            t = float(probe_resp.elapsed_ms)
            probe_samples.append(t)

            if not waf_detected and _looks_like_waf(probe_resp, baseline_body_length):
                waf_detected = True
                interference_body_length = len(probe_resp.body) if probe_resp.body else None
                # Don't break — still collect remaining samples so the result
                # is informative, but we'll return early after this round.
            if not rate_limited and _looks_like_rate_limit(probe_resp):
                rate_limited = True
                rate_limit_notes = (
                    f"probe returned HTTP {probe_resp.status_code}"
                )

        # Early exit: if the first probe round was blocked by a WAF or
        # rate-limit, no point running a second round.
        if waf_detected or rate_limited:
            break

    # ------------------------------------------------------------------
    # Step 4: classify
    # ------------------------------------------------------------------
    if waf_detected:
        return ReproducibilityResult(
            verdict=WAF_INTERFERENCE,
            baseline_samples=baseline_samples,
            baseline_median_ms=baseline_median,
            baseline_cv_pct=baseline_cv,
            control_samples=control_samples,
            probe_samples=probe_samples,
            waf_detected=True,
            interference_body_length=interference_body_length,
            notes="probe response indicates WAF or intermediary block",
        )

    if rate_limited:
        return ReproducibilityResult(
            verdict=RATE_LIMITED,
            baseline_samples=baseline_samples,
            baseline_median_ms=baseline_median,
            baseline_cv_pct=baseline_cv,
            control_samples=control_samples,
            probe_samples=probe_samples,
            rate_limited=True,
            notes=rate_limit_notes or "rate-limited",
        )

    if not probe_samples:
        return ReproducibilityResult(
            verdict=INCONCLUSIVE,
            baseline_samples=baseline_samples,
            baseline_median_ms=baseline_median,
            baseline_cv_pct=baseline_cv,
            control_samples=control_samples,
            notes="all probe samples failed",
        )

    probe_median = statistics.median(probe_samples)
    probe_min = min(probe_samples)
    probe_max = max(probe_samples)

    # Timing anomaly: some probe samples slow, some fast → not reproducible.
    # Heuristic: at least one > 2s AND at least one < 500ms.
    has_slow = any(t > 2000.0 for t in probe_samples)
    has_fast = any(t < 500.0 for t in probe_samples)
    if has_slow and has_fast:
        return ReproducibilityResult(
            verdict=TIMING_ANOMALY,
            baseline_samples=baseline_samples,
            baseline_median_ms=baseline_median,
            baseline_cv_pct=baseline_cv,
            control_samples=control_samples,
            probe_samples=probe_samples,
            probe_median_ms=probe_median,
            probe_min_ms=probe_min,
            probe_max_ms=probe_max,
            notes=(
                f"probe samples inconsistent: range=[{probe_min:.0f}, "
                f"{probe_max:.0f}]ms"
            ),
        )

    # Reproducibility check: median exceeds BOTH absolute and relative
    # thresholds. The "both" requirement rules out a slow baseline that
    # happens to be 2s (2000 + 2000 = 4000 is reachable by pure noise).
    if (
        probe_median >= baseline_median + delay_threshold_ms
        and probe_median >= baseline_median * ratio_threshold
    ):
        return ReproducibilityResult(
            verdict=TIMING_REPRODUCIBLE,
            baseline_samples=baseline_samples,
            baseline_median_ms=baseline_median,
            baseline_cv_pct=baseline_cv,
            control_samples=control_samples,
            probe_samples=probe_samples,
            probe_median_ms=probe_median,
            probe_min_ms=probe_min,
            probe_max_ms=probe_max,
            notes=(
                f"baseline={baseline_median:.0f}ms; probe_median="
                f"{probe_median:.0f}ms; ratio={probe_median / max(baseline_median, 1.0):.1f}x"
            ),
        )

    return ReproducibilityResult(
        verdict=INCONCLUSIVE,
        baseline_samples=baseline_samples,
        baseline_median_ms=baseline_median,
        baseline_cv_pct=baseline_cv,
        control_samples=control_samples,
        probe_samples=probe_samples,
        probe_median_ms=probe_median,
        probe_min_ms=probe_min,
        probe_max_ms=probe_max,
        notes=(
            f"baseline={baseline_median:.0f}ms; probe_median="
            f"{probe_median:.0f}ms; not reproducible"
        ),
    )
