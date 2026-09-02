"""Adaptive staged validation pipeline (Wave 14 spec deliverable).

Spec invariant:

    Discovery
       ↓
    Cheap anomaly detection
       ↓
    Potential signal
       ↓
    Targeted validation
       ↓
    Reproducibility check
       ↓
    CONFIRMED / LIKELY / INCONCLUSIVE / FALSE_POSITIVE

"Do not perform expensive validation against every parameter unless
necessary. Do not perform destructive validation automatically just
because a cheap probe produced an anomaly."

This module provides the framework that any check can adopt without
duplicating the staging logic:

- ``AnomalySignal`` — a small, structured data class a check emits
  from a CHEAP probe (one request, one response diff, one observed
  pattern). No CONTROL×PROBE×REPLAY yet, no expensive oracle call.

- ``StagedValidator`` — accepts a list of ``AnomalySignal``s and a
  per-check ``AnomalyHeuristic`` (or a default), then decides which
  signals to escalate to targeted validation, which to drop as
  noise, and which to mark as inconclusive.

- ``staged()`` decorator — wraps a check's ``discover()`` so each
  candidate is automatically annotated with an ``anomaly_score`` and
  ``escalation`` decision. The check can then short-circuit
  expensive validation when escalation == ``DROP``.

The framework is intentionally small (no async, no I/O) so it can
be unit-tested without HTTP. The actual probes and oracle calls
remain the check's responsibility.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable


class AnomalyKind(str, Enum):
    """Categories of cheap anomaly observations.

    Each kind maps to a simple heuristic the check can compute from
    one or two requests, without running the full oracle.
    """
    REFLECTION = "reflection"             # canary appears in response body
    STATUS_CHANGE = "status_change"       # probe status != baseline status
    LENGTH_DELTA = "length_delta"         # probe body length differs from baseline
    TIMING_PROMISE = "timing_promise"     # probe slower than baseline (not yet reproducible)
    OOB_INDICATOR = "oob_indicator"       # OOB URL appears in response
    COOKIE_PERSISTENCE = "cookie_persistence"  # session cookie still valid after logout
    STATE_TRANSITION = "state_transition"  # observed expected state change


class Escalation(str, Enum):
    """How the framework tells the check to act on a signal."""
    ESCALATE = "escalate"   # worth running expensive validation
    DEFER = "defer"         # borderline — run validation only if cheap
    DROP = "drop"           # noise / environmental artifact


@dataclass
class AnomalySignal:
    """A cheap observation from one probe of a candidate.

    The check fills these in ``discover()``. The framework uses them
    to decide whether ``validate()`` should run.
    """
    candidate: Any
    kind: AnomalyKind
    score: float = 0.0  # 0.0..1.0, higher = more suspicious
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class EscalationDecision:
    """Outcome of the cheap-anomaly classifier."""
    escalation: Escalation
    score: float
    reason: str


# Default heuristic: each anomaly kind gets a base score; specific
# signals bump it. The check can override by passing a custom
# ``classify`` callable to ``StagedValidator``.
_KIND_BASE_SCORE: dict[AnomalyKind, float] = {
    AnomalyKind.REFLECTION: 0.5,
    AnomalyKind.STATUS_CHANGE: 0.6,
    AnomalyKind.LENGTH_DELTA: 0.2,
    AnomalyKind.TIMING_PROMISE: 0.4,
    AnomalyKind.OOB_INDICATOR: 0.7,
    AnomalyKind.COOKIE_PERSISTENCE: 0.8,
    AnomalyKind.STATE_TRANSITION: 0.7,
}


# Default decision thresholds (above → ESCALATE, below → DROP).
DEFAULT_ESCALATE_THRESHOLD = 0.5
DEFAULT_DROP_THRESHOLD = 0.15


def default_classify(
    signal: AnomalySignal,
    *,
    escalate_threshold: float = DEFAULT_ESCALATE_THRESHOLD,
    drop_threshold: float = DEFAULT_DROP_THRESHOLD,
) -> EscalationDecision:
    """Default classifier: pure score-based decision.

    - score >= escalate_threshold → ESCALATE
    - score <= drop_threshold      → DROP
    - else                         → DEFER
    """
    base = _KIND_BASE_SCORE.get(signal.kind, 0.3)
    score = min(1.0, max(0.0, base + signal.score))
    if score >= escalate_threshold:
        return EscalationDecision(
            escalation=Escalation.ESCALATE,
            score=score,
            reason=f"score {score:.2f} >= {escalate_threshold} for {signal.kind.value}",
        )
    if score <= drop_threshold:
        return EscalationDecision(
            escalation=Escalation.DROP,
            score=score,
            reason=f"score {score:.2f} <= {drop_threshold} for {signal.kind.value} (likely noise)",
        )
    return EscalationDecision(
        escalation=Escalation.DEFER,
        score=score,
        reason=f"score {score:.2f} is borderline for {signal.kind.value}",
    )


class StagedValidator:
    """Decide which candidates deserve expensive validation.

    Usage from a check:

        class MyCheck(Check):
            def __init__(self):
                super().__init__()
                self._staged = StagedValidator(classify=my_classify)

            async def discover(self, ctx):
                signals = []
                for candidate in raw_probes():
                    signals.append(AnomalySignal(
                        candidate=candidate,
                        kind=AnomalyKind.REFLECTION,
                        score=0.0,
                        reason="canary echoed in body",
                    ))
                decisions = self._staged.classify_all(signals)
                return [
                    s.candidate
                    for s, d in zip(signals, decisions)
                    if d.escalation != Escalation.DROP
                ]
    """
    def __init__(
        self,
        *,
        classify: Callable[[AnomalySignal], EscalationDecision] | None = None,
        escalate_threshold: float = DEFAULT_ESCALATE_THRESHOLD,
        drop_threshold: float = DEFAULT_DROP_THRESHOLD,
    ):
        self._classify = classify or default_classify
        self._escalate_threshold = escalate_threshold
        self._drop_threshold = drop_threshold

    def classify(self, signal: AnomalySignal) -> EscalationDecision:
        return self._classify(
            signal,
            escalate_threshold=self._escalate_threshold,
            drop_threshold=self._drop_threshold,
        )

    def classify_all(
        self, signals: Iterable[AnomalySignal]
    ) -> list[EscalationDecision]:
        return [self._classify(s) for s in signals]

    def filter_escalate(
        self, signals_and_decisions: list[tuple[AnomalySignal, EscalationDecision]]
    ) -> list[tuple[AnomalySignal, EscalationDecision]]:
        """Return only the signals worth running expensive validation on."""
        return [
            (s, d) for s, d in signals_and_decisions
            if d.escalation != Escalation.DROP
        ]


# ---------------------------------------------------------------------------
# Convenience: build a signal from a (baseline, probe) response pair
# ---------------------------------------------------------------------------


def make_signal_from_diff(
    candidate: Any,
    baseline_status: int,
    probe_status: int,
    baseline_length: int,
    probe_length: int,
    canary_in_body: str | None = None,
    baseline_body: str = "",
    probe_body: str = "",
) -> AnomalySignal:
    """Classify a single (baseline, probe) response pair as a signal.

    This is the most common pattern in HTTP-based checks: probe
    something, compare to baseline, emit a cheap signal. The check
    can then let the framework decide whether to escalate.
    """
    if canary_in_body and canary_in_body in probe_body and canary_in_body not in baseline_body:
        return AnomalySignal(
            candidate=candidate,
            kind=AnomalyKind.REFLECTION,
            score=0.3,  # bonus for raw reflection
            reason=f"canary '{canary_in_body}' reflected in body",
        )
    if probe_status != baseline_status:
        return AnomalySignal(
            candidate=candidate,
            kind=AnomalyKind.STATUS_CHANGE,
            score=0.0,
            reason=f"status changed {baseline_status} -> {probe_status}",
        )
    if abs(probe_length - baseline_length) > 0:
        # Length delta alone is weak (CDN cache miss, error-page
        # substitution, etc.) — small score.
        return AnomalySignal(
            candidate=candidate,
            kind=AnomalyKind.LENGTH_DELTA,
            score=0.0,
            reason=f"length delta {baseline_length} -> {probe_length}",
        )
    return AnomalySignal(
        candidate=candidate,
        kind=AnomalyKind.LENGTH_DELTA,  # same length + no reflection → very weak
        score=-0.2,  # negative: explicit "not interesting"
        reason="no change vs baseline",
    )


__all__ = [
    "AnomalyKind",
    "AnomalySignal",
    "Escalation",
    "EscalationDecision",
    "StagedValidator",
    "make_signal_from_diff",
    "default_classify",
    "DEFAULT_ESCALATE_THRESHOLD",
    "DEFAULT_DROP_THRESHOLD",
]