"""Tests for the Wave 14 adaptive staged validation framework.

Spec deliverable: cheap anomaly detection → potential signal →
targeted validation pipeline. Do not run expensive validation
against every parameter unless necessary.

This test file covers the framework itself (the StagedValidator +
helper). Per-check adoption is tested in the relevant check's
test file (e.g. test_sqli_staged_validation).
"""
from __future__ import annotations

import pytest

from redveil.validation.staged import (
    AnomalyKind,
    AnomalySignal,
    Escalation,
    EscalationDecision,
    StagedValidator,
    default_classify,
    make_signal_from_diff,
)


# ---------------------------------------------------------------------------
# 1. Anomaly signal shape
# ---------------------------------------------------------------------------


def test_anomaly_signal_default_score_zero():
    s = AnomalySignal(candidate={"x": 1}, kind=AnomalyKind.REFLECTION)
    assert s.score == 0.0
    assert s.reason == ""
    assert s.extra == {}


def test_anomaly_signal_score_clamped_to_unit_interval():
    """default_classify clamps score to [0, 1]."""
    s = AnomalySignal(candidate=object(), kind=AnomalyKind.OOB_INDICATOR, score=99.0)
    d = default_classify(s)
    assert 0.0 <= d.score <= 1.0


# ---------------------------------------------------------------------------
# 2. Default classifier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,signal_score,expected_escalation",
    [
        # High-confidence signals (base score 0.6+)
        (AnomalyKind.COOKIE_PERSISTENCE, 0.0, Escalation.ESCALATE),
        (AnomalyKind.OOB_INDICATOR, 0.0, Escalation.ESCALATE),
        (AnomalyKind.STATUS_CHANGE, 0.0, Escalation.ESCALATE),
        (AnomalyKind.STATE_TRANSITION, 0.0, Escalation.ESCALATE),
        (AnomalyKind.REFLECTION, 0.0, Escalation.ESCALATE),  # base 0.5 hits threshold
        # Borderline (base 0.4)
        (AnomalyKind.TIMING_PROMISE, 0.0, Escalation.DEFER),
        # Weak
        (AnomalyKind.LENGTH_DELTA, -0.2, Escalation.DROP),
    ],
)
def test_default_classify_matrix(kind, signal_score, expected_escalation):
    s = AnomalySignal(candidate=object(), kind=kind, score=signal_score)
    d = default_classify(s)
    assert d.escalation == expected_escalation


def test_reflection_with_positive_bonus_escalates():
    """REFLECTION + score=0.3 bonus → score 0.8 → ESCALATE."""
    s = AnomalySignal(
        candidate=object(),
        kind=AnomalyKind.REFLECTION,
        score=0.3,  # bonus for raw canary in body
    )
    d = default_classify(s)
    assert d.escalation == Escalation.ESCALATE


# ---------------------------------------------------------------------------
# 3. StagedValidator.classify / classify_all
# ---------------------------------------------------------------------------


def test_classify_returns_decision():
    v = StagedValidator()
    s = AnomalySignal(candidate=object(), kind=AnomalyKind.OOB_INDICATOR)
    d = v.classify(s)
    assert isinstance(d, EscalationDecision)
    assert d.escalation == Escalation.ESCALATE


def test_classify_all_processes_every_signal():
    v = StagedValidator()
    signals = [
        AnomalySignal(candidate={"i": i}, kind=AnomalyKind.LENGTH_DELTA, score=-0.2)
        for i in range(10)
    ]
    decisions = v.classify_all(signals)
    assert len(decisions) == 10
    assert all(d.escalation == Escalation.DROP for d in decisions)


def test_filter_escalate_removes_drops():
    v = StagedValidator()
    signals = [
        AnomalySignal(candidate={"i": 0}, kind=AnomalyKind.LENGTH_DELTA, score=-0.2),
        AnomalySignal(candidate={"i": 1}, kind=AnomalyKind.OOB_INDICATOR),
        AnomalySignal(candidate={"i": 2}, kind=AnomalyKind.LENGTH_DELTA, score=-0.2),
        AnomalySignal(candidate={"i": 3}, kind=AnomalyKind.STATE_TRANSITION),
    ]
    decisions = v.classify_all(signals)
    pairs = list(zip(signals, decisions))
    kept = v.filter_escalate(pairs)
    # Only 2 of 4 survive the filter.
    assert len(kept) == 2
    kept_ids = {s.candidate["i"] for s, _ in kept}
    assert kept_ids == {1, 3}


# ---------------------------------------------------------------------------
# 4. Custom classifier
# ---------------------------------------------------------------------------


def test_custom_classifier_overrides_default():
    """A check can pass its own classifier for tighter thresholds."""
    def strict_classify(signal, **_):
        # Always escalate, regardless of score.
        return EscalationDecision(
            escalation=Escalation.ESCALATE,
            score=1.0,
            reason="strict mode",
        )

    v = StagedValidator(classify=strict_classify)
    s = AnomalySignal(candidate=object(), kind=AnomalyKind.LENGTH_DELTA, score=-0.2)
    d = v.classify(s)
    assert d.escalation == Escalation.ESCALATE
    assert d.reason == "strict mode"


def test_custom_thresholds():
    """Per-check tightening of drop / escalate thresholds."""
    v = StagedValidator(escalate_threshold=0.9, drop_threshold=0.4)
    # OOB_INDICATOR base 0.7 → below tightened escalate_threshold → DEFER
    s = AnomalySignal(candidate=object(), kind=AnomalyKind.OOB_INDICATOR)
    d = v.classify(s)
    assert d.escalation == Escalation.DEFER


# ---------------------------------------------------------------------------
# 5. make_signal_from_diff helper
# ---------------------------------------------------------------------------


def test_make_signal_from_diff_status_change():
    s = make_signal_from_diff(
        candidate=object(),
        baseline_status=200,
        probe_status=403,
        baseline_length=100,
        probe_length=50,
    )
    assert s.kind == AnomalyKind.STATUS_CHANGE


def test_make_signal_from_diff_reflection_in_body():
    s = make_signal_from_diff(
        candidate=object(),
        baseline_status=200,
        probe_status=200,
        baseline_length=100,
        probe_length=200,
        canary_in_body="redveilcanary",
        baseline_body="ok",
        probe_body="redveilcanary echoed",
    )
    assert s.kind == AnomalyKind.REFLECTION


def test_make_signal_from_diff_length_only():
    s = make_signal_from_diff(
        candidate=object(),
        baseline_status=200,
        probe_status=200,
        baseline_length=100,
        probe_length=200,
    )
    assert s.kind == AnomalyKind.LENGTH_DELTA


def test_make_signal_from_diff_no_change_is_low_signal():
    s = make_signal_from_diff(
        candidate=object(),
        baseline_status=200,
        probe_status=200,
        baseline_length=100,
        probe_length=100,
    )
    assert s.kind == AnomalyKind.LENGTH_DELTA
    # Negative score → drops below DROP_THRESHOLD
    d = default_classify(s)
    assert d.escalation == Escalation.DROP


# ---------------------------------------------------------------------------
# 6. End-to-end: discovery → anomaly → filter → targeted
# ---------------------------------------------------------------------------


def test_end_to_end_pipeline_filters_out_drops_before_targeted():
    """Simulate a real check: emit many signals, filter out drops,
    only the escalated ones reach targeted validation."""
    v = StagedValidator()
    raw_candidates = list(range(20))
    # 5 interesting (OOB / state / cookie), 15 noise (length-only
    # or no change).
    signals = []
    for i in raw_candidates:
        if i < 5:
            signals.append(AnomalySignal(
                candidate={"id": i, "kind": "real"},
                kind=AnomalyKind.OOB_INDICATOR,
            ))
        else:
            signals.append(AnomalySignal(
                candidate={"id": i, "kind": "noise"},
                kind=AnomalyKind.LENGTH_DELTA,
                score=-0.2,
            ))
    decisions = v.classify_all(signals)
    pairs = list(zip(signals, decisions))
    kept = v.filter_escalate(pairs)

    # Only 5 escalated.
    assert len(kept) == 5
    # The 15 noise candidates are dropped — expensive validation is
    # never run on them (spec: "Do not perform expensive validation
    # against every parameter unless necessary").
    kinds = [s.candidate["kind"] for s, _ in kept]
    assert all(k == "real" for k in kinds)