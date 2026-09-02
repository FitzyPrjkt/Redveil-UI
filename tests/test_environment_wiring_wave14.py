"""Wave 14: EnvironmentProfile / Uncertainty → ConfidenceScorer wiring.

Spec asks for environment uncertainty to actually affect confidence
scoring rather than just being recorded as metadata. The plumbing:

  - EnvironmentProfile.environmental_penalty → ConfidenceScorer penalty
  - Uncertainty.to_penalty() → comparable to score penalty
  - Evidence.environment_uncertainty → propagates to scorer via
    the new ``uncertainty`` kwarg on ``score()`` / ``confidence()``

These tests pin the wiring so a future change that drops the
uncertainty kwarg breaks the build.
"""
from __future__ import annotations

import pytest

from redveil.findings.confidence import Confidence
from redveil.validation.confidence import (
    ConfidenceScore,
    ConfidenceScorer,
    aggregate_uncertainty,
    uncertainty_from_evidence,
)
from redveil.validation.environment import (
    Environment,
    EnvironmentProfile,
    Uncertainty,
)
from redveil.validation.oracle import Oracle, Signal, SignalKind


# ---------------------------------------------------------------------------
# 1. Constructor accepts uncertainty_penalty_scale
# ---------------------------------------------------------------------------


def test_confidence_scorer_default_uncertainty_penalty_scale():
    """Default penalty scale is 2.0 (matches Uncertainty.to_penalty)."""
    scorer = ConfidenceScorer()
    assert scorer.uncertainty_penalty_scale == 2.0


def test_confidence_scorer_custom_penalty_scale():
    """Operators can tune the penalty scale for special cases."""
    scorer = ConfidenceScorer(uncertainty_penalty_scale=1.5)
    assert scorer.uncertainty_penalty_scale == 1.5


# ---------------------------------------------------------------------------
# 2. Uncertainty kwarg downgrades the score
# ---------------------------------------------------------------------------


def _single_signal_signal() -> Signal:
    return Signal(
        kind=SignalKind.TIMING_DELTA,
        description="probe slow",
        weight=1.0,
        dimension="response",
    )


def test_uncertainty_zero_does_not_downgrade():
    """uncertainty=0.0 → score is unchanged from the no-uncertainty baseline."""
    no_unc = ConfidenceScorer().score([_single_signal_signal()], Oracle.STATE_TRANSITION)
    explicit_zero = ConfidenceScorer().score(
        [_single_signal_signal()],
        Oracle.STATE_TRANSITION,
        uncertainty=0.0,
    )
    assert no_unc.score == explicit_zero.score


def test_uncertainty_high_downgrades_score():
    """uncertainty=0.9 → score drops by 0.9 * 2.0 = 1.8 from baseline."""
    no_unc = ConfidenceScorer().score([_single_signal_signal()], Oracle.STATE_TRANSITION)
    high_unc = ConfidenceScorer().score(
        [_single_signal_signal()],
        Oracle.STATE_TRANSITION,
        uncertainty=0.9,
    )
    delta = no_unc.score - high_unc.score
    # Allow for rounding tolerance
    assert 1.7 < delta < 1.9, f"expected ~1.8 downgrade, got {delta}"


def test_uncertainty_clamped_to_unit_interval():
    """uncertainty > 1.0 is clamped to 1.0 (no negative scores from overflow)."""
    s = ConfidenceScorer().score(
        [_single_signal_signal()],
        Oracle.STATE_TRANSITION,
        uncertainty=5.0,
    )
    assert s.uncertainty_penalty == 2.0  # 1.0 * scale
    assert s.score >= 0.0


def test_uncertainty_recorded_on_score_object():
    """ConfidenceScore exposes the uncertainty_penalty that was applied."""
    s = ConfidenceScorer().score(
        [_single_signal_signal()],
        Oracle.STATE_TRANSITION,
        uncertainty=0.5,
    )
    assert s.uncertainty_penalty == 1.0  # 0.5 * 2.0


def test_uncertainty_can_drop_confidence_enum_level():
    """High uncertainty can downgrade CONFIRMED→MEDIUM or lower.

    We pick an oracle + signals combo that lands at the CONFIRMED
    threshold (~4.0) without uncertainty, then apply enough uncertainty
    to push it below that threshold. This is the user-visible behavior
    the spec wants.
    """
    # STATE_TRANSITION oracle (value=4) + 1 signal: raw score = 4 * 1.0 *
    # (1.0 + 0.05) = 4.2 → CONFIRMED. After uncertainty 0.9 penalty
    # (= 1.8): score drops to 2.4 → MEDIUM.
    signals = [Signal(
        kind=SignalKind.TIMING_DELTA,
        description="probe slow",
        weight=1.0,
        dimension="response",
    )]
    clean = ConfidenceScorer().confidence(signals, Oracle.STATE_TRANSITION)
    noisy = ConfidenceScorer().confidence(
        signals,
        Oracle.STATE_TRANSITION,
        uncertainty=0.9,
    )
    assert clean == Confidence.CONFIRMED, f"expected baseline CONFIRMED, got {clean}"
    # The noisy version must be at least one tier lower than clean.
    tier_order = [
        Confidence.TENTATIVE,
        Confidence.LOW,
        Confidence.MEDIUM,
        Confidence.HIGH,
        Confidence.CONFIRMED,
    ]
    assert tier_order.index(clean) > tier_order.index(noisy), (
        f"uncertainty did not downgrade: clean={clean} noisy={noisy}"
    )


# ---------------------------------------------------------------------------
# 3. EnvironmentProfile penalty combines with uncertainty
# ---------------------------------------------------------------------------


def test_environment_profile_waf_penalty_applied():
    """EnvironmentProfile(Environment.WAF) → 0.6 penalty baseline."""
    scorer = ConfidenceScorer(
        environmental_penalty=EnvironmentProfile(environments=(Environment.WAF,)).environmental_penalty,
    )
    assert scorer.environmental_penalty == 0.6


def test_environment_plus_uncertainty_stack():
    """EnvironmentProfile penalty and uncertainty penalty both apply."""
    scorer = ConfidenceScorer(
        environmental_penalty=0.6,  # WAF env
    )
    no_unc = scorer.score([_single_signal_signal()], Oracle.STATE_TRANSITION)
    with_unc = scorer.score(
        [_single_signal_signal()],
        Oracle.STATE_TRANSITION,
        uncertainty=0.5,
    )
    # 0.5 * 2.0 = 1.0 uncertainty penalty on top of 0.6 env penalty
    assert no_unc.score - with_unc.score == pytest.approx(1.0, abs=0.05)


def test_environment_profile_dev_has_no_penalty():
    """EnvironmentProfile(Environment.DEV) → 0.0 penalty."""
    profile = EnvironmentProfile(environments=(Environment.DEV,))
    assert profile.environmental_penalty == 0.0


def test_environment_profile_multi_environment_stacks():
    """Multiple environments stack penalties (production + CDN = 0.8)."""
    profile = EnvironmentProfile(environments=(Environment.PRODUCTION, Environment.CDN))
    assert profile.environmental_penalty == pytest.approx(0.8, abs=0.01)


# ---------------------------------------------------------------------------
# 4. Uncertainty.to_penalty() agrees with the scorer's scale
# ---------------------------------------------------------------------------


def test_uncertainty_to_penalty_matches_scorer():
    """Uncertainty.to_penalty() = total * 2.0 should match the scorer's math.

    If these drift apart, callers wiring Uncertainty through to the
    scorer get inconsistent penalties.
    """
    u = Uncertainty()
    u.add("waf", 0.7)
    assert u.total == 0.7
    assert u.to_penalty() == 1.4  # 0.7 * 2.0

    # Same number via scorer.score() with uncertainty=0.7:
    s = ConfidenceScorer().score(
        [_single_signal_signal()],
        Oracle.STATE_TRANSITION,
        uncertainty=u.total,
    )
    assert s.uncertainty_penalty == pytest.approx(u.to_penalty(), abs=0.001)


# ---------------------------------------------------------------------------
# 5. aggregate_uncertainty helper
# ---------------------------------------------------------------------------


def test_aggregate_uncertainty_takes_max():
    """aggregate_uncertainty uses the most pessimistic of the inputs."""
    assert aggregate_uncertainty([0.1, 0.7, 0.4]) == 0.7
    assert aggregate_uncertainty([0.0]) == 0.0
    assert aggregate_uncertainty([]) == 0.0


def test_aggregate_uncertainty_ignores_none():
    assert aggregate_uncertainty([None, 0.5, None]) == 0.5
    assert aggregate_uncertainty([None, None]) == 0.0


def test_aggregate_uncertainty_clamps():
    """Values outside [0.0, 1.0] are clamped before max."""
    assert aggregate_uncertainty([1.5]) == 1.0
    assert aggregate_uncertainty([-0.3]) == 0.0


# ---------------------------------------------------------------------------
# 6. uncertainty_from_evidence helper
# ---------------------------------------------------------------------------


def test_uncertainty_from_evidence_with_field():
    """Reading uncertainty from an Evidence-shaped object returns the field."""
    class FakeEvidence:
        environment_uncertainty = 0.6
    assert uncertainty_from_evidence(FakeEvidence()) == 0.6


def test_uncertainty_from_evidence_with_none_field():
    """None uncertainty → 0.0 (default; full certainty)."""
    class FakeEvidence:
        environment_uncertainty = None
    assert uncertainty_from_evidence(FakeEvidence()) == 0.0


def test_uncertainty_from_evidence_missing_field():
    """Missing field → 0.0 (graceful degradation)."""
    class FakeEvidence:
        pass
    assert uncertainty_from_evidence(FakeEvidence()) == 0.0


def test_uncertainty_from_evidence_clamps_out_of_range():
    """Out-of-range field values are clamped."""
    class TooHigh:
        environment_uncertainty = 1.5
    class TooLow:
        environment_uncertainty = -0.2
    assert uncertainty_from_evidence(TooHigh()) == 1.0
    assert uncertainty_from_evidence(TooLow()) == 0.0


# ---------------------------------------------------------------------------
# 7. End-to-end: Wave 5 checks produce findings with confidence that
# reflects the environment uncertainty.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reproducible_finding_keeps_high_confidence():
    """A clean reproducible timing check should not be downgraded by uncertainty."""
    from redveil.checks.sqli import TimeBasedSQLiCheck
    from redveil.plugins.base import CheckDependencies
    from redveil.http.request import Request
    from redveil.http.response import Response
    from redveil.validation.control_probe import (
        ReproducibilityResult,
        TIMING_REPRODUCIBLE,
    )
    from unittest.mock import MagicMock, AsyncMock

    check = TimeBasedSQLiCheck()
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = True
    cfg.authorization.acknowledged_safety_terms = True
    cfg.authorization.allow_destructive = False
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock()
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)

    candidate = {
        "endpoint": "/",
        "parameter": "q",
        "method": "GET",
        "db_family": "mysql",
        "payload": "1' AND SLEEP(3)-- -",
        "verdict": TIMING_REPRODUCIBLE,
        "baseline_median_ms": 50.0,
        "probe_median_ms": 3000.0,
        "baseline_cv_pct": 5.0,
        "reproducibility": ReproducibilityResult(
            verdict=TIMING_REPRODUCIBLE,
            baseline_samples=[50.0, 50.0, 50.0],
            baseline_median_ms=50.0,
            baseline_cv_pct=5.0,
            probe_samples=[3000.0, 3100.0],
            probe_median_ms=3000.0,
            probe_min_ms=3000.0,
            probe_max_ms=3100.0,
        ),
    }
    finding = await check.assess(candidate)
    assert finding is not None
    # Reproducible timing → MEDIUM or higher; uncertainty 0.1 × 2.0 = 0.2
    # penalty, so still MEDIUM+ given the strong oracle + multi-signal.
    from redveil.findings.confidence import Confidence
    assert finding.confidence in (
        Confidence.MEDIUM,
        Confidence.HIGH,
        Confidence.CONFIRMED,
    ), f"reproducible finding got downgraded too far: {finding.confidence}"


@pytest.mark.asyncio
async def test_waf_finding_confidence_is_downgraded():
    """A WAF_INTERFERENCE finding should have lower confidence than a clean one."""
    from redveil.checks.sqli import TimeBasedSQLiCheck
    from redveil.plugins.base import CheckDependencies
    from redveil.validation.control_probe import (
        ReproducibilityResult,
        WAF_INTERFERENCE,
    )
    from redveil.findings.confidence import Confidence
    from unittest.mock import MagicMock, AsyncMock

    check = TimeBasedSQLiCheck()
    mock_http = MagicMock()
    mock_http._scope = MagicMock()
    cfg = MagicMock()
    cfg.target.base_url = "https://example.com"
    cfg.authorization.active_testing = True
    cfg.authorization.acknowledged_safety_terms = True
    cfg.authorization.allow_destructive = False
    cfg.authorization.out_of_band_callback_domain = None
    mock_http.send = AsyncMock()
    deps = CheckDependencies(http=mock_http, scope=mock_http._scope, config=cfg, context=MagicMock())
    check.bind(deps)

    candidate = {
        "endpoint": "/",
        "parameter": "q",
        "method": "GET",
        "db_family": "mysql",
        "payload": "1' AND SLEEP(3)-- -",
        "verdict": WAF_INTERFERENCE,
        "baseline_median_ms": 50.0,
        "probe_median_ms": 0.0,
        "baseline_cv_pct": 5.0,
        "reproducibility": ReproducibilityResult(
            verdict=WAF_INTERFERENCE,
            baseline_samples=[50.0, 50.0, 50.0],
            baseline_median_ms=50.0,
            baseline_cv_pct=5.0,
            waf_detected=True,
            interference_body_length=412,
        ),
    }
    finding = await check.assess(candidate)
    assert finding is not None
    # WAF interference → uncertainty 0.7 × 2.0 = 1.4 penalty
    # → downgraded significantly from a clean run
    assert finding.confidence in (
        Confidence.TENTATIVE,
        Confidence.LOW,
        Confidence.MEDIUM,
    ), f"WAF finding should be downgraded but is: {finding.confidence}"