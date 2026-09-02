"""Tests for the Wave 14 Evidence extension.

Spec invariants covered here:

- Evidence carries the WAF / CDN / rate-limit indicators that the
  ReproducibilityResult detected.
- Evidence carries environment uncertainty as a 0..1 score.
- Evidence carries baseline / control timing for differential checks.
- Evidence carries the validation_outcome that was applied.
- Evidence carries the destructive flag + level for active destructive
  probes.
- Fingerprint still differs across the new fields so dedup doesn't
  collapse distinct WAF / rate-limit events.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.http.request import Request
from redveil.http.response import Response
from redveil.validation.control_probe import (
    INCONCLUSIVE,
    RATE_LIMITED,
    TIMING_ANOMALY,
    TIMING_FLAKY,
    TIMING_REPRODUCIBLE,
    WAF_INTERFERENCE,
    ReproducibilityResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_evidence(**overrides) -> Evidence:
    defaults = {
        "request": Request(method="GET", url="https://example.com/test"),
        "kind": ObservationKind.HEADER_MISSING,
        "endpoint": "/test",
        "method": "GET",
        "observation": "missing header",
    }
    defaults.update(overrides)
    return Evidence(**defaults)


def _fake_response(
    *,
    status: int = 200,
    body: str = "ok",
    elapsed_ms: float = 50.0,
) -> Response:
    return Response(
        request_id="r1",
        status_code=status,
        headers={"content-type": "text/html"},
        body=body,
        elapsed_ms=elapsed_ms,
    )


def _fake_result(
    *,
    verdict: str = TIMING_REPRODUCIBLE,
    waf_detected: bool = False,
    rate_limited: bool = False,
    interference_body_length: int | None = None,
    baseline_median_ms: float = 50.0,
    baseline_cv_pct: float = 5.0,
    probe_samples: list[float] | None = None,
    control_samples: list[float] | None = None,
) -> ReproducibilityResult:
    return ReproducibilityResult(
        verdict=verdict,
        baseline_samples=[50.0, 50.0, 50.0],
        baseline_median_ms=baseline_median_ms,
        baseline_cv_pct=baseline_cv_pct,
        control_samples=control_samples or [50.0],
        probe_samples=probe_samples or [3000.0, 3100.0],
        probe_median_ms=3000.0,
        probe_min_ms=3000.0,
        probe_max_ms=3100.0,
        waf_detected=waf_detected,
        rate_limited=rate_limited,
        interference_body_length=interference_body_length,
        notes="ok",
    )


# ---------------------------------------------------------------------------
# 1. Environment indicators
# ---------------------------------------------------------------------------


def test_evidence_defaults_have_no_environmental_alarms():
    """A baseline Evidence has no WAF / rate-limit / environment flags."""
    e = _make_evidence()
    assert e.waf_detected is False
    assert e.waf_indicators == []
    assert e.rate_limited is False
    assert e.rate_limit_indicators == []
    assert e.cdn_detected is None  # None = unknown
    assert e.environment_uncertainty is None


def test_evidence_waf_field_can_be_set():
    """Operators can set waf_detected + waf_indicators directly."""
    e = _make_evidence(
        waf_detected=True,
        waf_indicators=["status_403", "body_length_change"],
    )
    assert e.waf_detected is True
    assert e.waf_indicators == ["status_403", "body_length_change"]


def test_evidence_rate_limit_field_can_be_set():
    e = _make_evidence(
        rate_limited=True,
        rate_limit_indicators=["status_429", "retry_after_header"],
    )
    assert e.rate_limited is True
    assert "status_429" in e.rate_limit_indicators


def test_evidence_environment_uncertainty_range():
    """environment_uncertainty is None by default; settable to 0.0-1.0."""
    e_low = _make_evidence(environment_uncertainty=0.1)
    e_high = _make_evidence(environment_uncertainty=0.9)
    assert e_low.environment_uncertainty == 0.1
    assert e_high.environment_uncertainty == 0.9


# ---------------------------------------------------------------------------
# 2. Timing comparison fields
# ---------------------------------------------------------------------------


def test_evidence_baseline_and_control_timing_fields():
    """Wave 14: baseline_timing_ms + control_timing_ms are populated."""
    e = _make_evidence(
        baseline_timing_ms=240.0,
        control_timing_ms=250.0,
        timing_ms=3260.0,
    )
    assert e.baseline_timing_ms == 240.0
    assert e.control_timing_ms == 250.0
    assert e.timing_ms == 3260.0


def test_evidence_control_input_field():
    """control_input records the legitimate request for comparison."""
    e = _make_evidence(
        input_used="1' AND SLEEP(3)-- -",
        control_input="1",
        observation="probe vs control comparison",
    )
    assert e.control_input == "1"
    assert e.input_used == "1' AND SLEEP(3)-- -"


# ---------------------------------------------------------------------------
# 3. Validation framework linkage
# ---------------------------------------------------------------------------


def test_evidence_validation_outcome_field():
    e = _make_evidence(validation_outcome="confirmed")
    assert e.validation_outcome == "confirmed"


def test_evidence_oracle_signal_field():
    e = _make_evidence(oracle_signal="timing_delta")
    assert e.oracle_signal == "timing_delta"


def test_evidence_confidence_field_is_independent_of_finding():
    """Evidence-level confidence can differ from Finding-level confidence."""
    e = _make_evidence(confidence="low")
    assert e.confidence == "low"


# ---------------------------------------------------------------------------
# 4. Action classification (test_mode + destructive + level)
# ---------------------------------------------------------------------------


def test_evidence_defaults_to_safe_test_mode():
    """Default test_mode is None — caller decides."""
    e = _make_evidence()
    assert e.test_mode is None
    assert e.destructive is False
    assert e.destructive_level is None


def test_evidence_destructive_can_be_set_with_level():
    """Destructive probes carry the level (1..6)."""
    e = _make_evidence(
        test_mode="destructive",
        destructive=True,
        destructive_level=3,
    )
    assert e.test_mode == "destructive"
    assert e.destructive is True
    assert e.destructive_level == 3


# ---------------------------------------------------------------------------
# 5. Fingerprint still differs across new fields
# ---------------------------------------------------------------------------


def test_evidence_fingerprint_differs_by_waf_flag():
    """Same response with vs without WAF gets a different fingerprint."""
    e1 = _make_evidence(waf_detected=False, rate_limited=False)
    e2 = _make_evidence(waf_detected=True, rate_limited=False)
    assert e1.fingerprint != e2.fingerprint


def test_evidence_fingerprint_differs_by_rate_limit_flag():
    e1 = _make_evidence(rate_limited=False)
    e2 = _make_evidence(rate_limited=True)
    assert e1.fingerprint != e2.fingerprint


def test_evidence_fingerprint_differs_by_destructive():
    e1 = _make_evidence(destructive=False)
    e2 = _make_evidence(destructive=True, destructive_level=3)
    assert e1.fingerprint != e2.fingerprint


def test_evidence_fingerprint_stable_across_new_fields_when_equal():
    e1 = _make_evidence(
        waf_detected=True,
        rate_limited=False,
        destructive_level=2,
    )
    e2 = _make_evidence(
        waf_detected=True,
        rate_limited=False,
        destructive_level=2,
    )
    assert e1.fingerprint == e2.fingerprint


# ---------------------------------------------------------------------------
# 6. Sanitizer compatibility
# ---------------------------------------------------------------------------


def test_evidence_serializer_drops_none_new_fields():
    """New fields default to None / empty list and round-trip cleanly."""
    e = _make_evidence()
    dumped = e.model_dump(mode="json", exclude_none=True)
    assert "waf_detected" in dumped
    assert "waf_indicators" in dumped
    assert dumped["waf_indicators"] == []
    # The None-defaulted optionals are dropped.
    assert "environment_uncertainty" not in dumped
    assert "cdn_detected" not in dumped


# ---------------------------------------------------------------------------
# 7. Integration: SQLi / CMDi checks populate the new fields
# ---------------------------------------------------------------------------


def test_sqli_evidence_records_waf_indicators():
    """When the helper reports WAF, the Evidence carries it forward."""
    from redveil.checks.sqli import TimeBasedSQLiCheck
    from redveil.plugins.base import CheckDependencies
    from unittest.mock import AsyncMock

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
        "reproducibility": _fake_result(
            verdict=WAF_INTERFERENCE,
            waf_detected=True,
            interference_body_length=412,
        ),
        "request": Request(method="GET", url="https://example.com/?q=1"),
        "response": _fake_response(status=403, body="blocked" * 50),
    }
    evidence_list = check._evidence_for_candidate(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.waf_detected is True
    assert "status_403" in e.waf_indicators
    assert "body_length_change" in e.waf_indicators
    assert e.environment_uncertainty >= 0.7
    assert e.validation_outcome == "inconclusive"
    assert e.test_mode == "safe"
    assert e.destructive is False


@pytest.mark.asyncio
async def test_cmdi_evidence_records_rate_limit_indicators():
    """When the helper reports rate-limit, CMDi Evidence carries it forward."""
    from redveil.checks.command_injection import CommandInjectionCheck
    from redveil.plugins.base import CheckDependencies
    from unittest.mock import AsyncMock

    check = CommandInjectionCheck()
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
        "parameter": "host",
        "method": "GET",
        "payload": "; sleep 3",
        "separator": ";",
        "baseline_ms": 50.0,
        "delay_ms": 0.0,
        "ratio": 0.0,
        "verdict": RATE_LIMITED,
        "reproducibility": _fake_result(
            verdict=RATE_LIMITED,
            rate_limited=True,
        ),
        "request": Request(method="GET", url="https://example.com/?host=test"),
        "response": _fake_response(status=429, body="rate limited"),
    }
    evidence_list = await check.collect_evidence(candidate)
    assert len(evidence_list) == 1
    e = evidence_list[0]
    assert e.rate_limited is True
    assert "status_429" in e.rate_limit_indicators
    assert "throttle_status" in e.rate_limit_indicators
    assert e.environment_uncertainty >= 0.8
    assert e.validation_outcome == "inconclusive"


def test_sqli_reproducible_evidence_has_low_environment_uncertainty():
    """A clean reproducible probe records low uncertainty."""
    from redveil.checks.sqli import TimeBasedSQLiCheck
    from redveil.plugins.base import CheckDependencies
    from unittest.mock import AsyncMock

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
        "reproducibility": _fake_result(verdict=TIMING_REPRODUCIBLE),
        "request": Request(method="GET", url="https://example.com/?q=1"),
        "response": _fake_response(elapsed_ms=3000.0),
    }
    evidence_list = check._evidence_for_candidate(candidate)
    e = evidence_list[0]
    assert e.waf_detected is False
    assert e.rate_limited is False
    assert e.environment_uncertainty is not None
    assert e.environment_uncertainty <= 0.2
    assert e.validation_outcome == "confirmed"
    assert e.confidence == "high"
    # Baseline + control + probe timing all populated.
    assert e.baseline_timing_ms == 50.0
    assert e.control_timing_ms == 50.0
    assert e.timing_ms == 3000.0