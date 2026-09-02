from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from redveil.http.request import Request
from redveil.http.response import Response


class ObservationKind(str, Enum):
    REFLECTION = "reflection"
    TIMING_DELTA = "timing_delta"
    STATUS_DIFF = "status_diff"
    BODY_DIFF = "body_diff"
    OOB_CALLBACK = "oob_callback"
    HEADER_PRESENT = "header_present"
    HEADER_MISSING = "header_missing"
    COOKIE_FLAG = "cookie_flag"
    REDIRECT_TARGET = "redirect_target"
    ERROR_DISCLOSURE = "error_disclosure"
    FILE_EXISTENCE = "file_existence"


class Evidence(BaseModel):
    """First-class evidence object. Reproducible + sanitizable.

    Spec invariants (Wave 14 evidence extension):

    - target / endpoint: ``endpoint``
    - HTTP method: ``method``
    - parameter / location: ``parameter``
    - probe identifier: ``request.request_id``
    - probe input: ``input_used``
    - control input: ``control_input`` (NEW — the legitimate request
      sent before/after the probe for timing checks)
    - status code: ``status_code``
    - response timing: ``timing_ms``
    - baseline timing: ``baseline_timing_ms`` (NEW)
    - control timing: ``control_timing_ms`` (NEW)
    - relevant headers: ``relevant_headers``
    - response excerpt: ``body_excerpt``
    - oracle signal: ``oracle_signal`` (NEW — which SignalKind
      triggered the finding, e.g. "timing_delta", "waf_challenge_page")
    - validation outcome: ``validation_outcome`` (NEW — the
      ValidationOutcome enum value applied to this evidence)
    - confidence: ``confidence`` (NEW — confidence level at the
      evidence-collection point; the Finding also has its own confidence
      which may differ after aggregation)
    - environment uncertainty: ``environment_uncertainty`` (NEW —
      0.0 = confident no environmental contamination, 1.0 = full
      uncertainty about whether the signal is from the target or the
      infrastructure in front of it)
    - WAF indicators: ``waf_detected`` + ``waf_indicators`` (NEW —
      list of strings describing why WAF was flagged)
    - CDN indicators: ``cdn_detected`` (NEW — None = unknown,
      True = strong CDN signal, False = direct origin)
    - rate-limit indicators: ``rate_limited`` + ``rate_limit_indicators``
      (NEW — list of strings describing the rate-limit evidence)
    - test mode: ``test_mode`` (NEW — "safe" or "destructive")
    - whether destructive: ``destructive`` (NEW)
    - destructive level: ``destructive_level`` (NEW — 1..6)
    """
    id: str = Field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:8]}")
    finding_id: str | None = None  # backref once attached
    request: Request
    response: Response | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    kind: ObservationKind
    endpoint: str
    method: str
    parameter: str | None = None
    input_used: str | None = None
    status_code: int | None = None
    relevant_headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str = ""

    timing_ms: float | None = None
    observation: str = ""  # human-readable summary
    fingerprint: str = ""

    # Control / baseline comparison (timing checks populate these)
    control_input: str | None = None
    baseline_timing_ms: float | None = None
    control_timing_ms: float | None = None

    # Validation framework linkage
    oracle_signal: str | None = None
    validation_outcome: str | None = None
    confidence: str | None = None

    # Environmental indicators — populated by checks via the
    # ReproducibilityResult from control_probe.py.
    environment_uncertainty: float | None = None  # 0.0 .. 1.0
    waf_detected: bool = False
    waf_indicators: list[str] = Field(default_factory=list)
    cdn_detected: bool | None = None  # None = unknown
    rate_limited: bool = False
    rate_limit_indicators: list[str] = Field(default_factory=list)

    # Action classification at evidence-collection time
    test_mode: str | None = None  # "safe" or "destructive"
    destructive: bool = False
    destructive_level: int | None = None  # 1..6

    def compute_fingerprint(self) -> str:
        """Stable fingerprint for dedup. Hashes kind+endpoint+parameter+input+relevant_headers+status+waf/rate-limit/destructive state.

        The WAF / rate-limit / destructive flags are included so two
        identical-looking responses with different WAF or destructive
        behavior do not collapse into one finding during dedup.
        """
        payload = "|".join([
            self.kind.value,
            self.endpoint,
            self.parameter or "",
            (self.input_used or "")[:200],
            str(self.status_code or ""),
            ",".join(f"{k.lower()}={v}" for k, v in sorted(self.relevant_headers.items())),
            f"waf={int(self.waf_detected)}",
            f"rl={int(self.rate_limited)}",
            f"dest={int(self.destructive)}",
            f"lvl={self.destructive_level or 0}",
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def model_post_init(self, __context) -> None:
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self.compute_fingerprint())
