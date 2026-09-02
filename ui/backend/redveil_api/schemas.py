"""Pydantic v2 request/response schemas for the redveil API.

All ORM-mapped schemas use ``ConfigDict(from_attributes=True)`` so they can
be built directly from SQLAlchemy ORM objects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --- Targets ---------------------------------------------------------------


class TargetBase(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    name: str | None = None
    scope_yaml: str | None = None


class TargetCreate(TargetBase):
    """Request body for POST /api/targets."""


class TargetUpdate(BaseModel):
    """Request body for PATCH /api/targets/{id}."""

    name: str | None = None
    scope_yaml: str | None = None


class TargetOut(TargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


# --- Scans -----------------------------------------------------------------


class ScanCreate(BaseModel):
    """Request body for POST /api/scans."""

    target_id: int
    profile: str = "passive"
    scope_yaml: str | None = None
    max_requests: int | None = None
    rps: float | None = None
    # Wave 3 follow-up: destructive level + gate mode
    max_destructive_level: str = Field(
        default="L2",
        pattern=r"^L[1-6]$",
        description=(
            "Maximum destructive level the operator allows. "
            "One of L1..L6 (also accepts '1'..'6'). "
            "Higher levels unlock more invasive actions."
        ),
    )
    allow_destructive: bool = Field(
        default=False,
        description=(
            "Allow destructive actions (data destruction, persistence, "
            "lateral movement, takeover). Defaults to false."
        ),
    )
    gate_mode: str = Field(
        default="non_interactive",
        description=(
            "ActionGate mode: 'interactive' (prompt per action), "
            "'non_interactive' (auto-approve), or 'strict' (auto-deny "
            "MEDIUM+). Stored for future use."
        ),
    )

    # Allowed destructive level values (both forms accepted on input).
    _DESTRUCTIVE_LEVELS: ClassVar[set[str]] = {
        "L1", "L2", "L3", "L4", "L5", "L6",
        "1", "2", "3", "4", "5", "6",
    }
    _GATE_MODES: ClassVar[set[str]] = {
        "interactive",
        "non_interactive",
        "strict",
    }

    @field_validator("max_destructive_level", mode="before")
    @classmethod
    def _validate_level(cls, v: Any) -> str:
        """Accept 'L1'..'L6' or '1'..'6'; normalize to 'L#' form."""
        if not isinstance(v, str):
            raise ValueError(
                f"max_destructive_level must be a string, got {type(v).__name__}"
            )
        if v not in cls._DESTRUCTIVE_LEVELS:
            raise ValueError(
                f"max_destructive_level must be one of L1-L6, got {v!r}"
            )
        # Normalize numeric form to L# form for consistency in the DB.
        return v if v.upper().startswith("L") else f"L{v}"

    @field_validator("gate_mode", mode="before")
    @classmethod
    def _validate_gate_mode(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError(
                f"gate_mode must be a string, got {type(v).__name__}"
            )
        if v not in cls._GATE_MODES:
            raise ValueError(
                f"gate_mode must be one of {sorted(cls._GATE_MODES)}, got {v!r}"
            )
        return v


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    status: str
    profile: str
    scan_type: str
    started_at: datetime | None
    completed_at: datetime | None
    output_dir: str | None
    total_requests: int
    error: str | None
    # Wave 3 follow-up: destructive level + gate mode
    max_destructive_level: str = "L2"
    allow_destructive: bool = False
    gate_mode: str = "non_interactive"


class ScanStatus(BaseModel):
    """Lightweight status payload used for the SSE stream and quick polls."""

    id: int
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    total_requests: int
    error: str | None


# --- Findings --------------------------------------------------------------


class FindingOut(BaseModel):
    """Trimmed finding view (used in lists)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    wpoc_id: str
    severity: str
    confidence: str
    status: str
    title: str
    endpoint: str | None
    check_id: str | None
    created_at: datetime


class FindingDetailOut(FindingOut):
    """Detailed finding view with evidence + raw finding payload."""

    fingerprint: str | None
    finding_data: dict[str, Any] = Field(default_factory=dict)


# --- Checks ----------------------------------------------------------------


class CheckOut(BaseModel):
    """Plugin metadata for the /api/checks endpoints."""

    id: str
    name: str
    category: str
    safety_profile: str
    description: str = ""
    max_risk: str = "none"
    version: str = "0.1.0"


class CheckDetailOut(CheckOut):
    """Same as CheckOut for now — kept separate so the API can grow later."""


# --- Evidence (Wave 14 / Site Map page) -----------------------------------


class EvidenceOut(BaseModel):
    """Serialized Evidence record (one HTTP request/response observation)."""

    id: str
    finding_id: str | None = None
    kind: str
    endpoint: str
    method: str
    parameter: str | None = None
    input_used: str | None = None
    status_code: int | None = None
    timing_ms: float | None = None
    baseline_timing_ms: float | None = None
    control_timing_ms: float | None = None
    control_input: str | None = None
    body_excerpt: str = ""
    oracle_signal: str | None = None
    validation_outcome: str | None = None
    confidence: str | None = None
    environment_uncertainty: float | None = None
    waf_detected: bool = False
    rate_limited: bool = False
    check_id: str | None = None
    timestamp: str | None = None  # ISO-8601 string


# --- Scope (Target / Site Map page) ----------------------------------------


class ScopeOut(BaseModel):
    """Scope summary for a target — allowed/deny hosts and path globs."""

    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    follow_redirects: bool = True
    max_redirects: int = 5
    raw_yaml: str | None = None  # original user-authored YAML, if any


# --- Issue definitions (Target / Site Map page) ----------------------------


class IssueDefinitionOut(BaseModel):
    """An entry from redveil.knowledge.vuln_descriptions.

    The knowledge base keys entries by ``(check_id, issue_kind)`` and many
    aliases point at the same canonical entry. We dedupe by canonical entry
    identity so the UI shows each issue definition exactly once.
    """

    id: str
    name: str
    check_id: str | None = None
    severity: str = "info"
    summary: str
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)


# --- Site map (Target / Site Map page) ------------------------------------


class SiteMapEndpointOut(BaseModel):
    """One endpoint row in the target site map."""

    endpoint: str
    method: str
    finding_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    severity_counts: dict[str, int] = Field(default_factory=dict)


class SiteMapOut(BaseModel):
    """Per-target site map: endpoints grouped by path prefix (folder tree)."""

    target_id: int
    target_url: str
    endpoints: list[SiteMapEndpointOut] = Field(default_factory=list)
    folders: list[str] = Field(default_factory=list)


# --- Replay ----------------------------------------------------------------


class ReplaySample(BaseModel):
    """A single sample from a replay run — one HTTP response."""

    index: int
    status_code: int
    elapsed_ms: float
    body_length: int
    body_excerpt: str = ""  # first ~200 chars, redacted
    error: str | None = None  # timeout, connection error, etc.


class ReplayOut(BaseModel):
    """Result of replaying a finding's recipe against its target.

    The verdict is the operator-facing summary:
      - "Reproducible"  : is_reliable() and all samples succeeded
      - "Flaky"          : samples succeeded but consistency signals disagree
      - "Not verified"  : is_reliable() returned False
    """

    wpoc_id: str
    finding_title: str
    target_url: str | None
    method: str
    samples: list[ReplaySample]
    sample_count: int
    success_count: int
    total_duration_ms: float
    consistent: bool
    status_variance: int
    body_length_variance: int
    body_content_match: bool
    timing_variance_ms: float
    reliable: bool
    verdict: str  # "Reproducible" | "Not verified" | "Flaky"
    notes: str = ""
    executed_at: str  # ISO-8601 timestamp
