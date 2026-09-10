"""Pydantic v2 request/response schemas for the redveil API.

All ORM-mapped schemas use ``ConfigDict(from_attributes=True)`` so they can
be built directly from SQLAlchemy ORM objects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# --- Targets ---------------------------------------------------------------


class TargetBase(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    name: str | None = None
    scope_yaml: str | None = None

    @field_validator("url", mode="before")
    @classmethod
    def _validate_url(cls, v: Any) -> str:
        """Reject URLs that are unsafe to persist as scan targets.

        This is the first line of defense — applied at the schema layer
        so the rejection surfaces as HTTP 422 before any DB write. The
        operator's scope_yaml (allowed_hosts / allowed_paths) remains the
        authority on WHICH hosts are in-scope; this validator only blocks
        the small set of inputs that are unsafe regardless of scope:
        non-http(s) schemes (file://, ftp://, javascript:, data:, ...),
        cloud metadata endpoints (AWS IMDS, GCP, Azure), and unspecified
        addresses. Loopback and RFC1918 are deliberately allowed here —
        ScopeController enforces them via the operator's allowed_hosts.
        """
        from redveil_ui.api.url_safety import validate_target_url

        ok, reason = validate_target_url(v)
        if not ok:
            raise ValueError(reason)
        return v


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
    max_requests: int | None = Field(
        default=None,
        gt=0,
        le=100_000,
        description=(
            "Optional per-scan request budget. Must be > 0 and <= 100000. "
            "When None, the production default of 500 is used."
        ),
    )
    rps: float | None = Field(
        default=None,
        gt=0,
        le=100,
        description="Optional requests-per-second override (must be > 0 and <= 100).",
    )
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
    # Phase A1: optional allowlist of check IDs. None/empty = all checks.
    enabled_checks: list[str] | None = Field(
        default=None,
        description="Optional allowlist of check IDs to run (e.g. ['sqli-time-based','xss-reflected']). None/empty = all.",
    )
    # Phase A3: optional OpenAPI spec content (yaml/json) to seed ApplicationModel
    openapi_spec: str | None = Field(
        default=None,
        description="OpenAPI spec content (yaml/json) to seed ApplicationModel endpoints (A3). Max 200KB.",
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

    @field_validator("openapi_spec", mode="before")
    @classmethod
    def _validate_openapi_spec(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("openapi_spec must be a string")
        s = v.strip()
        if not s:
            return None
        if len(s) > 200_000:
            raise ValueError("openapi_spec too large (max 200KB)")
        # Basic sanity: must look like yaml/json with paths or openapi
        lower = s.lower()
        if "paths" not in lower and "openapi" not in lower and "swagger" not in lower:
            raise ValueError("openapi_spec must contain 'paths' or 'openapi'/'swagger'")
        return s

    @field_validator("enabled_checks", mode="before")
    @classmethod
    def _validate_enabled_checks(cls, v: Any) -> list[str] | None:
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError("enabled_checks must be a list of check IDs")
        # Strip, drop empty, dedup preserving order, limit 50
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError(f"enabled_checks must be strings, got {type(item).__name__}")
            s = item.strip()
            if not s or s in seen:
                continue
            if len(s) > 64:
                raise ValueError(f"check ID too long: {s!r}")
            seen.add(s)
            cleaned.append(s)
        if len(cleaned) > 50:
            raise ValueError("enabled_checks: too many checks (max 50)")
        # Validate against known checks (fail fast, not silent skip)
        if cleaned:
            try:
                from redveil.plugins.loader import build_default_registry

                reg = build_default_registry()
                unknown = [c for c in cleaned if c not in reg]
                if unknown:
                    raise ValueError(
                        f"unknown check IDs: {', '.join(unknown)}. "
                        f"Use GET /api/checks to list valid IDs."
                    )
            except ValueError:
                raise
            except Exception:
                # If loader fails, skip validation (don't block scan)
                pass
        return cleaned if cleaned else None

    @model_validator(mode="after")
    def _check_destructive_consent(self) -> "ScanCreate":
        """Reject L3+ scans that lack explicit operator consent.

        L1/L2 (reconnaissance, light probing) is allowed without the
        allow_destructive flag — those actions are read-only by design.
        L3+ (active exploitation, persistence, takeover) MUST have
        allow_destructive=true. Without this check, the API accepts
        L3+ scans that the per-action gate later silently drops —
        the persisted Scan row would carry an authorization surface
        that does not match what actually ran.
        """
        # max_destructive_level is normalized to L# form by the field
        # validator above, so int(self.max_destructive_level[1:]) is safe.
        level_num = int(self.max_destructive_level[1:])
        if level_num >= 3 and not self.allow_destructive:
            raise ValueError(
                f"max_destructive_level={self.max_destructive_level} requires "
                f"allow_destructive=true. Destructive actions (L3+) cannot "
                f"be authorized without explicit operator consent. Set "
                f"allow_destructive=true to proceed, or lower "
                f"max_destructive_level to L2 or below."
            )
        return self


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
    # Phase A1: allowlist (None/empty = all)
    enabled_checks: list[str] | None = None
    # Phase A3: OpenAPI spec
    openapi_spec: str | None = None


class ScanStatus(BaseModel):
    """Lightweight status payload used for the SSE stream and quick polls."""

    id: int
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    total_requests: int
    error: str | None


class ScheduledScanCreate(BaseModel):
    target_id: int
    cron: str = Field(..., max_length=100, description='Cron "min hour day month weekday" e.g. "0 2 * * *"')
    profile: str = Field(default="passive", pattern=r"^(passive|low_impact|active)$")
    max_destructive_level: str = Field(default="L2", pattern=r"^L[1-6]$")
    allow_destructive: bool = False
    gate_mode: str = Field(default="non_interactive", pattern=r"^(interactive|non_interactive|strict)$")
    enabled: bool = True

    @field_validator("cron", mode="before")
    @classmethod
    def _validate_cron(cls, v: Any) -> str:
        from croniter import croniter

        if not isinstance(v, str) or not croniter.is_valid(v):
            raise ValueError(f"Invalid cron expression: {v!r} (expected 'm h dom mon dow' e.g. '0 2 * * *')")
        return v


class ScheduledScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    cron: str
    profile: str
    max_destructive_level: str
    allow_destructive: bool
    gate_mode: str
    enabled: bool
    created_at: datetime
    last_run_at: datetime | None
    next_run_at: datetime | None


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
    notes: str | None = None
    annotated_at: datetime | None = None


class FindingDetailOut(FindingOut):
    """Detailed finding view with evidence + raw finding payload."""

    fingerprint: str | None
    finding_data: dict[str, Any] = Field(default_factory=dict)


class FindingPatchIn(BaseModel):
    """PATCH body for operator annotations."""

    notes: str | None = Field(default=None, max_length=5000, description="Operator notes, max 5000 chars. Null/empty clears.")


class FindingPatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    wpoc_id: str
    notes: str | None
    annotated_at: datetime | None


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


# --- Probe Builder (Wave 14) -----------------------------------------------


class ProbeRunIn(BaseModel):
    """Request body for POST /api/probes/custom.

    The frontend builds this AFTER the operator types the DWYOR
    confirm string into the Gate 2 input. If confirmed_dwyor is
    false, the endpoint returns 403 and never invokes ProbeRunner.
    """

    target_id: int
    payloads: list[str] = Field(..., min_length=1, max_length=200)
    method: str = Field(default="GET", pattern=r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$")
    position: str = Field(default="", max_length=200)
    position_kind: str = Field(default="query", pattern=r"^(query|path|body)$")
    path_template: str | None = None  # used when position_kind="path"
    body_template: str | None = None  # used when position_kind="body"
    extra_headers: dict[str, str] | None = None
    confirmed_dwyor: bool = False
    attack_mode: str = Field(default="sniper", pattern=r"^(sniper|battering_ram|pitchfork|cluster_bomb)$")
    payloads2: list[str] | None = Field(default=None, description="Second payload list for pitchfork/cluster_bomb")
    position2: str | None = Field(default=None, description="Second position for battering_ram/pitchfork/cluster")
    payload_processors: list[str] | None = Field(default=None, description="Processors: url_encode, base64, hex, etc")
    preset_check_id: str | None = None  # if Preset mode, which check's set


class ProbeSampleOut(BaseModel):
    """One sample from a probe run — mirrors ReplaySample shape."""

    index: int
    payload: str
    status_code: int
    elapsed_ms: float
    body_length: int
    body_excerpt: str = ""
    error: str | None = None
    method: str
    target_url: str
    position: str
    started_at: str = ""


class ProbeRunOut(BaseModel):
    """Response body for POST /api/probes/custom."""

    probe_id: str
    target_id: int
    scan_id: int  # synthetic scan row for Evidence Log integration
    finding_wpoc_id: str  # synthetic finding carrying the evidence
    mode: str  # "preset" or "custom"
    method: str
    target_url: str
    total_requested: int
    total_executed: int
    skipped: int
    scope_rejections: int
    samples: list[ProbeSampleOut]
    started_at: str
    completed_at: str
