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
