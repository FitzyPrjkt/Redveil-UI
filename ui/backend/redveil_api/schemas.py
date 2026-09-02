"""Pydantic v2 request/response schemas for the redveil API.

All ORM-mapped schemas use ``ConfigDict(from_attributes=True)`` so they can
be built directly from SQLAlchemy ORM objects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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
