"""SQLAlchemy ORM models for the redveil API.

Three tables:
* targets   — what the user is scanning
* scans     — a single scan run against a target
* findings  — individual findings (PoCs) discovered during a scan
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redveil_ui.api.db import Base


def _now() -> datetime:
    return datetime.now(UTC)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(2048), unique=True, nullable=False, index=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=_now, nullable=False)

    scans: Mapped[list["Scan"]] = relationship(
        "Scan", back_populates="target", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Scan lifecycle status (0.2.0 spec §11.1): valid values are
    # "pending" | "running" | "completed" | "failed" | "cancelled".
    # Freeform String(32); no DB constraint. Cancelled is terminal.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    profile: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="standard")
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    output_dir: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    total_requests: Mapped[int] = mapped_column(default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Wave 3 follow-up: destructive level + gate mode
    max_destructive_level: Mapped[str] = mapped_column(
        String(4), nullable=False, default="L2"
    )
    allow_destructive: Mapped[bool] = mapped_column(default=False, nullable=False)
    gate_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="non_interactive"
    )
    # Phase A1: optional allowlist of check IDs (JSON, None/empty = all)
    enabled_checks: Mapped[list | None] = mapped_column(JSON, nullable=True, default=None)
    # Phase A3: optional OpenAPI spec content (Text, None/empty = none)
    openapi_spec: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    target: Mapped[Target] = relationship("Target", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    wpoc_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="tentative")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="discovered")
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    check_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    finding_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=_now, nullable=False)
    # 0.3.0 annotations: operator notes per finding
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    annotated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan", "scan_id"),
        Index("idx_findings_wpoc", "wpoc_id"),
    )


class AuditLog(Base):
    """Append-only operator-action audit trail (0.2.0 spec §7.2).

    Durable + queryable, distinct from the transient SSE stream. There
    is no UI/API delete path: the ONLY deletion is `redveil-ui auth
    audit-rotate` (retention window), which logs itself here.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(32), nullable=False)  # ISO 8601 UTC
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_meta: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    deny_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("idx_audit_ts", "ts"),)


class ScheduledScan(Base):
    """Cron-scheduled scan (0.3.0)."""

    __tablename__ = "scheduled_scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cron: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "0 2 * * *"
    profile: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")
    max_destructive_level: Mapped[str] = mapped_column(String(4), nullable=False, default="L2")
    allow_destructive: Mapped[bool] = mapped_column(default=False, nullable=False)
    gate_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="non_interactive")
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=_now, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(nullable=True)

    target: Mapped[Target] = relationship("Target")


class OpenApiSpec(Base):
    """Stored OpenAPI spec for management page /openapi (Phase C)."""

    __tablename__ = "openapi_specs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    spec: Mapped[str] = mapped_column(Text, nullable=False)  # raw yaml/json
    created_at: Mapped[datetime] = mapped_column(default=_now, nullable=False)
    parsed: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=None)  # {endpoints: [{method,path,params}]}


class SessionRuleSet(Base):
    """Singleton session rules config for /session-rules (Phase C)."""

    __tablename__ = "session_rule_sets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # SessionHandlingConfig dict
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now, nullable=False)


class AiConfigStore(Base):
    """Singleton AI gateway config for /ai (Phase C)."""

    __tablename__ = "ai_configs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # AiConfig dict
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now, nullable=False)
