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

from redveil_api.db import Base


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
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    profile: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="standard")
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    output_dir: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    total_requests: Mapped[int] = mapped_column(default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

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

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan", "scan_id"),
        Index("idx_findings_wpoc", "wpoc_id"),
    )
