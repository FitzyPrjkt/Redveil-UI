"""Findings endpoints: cross-scan list + per-finding detail + annotations."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_ui.api.db import get_session
from redveil_ui.api.models import Finding
from redveil_ui.api.schemas import FindingDetailOut, FindingOut, FindingPatchIn, FindingPatchOut

router = APIRouter()


@router.get("", response_model=list[FindingOut])
async def list_findings(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
    check_id: str | None = Query(None),
    scan_id: int | None = Query(None),
    include_fp: bool = Query(
        False,
        description=(
            "Include false_positive findings in the response. "
            "Default (false) hides them so the Findings list shows only "
            "actionable items. Pass true to surface FPs for audit / triage."
        ),
    ),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    stmt = select(Finding).order_by(Finding.id.desc()).offset(offset).limit(limit)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if check_id is not None:
        stmt = stmt.where(Finding.check_id == check_id)
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if not include_fp:
        # Default behavior: hide false_positive so the Findings list
        # shows only actionable items. Operators can pass include_fp=true
        # (or use the "show all" toggle in the UI) to surface FPs.
        stmt = stmt.where(Finding.status != "false_positive")
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{wpoc_id}", response_model=FindingDetailOut)
async def get_finding(wpoc_id: str, session: AsyncSession = Depends(get_session)) -> Finding:
    result = await session.execute(select(Finding).where(Finding.wpoc_id == wpoc_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@router.patch("/{wpoc_id}", response_model=FindingPatchOut)
async def patch_finding(
    wpoc_id: str, body: FindingPatchIn, session: AsyncSession = Depends(get_session)
) -> Finding:
    """Update operator notes for a finding (0.3.0 annotations)."""
    result = await session.execute(select(Finding).where(Finding.wpoc_id == wpoc_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    # Normalize: strip, None if empty
    notes = body.notes.strip() if body.notes and body.notes.strip() else None
    finding.notes = notes
    finding.annotated_at = datetime.now(UTC) if notes else None
    await session.commit()
    await session.refresh(finding)
    return finding
