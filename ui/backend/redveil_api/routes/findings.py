"""Findings endpoints: cross-scan list + per-finding detail."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_api.db import get_session
from redveil_api.models import Finding
from redveil_api.schemas import FindingDetailOut, FindingOut

router = APIRouter()


@router.get("", response_model=list[FindingOut])
async def list_findings(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
    check_id: str | None = Query(None),
    scan_id: int | None = Query(None),
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
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{wpoc_id}", response_model=FindingDetailOut)
async def get_finding(wpoc_id: str, session: AsyncSession = Depends(get_session)) -> Finding:
    result = await session.execute(select(Finding).where(Finding.wpoc_id == wpoc_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding
