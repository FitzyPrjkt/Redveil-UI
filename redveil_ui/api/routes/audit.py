"""GET /api/audit — read-only listing of the audit trail (Task 4.5).

Read-only and unauthenticated (reading your own audit log is not a
destructive action, spec §7.2). Append-only: there is no delete route;
retention is the CLI `auth audit-rotate` only.
"""
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_ui.api.db import get_session
from redveil_ui.api.models import AuditLog

router = APIRouter()


class AuditEntryOut(BaseModel):
    id: int
    ts: str
    actor: str
    action: str
    target_kind: str | None = None
    target_id: str | None = None
    request_meta: str | None = None
    result: str
    deny_reason: str | None = None

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AuditEntryOut])
async def list_audit_entries(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, description="Filter by action"),
    result: str | None = Query(None, description="allowed | denied"),
    session: AsyncSession = Depends(get_session),
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(limit)
    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    if result is not None:
        stmt = stmt.where(AuditLog.result == result)
    rows = await session.execute(stmt)
    return list(rows.scalars().all())
