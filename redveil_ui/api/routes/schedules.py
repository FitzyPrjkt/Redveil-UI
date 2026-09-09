"""Scheduled scans: cron-based auto scans (0.3.0)."""
from __future__ import annotations

from datetime import UTC, datetime

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_ui.api.db import get_session
from redveil_ui.api.models import ScheduledScan, Target
from redveil_ui.api.schemas import ScheduledScanCreate, ScheduledScanOut

router = APIRouter()


def _next_run(cron: str) -> datetime:
    return croniter(cron, datetime.now(UTC)).get_next(datetime)


@router.get("", response_model=list[ScheduledScanOut])
async def list_schedules(session: AsyncSession = Depends(get_session)) -> list[ScheduledScan]:
    result = await session.execute(select(ScheduledScan).order_by(ScheduledScan.id.desc()))
    return list(result.scalars().all())


@router.post("", response_model=ScheduledScanOut, status_code=201)
async def create_schedule(body: ScheduledScanCreate, session: AsyncSession = Depends(get_session)) -> ScheduledScan:
    target = await session.get(Target, body.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")
    sched = ScheduledScan(
        target_id=body.target_id,
        cron=body.cron,
        profile=body.profile,
        max_destructive_level=body.max_destructive_level,
        allow_destructive=body.allow_destructive,
        gate_mode=body.gate_mode,
        enabled=body.enabled,
        next_run_at=_next_run(body.cron) if body.enabled else None,
    )
    session.add(sched)
    await session.commit()
    await session.refresh(sched)
    # Register with scheduler if running
    try:
        from redveil_ui.api.scheduler import add_job

        add_job(sched)
    except Exception:
        pass
    return sched


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: int, session: AsyncSession = Depends(get_session)):
    sched = await session.get(ScheduledScan, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    try:
        from redveil_ui.api.scheduler import remove_job

        remove_job(schedule_id)
    except Exception:
        pass
    await session.delete(sched)
    await session.commit()
    return None


@router.post("/{schedule_id}/trigger", response_model=dict)
async def trigger_schedule(schedule_id: int, session: AsyncSession = Depends(get_session)):
    sched = await session.get(ScheduledScan, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    # Create a scan immediately (same as scheduled run)
    from redveil_ui.api.models import Scan
    from redveil_ui.api.scheduler import run_scheduled_scan

    scan = Scan(
        target_id=sched.target_id,
        status="pending",
        profile=sched.profile,
        max_destructive_level=sched.max_destructive_level,
        allow_destructive=sched.allow_destructive,
        gate_mode=sched.gate_mode,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    # Fire async
    import asyncio

    asyncio.create_task(run_scheduled_scan(scan.id, sched.id))
    return {"scan_id": scan.id, "schedule_id": sched.id}
