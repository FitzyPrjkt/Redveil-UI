"""Scans endpoints: launch a scan, list, detail, SSE stream, findings, report."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_api.db import get_session
from redveil_api.models import Finding, Scan, Target
from redveil_api.schemas import FindingOut, ScanCreate, ScanOut, ScanStatus
from redveil_api.sse import event_generator

router = APIRouter()


async def _get_scanner(request: Request):
    scanner = getattr(request.app.state, "scanner", None)
    if scanner is None:
        raise HTTPException(status_code=503, detail="scanner not initialized")
    return scanner


@router.post("", response_model=ScanStatus, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ScanStatus:
    """Start a new scan. Returns immediately with a `pending` status;
    the actual work happens in a background task fed by the SSE stream.
    """
    target = await session.get(Target, body.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")

    # Persist a 'pending' row first so /api/scans/{id} works immediately.
    scan = Scan(
        target_id=target.id,
        status="pending",
        profile=body.profile,
        scan_type="standard",
        output_dir=None,
        total_requests=0,
        max_destructive_level=body.max_destructive_level,
        allow_destructive=body.allow_destructive,
        gate_mode=body.gate_mode,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    scope_yaml = body.scope_yaml if body.scope_yaml is not None else target.scope_yaml

    # Kick off the orchestrator in the background.
    scanner = await _get_scanner(request)
    asyncio.create_task(
        _drive_scan(
            scanner=scanner,
            scan_id=scan.id,
            target_url=target.url,
            target_name=target.name,
            scope_yaml=scope_yaml,
            profile=body.profile,
            max_destructive_level=body.max_destructive_level,
            allow_destructive=body.allow_destructive,
            gate_mode=body.gate_mode,
        )
    )

    return ScanStatus(
        id=scan.id,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_requests=scan.total_requests,
        error=scan.error,
    )


async def _drive_scan(
    scanner,
    scan_id: int,
    target_url: str,
    target_name: str | None,
    scope_yaml: str | None,
    profile: str,
    max_destructive_level: str = "L2",
    allow_destructive: bool = False,
    gate_mode: str = "non_interactive",
) -> None:
    """Background task: update Scan row as the orchestrator runs."""
    from redveil_api.db import get_session_factory

    factory = get_session_factory()
    async with factory() as session:
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            scan.status = "running"
            scan.started_at = datetime.now(UTC)
            await session.commit()

    last_event: dict[str, Any] = {}
    output_dir: str | None = None
    final_error: str | None = None
    final_count = 0
    try:
        async for event in scanner.run_scan(
            target_url=target_url,
            scope_yaml=scope_yaml,
            profile=profile,
            scan_id=scan_id,
            target_name=target_name,
            max_destructive_level=max_destructive_level,
            allow_destructive=allow_destructive,
            gate_mode=gate_mode,
        ):
            last_event = event
            if event.get("event") == "scan.started":
                output_dir = (event.get("data") or {}).get("output_dir")
            elif event.get("event") == "scan.completed":
                output_dir = (event.get("data") or {}).get("output_dir", output_dir)
                final_count = (event.get("data") or {}).get("findings_count", 0)
            elif event.get("event") == "scan.failed":
                final_error = (
                    (event.get("data") or {}).get("error")
                    or "scan failed"
                )
    except Exception as e:  # noqa: BLE001
        final_error = str(e)

    async with factory() as session:
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            if final_error is not None:
                scan.status = "failed"
                scan.error = final_error
            else:
                scan.status = "completed"
            scan.completed_at = datetime.now(UTC)
            if output_dir:
                scan.output_dir = output_dir
            scan.total_requests = final_count
            await session.commit()


@router.get("", response_model=list[ScanOut])
async def list_scans(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    target_id: int | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> list[Scan]:
    stmt = select(Scan).order_by(Scan.id.desc()).offset(offset).limit(limit)
    if target_id is not None:
        stmt = stmt.where(Scan.target_id == target_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)) -> Scan:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: int, request: Request, session: AsyncSession = Depends(get_session)):
    """SSE stream of events for an in-flight scan.

    For completed scans we replay the relevant persisted state and close
    the stream. The DB is the source of truth for findings; the stream
    only carries live orchestration events.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")

    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    async def producer() -> None:
        if scan.status in ("completed", "failed"):
            await queue.put(
                {
                    "event": "scan.completed" if scan.status == "completed" else "scan.failed",
                    "data": {
                        "scan_id": scan_id,
                        "status": scan.status,
                        "findings_count": scan.total_requests,
                        "output_dir": scan.output_dir,
                        "error": scan.error,
                    },
                }
            )
            await queue.put(None)
        else:
            # Live stream — in this minimal impl we surface status immediately
            # and close. A real impl would subscribe to a running task.
            await queue.put(
                {
                    "event": "scan.started",
                    "data": {
                        "scan_id": scan_id,
                        "status": scan.status,
                        "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    },
                }
            )
            await queue.put(
                {
                    "event": "scan.completed",
                    "data": {"scan_id": scan_id, "status": scan.status},
                }
            )
            await queue.put(None)

    asyncio.create_task(producer())
    return event_generator(queue)


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def list_scan_findings(
    scan_id: int, session: AsyncSession = Depends(get_session)
) -> list[Finding]:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    result = await session.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id.asc())
    )
    return list(result.scalars().all())


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: int,
    format: str = Query("md", pattern="^(md|html|json)$"),
    session: AsyncSession = Depends(get_session),
):
    """Return the on-disk report for a completed scan."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if not scan.output_dir:
        raise HTTPException(status_code=404, detail="report not yet available")

    base = Path(scan.output_dir)
    if format == "md":
        path = base / "summary.md"
    elif format == "html":
        path = base / "report.html"
    else:
        path = base / "findings.json"

    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{path.name} not found")
    media_type = "text/markdown" if format == "md" else (
        "text/html" if format == "html" else "application/json"
    )
    return FileResponse(path, media_type=media_type, filename=path.name)
