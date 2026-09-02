"""Scans endpoints: launch a scan, list, detail, SSE stream, findings, report."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

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


class EvidenceOut(BaseModel):
    """Evidence record surfaced for the Comparer + Evidence Log UI.

    The :class:`~redveil.evidence.evidence.Evidence` objects are kept in
    memory on the orchestrator; the scanner now persists them as JSON
    files under ``output_dir/evidence/`` so this endpoint can read them
    back. We surface:

    * ``evidence_id`` — taken from the ``evidence_ids`` list on the
      Finding, or the Evidence's own ``id`` when reading from disk.
    * ``finding_id`` — backref to the parent Finding.
    * ``status_code`` / ``timing_ms`` / ``body_excerpt`` / ``length`` —
      from the on-disk Evidence (or ``replay_recipe`` fallback for
      older scans that didn't persist).
    * ``check_id`` / ``timestamp`` / ``baseline_timing_ms`` — useful
      for the Evidence Log chronological view.
    """

    finding_id: str
    evidence_id: str
    title: str
    severity: str
    endpoint: str | None = None
    method: str | None = None
    status_code: int | None = None
    timing_ms: float | None = None
    baseline_timing_ms: float | None = None
    length: int | None = None
    body_excerpt: str | None = None
    input_used: str | None = None
    check_id: str | None = None
    timestamp: str | None = None


@router.get("/{scan_id}/evidence", response_model=list[EvidenceOut])
async def list_scan_evidence(
    scan_id: int,
    method: str | None = Query(None, description="Filter by HTTP method"),
    check_id: str | None = Query(None, description="Filter by check_id"),
    status_min: int | None = Query(None, ge=100, le=599),
    status_max: int | None = Query(None, ge=100, le=599),
    session: AsyncSession = Depends(get_session),
) -> list[EvidenceOut]:
    """Aggregate ``Evidence`` records for every finding of a scan.

    Prefers on-disk ``evidence/{EV-id}.json`` files (written by the
    scanner at scan-completion time) because they carry the full set
    of fields (status_code, timing_ms, baseline/control timing, etc.).
    Falls back to projecting from Finding payloads for older scans
    that predate the persistence path.

    Filters (method / check_id / status_min / status_max) are applied
    after loading so the in-memory filter is consistent regardless of
    which source produced the rows.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")

    rows: list[EvidenceOut] = []
    evidence_dir = Path(scan.output_dir) / "evidence" if scan.output_dir else None
    if evidence_dir and evidence_dir.exists():
        rows = _load_evidence_files(evidence_dir)
        # Newest first
        rows.sort(key=lambda r: r.evidence_id, reverse=True)

    if not rows:
        # Fall back to projecting from Finding payloads.
        result = await session.execute(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id.asc())
        )
        findings = list(result.scalars().all())

        # Fall back to the on-disk report if DB has no rows yet.
        if not findings and scan.output_dir:
            fpath = Path(scan.output_dir) / "findings.json"
            if fpath.exists():
                try:
                    findings = _load_findings_from_disk(fpath, scan_id)
                except Exception as e:  # noqa: BLE001
                    log.warning("failed to read on-disk findings.json: %s", e)
        elif not findings:
            # Try to discover a report dir on disk by scan-id prefix.
            fpath = _discover_findings_file(scan_id)
            if fpath is not None:
                try:
                    findings = _load_findings_from_disk(fpath, scan_id)
                except Exception as e:  # noqa: BLE001
                    log.warning("failed to read on-disk findings.json: %s", e)

        rows = _project_evidence(findings)

    if method:
        rows = [r for r in rows if (r.method or "").upper() == method.upper()]
    if check_id:
        rows = [r for r in rows if r.check_id == check_id]
    if status_min is not None:
        rows = [
            r for r in rows if r.status_code is not None and r.status_code >= status_min
        ]
    if status_max is not None:
        rows = [
            r for r in rows if r.status_code is not None and r.status_code <= status_max
        ]

    return rows


def _load_evidence_files(evidence_dir: Path) -> list[EvidenceOut]:
    """Read each ``*.json`` in ``evidence_dir`` and project to EvidenceOut.

    The on-disk schema is the Pydantic dump of the Evidence model — it
    carries every field the orchestrator captured. We map the most
    useful ones into the EvidenceOut projection used by the UI.
    """
    import json as _json

    out: list[EvidenceOut] = []
    if not evidence_dir.exists():
        return out
    for fp in sorted(evidence_dir.glob("*.json")):
        try:
            raw = _json.loads(fp.read_text())
        except (OSError, ValueError) as e:
            log.warning("failed to read evidence file %s: %s", fp, e)
            continue
        # The endpoint that produced this Evidence recorded which finding
        # it belongs to via ``finding_id``. Older runs may have only the
        # Evidence's own ``id`` (EV-xxxx); use it as a stable join key.
        ev_id = raw.get("id") or fp.stem
        target_method = (raw.get("method") or "GET").upper()
        out.append(
            EvidenceOut(
                finding_id=raw.get("finding_id") or "",
                evidence_id=str(ev_id),
                title="",  # Title comes from the Finding; not on Evidence.
                severity="info",
                endpoint=raw.get("endpoint") or "",
                method=target_method,
                status_code=raw.get("status_code"),
                timing_ms=raw.get("timing_ms"),
                baseline_timing_ms=raw.get("baseline_timing_ms"),
                length=raw.get("relevant_headers", {}).get("content-length"),
                body_excerpt=raw.get("body_excerpt") or "",
                input_used=raw.get("input_used"),
                check_id=raw.get("check_id"),
                timestamp=raw.get("timestamp"),
            )
        )
    return out


def _discover_findings_file(scan_id: int) -> Path | None:
    """Find ``findings.json`` under any ``scan-{id}-*`` dir on disk."""
    from redveil_api.scanner import OUTPUT_BASE_DIR

    if not OUTPUT_BASE_DIR.exists():
        return None
    prefix = f"scan-{scan_id}-"
    for d in OUTPUT_BASE_DIR.iterdir():
        if d.is_dir() and d.name.startswith(prefix):
            candidate = d / "findings.json"
            if candidate.exists():
                return candidate
    return None


def _load_findings_from_disk(path: Path, scan_id: int) -> list[Finding]:
    """Read findings.json and return FindingORM instances.

    The disk payload carries the full Finding dict; we map it back to
    the ORM shape so the projection logic below stays uniform.
    """
    import json as _json

    payload = _json.loads(path.read_text())
    items = payload.get("findings") or []
    rows: list[Finding] = []
    for item in items:
        wpoc_id = item.get("id") or ""
        rows.append(
            Finding(
                scan_id=scan_id,
                wpoc_id=wpoc_id,
                severity=item.get("severity", "info"),
                confidence=item.get("confidence", "tentative"),
                status=item.get("status", "discovered"),
                title=item.get("title", ""),
                endpoint=None,
                check_id=(item.get("check") or {}).get("id"),
                fingerprint=item.get("fingerprint"),
                finding_data=item,
            )
        )
    return rows


def _project_evidence(findings: list[Finding]) -> list[EvidenceOut]:
    """Project a list of Finding rows to the EvidenceOut shape."""
    out: list[EvidenceOut] = []
    for f in findings:
        data = f.finding_data or {}
        evidence_ids = data.get("evidence_ids") or []
        # replay_recipe carries the captured response fingerprint for
        # checks that publish one (e.g. session-cookie). It's optional.
        recipe = data.get("replay_recipe") or {}
        status_code = recipe.get("expected_status_code")
        timing_ms = recipe.get("expected_timing_ms")
        body_excerpt = recipe.get("expected_body_excerpt")
        body_length = recipe.get("expected_body_length")

        target = data.get("target") or {}
        endpoint = (
            f"{target.get('method', 'GET')} {target.get('scheme', 'https')}://"
            f"{target.get('host', '')}{target.get('endpoint', '')}"
            if target
            else f.endpoint
        )

        # If the Finding carries no evidence_ids we still emit one row
        # using the Finding's own id so the UI has something to display.
        ids = evidence_ids if evidence_ids else [f.wpoc_id]
        for eid in ids:
            out.append(
                EvidenceOut(
                    finding_id=f.wpoc_id,
                    evidence_id=str(eid),
                    title=f.title,
                    severity=f.severity,
                    endpoint=endpoint,
                    method=target.get("method") if target else None,
                    status_code=status_code,
                    timing_ms=timing_ms,
                    length=body_length,
                    body_excerpt=body_excerpt,
                    input_used=data.get("input_used"),
                )
            )
    return out


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
