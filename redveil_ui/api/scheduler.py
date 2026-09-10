"""Scheduler for cron-based scans (0.3.0)."""
# Status handling covers: pending, running, completed, failed, cancelled (see scan_recovery)
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

log = logging.getLogger(__name__)

_scheduler = None  # AsyncIOScheduler


def _get_scheduler():
    global _scheduler
    if _scheduler is None:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        _scheduler = AsyncIOScheduler()
    return _scheduler


def start_scheduler():
    sched = _get_scheduler()
    if not sched.running:
        sched.start()
        log.info("Scheduler started")


def stop_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("Scheduler stopped")


def add_job(sched_row):
    """Add or update a cron job for a ScheduledScan row."""
    try:
        sched = _get_scheduler()
        job_id = f"schedule_{sched_row.id}"
        # Remove existing
        try:
            sched.remove_job(job_id)
        except Exception:
            pass
        if not sched_row.enabled:
            return
        from apscheduler.triggers.cron import CronTrigger

        trigger = CronTrigger.from_crontab(sched_row.cron)
        # Use lambda with scan creation; run_scheduled_scan will create scan row
        sched.add_job(
            lambda: asyncio.create_task(trigger_scan(sched_row.id)),
            trigger=trigger,
            id=job_id,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        log.info("Scheduled job %s cron=%s", job_id, sched_row.cron)
    except Exception as e:  # noqa: BLE001
        log.warning("Failed to add schedule %s: %s", sched_row.id, e)


def remove_job(schedule_id: int):
    try:
        sched = _get_scheduler()
        sched.remove_job(f"schedule_{schedule_id}")
    except Exception:
        pass


async def trigger_scan(schedule_id: int):
    """Cron trigger: create a scan row for the schedule."""
    from sqlalchemy import select
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan, ScheduledScan

    factory = get_session_factory()
    async with factory() as session:
        sched = await session.get(ScheduledScan, schedule_id)
        if sched is None or not sched.enabled:
            return
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
        # Update last/next
        sched.last_run_at = datetime.now(UTC)
        try:
            from croniter import croniter

            sched.next_run_at = croniter(sched.cron, datetime.now(UTC)).get_next(datetime)
        except Exception:
            pass
        await session.commit()
        scan_id = scan.id
    await run_scheduled_scan(scan_id, schedule_id)


async def run_scheduled_scan(scan_id: int, schedule_id: int):
    """Drive the scan via the scanner (like _drive_scan in scans.py)."""
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan, Target

    factory = get_session_factory()
    # Load scan + target
    async with factory() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        target = await session.get(Target, scan.target_id)
        if target is None:
            scan.status = "failed"
            scan.error = "target not found for scheduled scan"
            scan.completed_at = datetime.now(UTC)
            await session.commit()
            return
        # Update to running
        scan.status = "running"
        scan.started_at = datetime.now(UTC)
        await session.commit()
        target_url = target.url
        target_name = target.name
        scope_yaml = target.scope_yaml
        profile = scan.profile
        max_level = scan.max_destructive_level
        allow_dest = scan.allow_destructive
        gate_mode = scan.gate_mode

    # Run scanner
    try:
        from redveil_ui.api.db import get_session_factory as gsf
        from redveil_ui.api.main import app
        from redveil_ui.api.event_bus import get_event_bus

        # Get scanner from app state if available, else create one
        scanner = getattr(app.state, "scanner", None)
        if scanner is None:
            from redveil_ui.api.scanner import Scanner
            from redveil_ui.api.db import DATA_DIR

            scanner = Scanner(session_factory=gsf(), output_base_dir=DATA_DIR / "reports")

        bus = get_event_bus()
        final_error = None
        final_count = 0
        output_dir = None
        async for event in scanner.run_scan(
            target_url=target_url,
            scope_yaml=scope_yaml,
            profile=profile,
            scan_id=scan_id,
            target_name=target_name,
            max_destructive_level=max_level,
            allow_destructive=allow_dest,
            gate_mode=gate_mode,
        ):
            await bus.publish(scan_id, event)
            if event.get("event") == "scan.started":
                output_dir = (event.get("data") or {}).get("output_dir")
            elif event.get("event") == "scan.completed":
                output_dir = (event.get("data") or {}).get("output_dir", output_dir)
                final_count = (event.get("data") or {}).get("findings_count", 0)
            elif event.get("event") == "scan.failed":
                final_error = (event.get("data") or {}).get("error") or "scan failed"
        await bus.close(scan_id)
    except Exception as e:  # noqa: BLE001
        final_error = str(e)
        try:
            await bus.publish(scan_id, {"event": "scan.failed", "data": {"scan_id": scan_id, "error": final_error}})
            await bus.close(scan_id)
        except Exception:
            pass
    # Finalize
    factory = get_session_factory()
    async with factory() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        if final_error:
            scan.status = "failed"
            scan.error = final_error
        else:
            scan.status = "completed"
        scan.completed_at = datetime.now(UTC)
        if output_dir:
            scan.output_dir = output_dir
        scan.total_requests = final_count
        await session.commit()


async def load_schedules():
    """Load all enabled schedules from DB and register them. Called at startup."""
    try:
        from sqlalchemy import select
        from redveil_ui.api.db import get_session_factory
        from redveil_ui.api.models import ScheduledScan

        factory = get_session_factory()
        async with factory() as session:
            result = await session.execute(select(ScheduledScan).where(ScheduledScan.enabled == True))  # noqa: E712
            for sched in result.scalars().all():
                add_job(sched)
        start_scheduler()
    except Exception as e:  # noqa: BLE001
        log.warning("Failed to load schedules: %s", e)
