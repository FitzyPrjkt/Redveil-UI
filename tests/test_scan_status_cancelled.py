"""T1: a scan row can carry status='cancelled' (freeform String(32))."""
from datetime import datetime, timezone

from redveil_ui.api.models import Scan


async def test_scan_can_have_cancelled_status(session):
    scan = Scan(
        target_id=1,
        status="cancelled",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    assert scan.status == "cancelled"


async def test_cancelled_survives_roundtrip(session):
    scan = Scan(target_id=1, status="cancelled")
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    assert scan.status == "cancelled"
    assert scan.completed_at is None  # no completed_at required for cancelled
