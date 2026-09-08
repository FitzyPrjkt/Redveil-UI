import pytest
from datetime import datetime, timezone
from redveil_ui.api.models import Scan
from redveil_ui.api.scan_recovery import recover_orphan_scans

@pytest.mark.asyncio
async def test_recover_orphan_scans_transitions_running_to_failed(session):
    orphan = Scan(
        target_id=1,
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    session.add(orphan)
    await session.commit()
    await session.refresh(orphan)

    count = await recover_orphan_scans(session)

    assert count == 1
    await session.refresh(orphan)
    assert orphan.status == "failed"
    assert orphan.error.startswith("recovered from unclean shutdown at ")

@pytest.mark.asyncio
async def test_recover_orphan_scans_skips_terminal_states(session):
    completed = Scan(target_id=1, status="completed",
                     started_at=datetime.now(timezone.utc))
    failed = Scan(target_id=1, status="failed",
                  started_at=datetime.now(timezone.utc))
    session.add_all([completed, failed])
    await session.commit()

    count = await recover_orphan_scans(session)

    assert count == 0
