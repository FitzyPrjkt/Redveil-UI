"""Recover scans left in 'running' state by a previous unclean shutdown.

Called once at server startup before the FastAPI app begins accepting
requests. Transitions all running scans to failed with a recovery
prefix in the error message so they can be distinguished from
genuine runtime failures.
"""
import logging
from datetime import datetime, timezone
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from redveil_ui.api.models import Scan

log = logging.getLogger(__name__)

RECOVERY_PREFIX = "recovered from unclean shutdown at "

async def recover_orphan_scans(session: AsyncSession) -> int:
    now = datetime.now(timezone.utc).isoformat()
    stmt = (
        update(Scan)
        .where(Scan.status == "running")
        .values(
            status="failed",
            error=f"{RECOVERY_PREFIX}{now}",
            completed_at=datetime.now(timezone.utc),
        )
        .returning(Scan.id)
    )
    result = await session.execute(stmt)
    recovered_ids = [row[0] for row in result.fetchall()]
    await session.commit()

    if recovered_ids:
        log.warning(
            "scan_recovery: transitioned %d orphan scan(s) to failed: %s",
            len(recovered_ids), recovered_ids,
        )
    return len(recovered_ids)
