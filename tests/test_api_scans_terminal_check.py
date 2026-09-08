"""T3: the terminal-state check treats 'cancelled' as terminal (B7).

The stream endpoint's replay branch is the B7 site: it must route
cancelled scans to the terminal snapshot (single event, no live
subscribe), and must NOT re-emit or double-emit terminal events.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


async def _mk_scan(_unused_session, status):
    """Insert via the APP's engine (routes read through get_session)."""
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan

    factory = get_session_factory()
    async with factory() as s:
        scan = Scan(target_id=1, status=status)
        s.add(scan)
        await s.commit()
        await s.refresh(scan)
        scan_id = scan.id
    return scan_id


async def test_terminal_check_includes_cancelled(client, session):
    scan_id = await _mk_scan(session, "cancelled")
    with client.stream("GET", f"/api/scans/{scan_id}/stream") as resp:
        body = b"".join(resp.iter_bytes()).decode()
    # Terminal snapshot: exactly one event line then end-of-stream marker
    events = [l for l in body.splitlines() if l.startswith("event:")]
    assert len(events) == 1
    assert events[0] == "event: scan.cancelled"
    assert ": end-of-stream" in body


async def test_failed_scan_still_terminal(client, session):
    """Pre-existing behavior preserved: failed stays scan.failed."""
    scan_id = await _mk_scan(session, "failed")
    with client.stream("GET", f"/api/scans/{scan_id}/stream") as resp:
        body = b"".join(resp.iter_bytes()).decode()
    assert "event: scan.failed" in body
