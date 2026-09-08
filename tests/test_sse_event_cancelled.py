"""T2/T3: SSE dispatch + terminal-state check treat 'cancelled' correctly.

Covers spec §11.1.1 B7 (terminal check includes cancelled) and B8
(scan.cancelled event dispatch) by invoking the route's stream endpoint
against a scan row already in the cancelled state.
"""
import pytest
from fastapi.testclient import TestClient


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


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


async def test_cancelled_scan_streams_single_terminal_event(client, session):
    """A cancelled scan replays exactly one scan.cancelled event and closes."""
    from redveil_ui.api.event_bus import get_event_bus

    scan_id = await _mk_scan(session, "cancelled")

    with client.stream("GET", f"/api/scans/{scan_id}/stream") as resp:
        assert resp.status_code == 200
        body = b"".join(resp.iter_bytes()).decode()
    assert "scan.cancelled" in body
    assert body.count("scan.cancelled") == 1
    assert "scan.completed" not in body
    assert "scan.failed" not in body


async def test_completed_scan_does_not_emit_cancelled(client, session):
    """Terminal check: completed scans must not leak scan.cancelled."""
    scan_id = await _mk_scan(session, "completed")

    with client.stream("GET", f"/api/scans/{scan_id}/stream") as resp:
        body = b"".join(resp.iter_bytes()).decode()
    assert "scan.completed" in body
    assert "scan.cancelled" not in body
