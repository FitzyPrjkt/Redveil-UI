"""POST /api/scans/{id}/start and /cancel — spec §5.5 response matrix.

Scan rows are inserted through the APP's engine (the routes read via
get_session), on a dedicated event loop per test — TestClient runs its
own loop internally, so DB setup uses asyncio.run() on the caller side.

The TestClient fakes a loopback direct peer (client=127.0.0.1): the
0.2.0 /start gate 401s unauthenticated LAN callers for destructive
rows (see test_scan_start_auth_gate.py); here we assert the response
matrix itself.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        yield c


def _mk_scan(status: str) -> int:
    """Insert a scan row in `status` via the app's engine; return its id."""
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan

    async def _make() -> int:
        factory = get_session_factory()
        async with factory() as s:
            scan = Scan(target_id=1, status=status, profile="passive")
            s.add(scan)
            await s.commit()
            await s.refresh(scan)
            return scan.id

    return asyncio.run(_make())


def _scan_status(scan_id: int) -> str:
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan

    async def _get() -> str:
        factory = get_session_factory()
        async with factory() as s:
            scan = await s.get(Scan, scan_id)
            return scan.status

    return asyncio.run(_get())


# --- /start -----------------------------------------------------------------


def test_start_pending_dispatches_running(client):
    """Pending scan + /start → 202 Accepted (dispatch) with running."""
    scan_id = _mk_scan("pending")
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "running"
    assert body["scan_id"] == scan_id


def test_start_running_is_idempotent(client):
    """Running scan + /start → 200 with idempotent: true."""
    scan_id = _mk_scan("running")
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 200
    assert resp.json()["idempotent"] is True


def test_start_completed_conflicts(client):
    """Completed scan + /start → 409 with terminal-state detail."""
    scan_id = _mk_scan("completed")
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 409
    assert "terminal state 'completed'" in resp.json()["detail"]
    assert "Create a new scan" in resp.json()["detail"]


def test_start_failed_conflicts(client):
    scan_id = _mk_scan("failed")
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 409
    assert "terminal state 'failed'" in resp.json()["detail"]


def test_start_cancelled_conflicts(client):
    scan_id = _mk_scan("cancelled")
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 409
    assert "terminal state 'cancelled'" in resp.json()["detail"]


def test_start_unknown_scan_404(client):
    resp = client.post("/api/scans/999999/start")
    assert resp.status_code == 404


# --- /cancel ----------------------------------------------------------------


def test_cancel_completed_conflicts_with_timestamps(client):
    """Completed scan + /cancel → 409 carrying started/completed times."""
    scan_id = _mk_scan("completed")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert "terminal state 'completed'" in detail
    assert "started" in detail and "completed" in detail
    # Status MUST NOT change (cancel of terminal state is a no-op)
    assert _scan_status(scan_id) == "completed"


def test_cancel_failed_conflicts(client):
    scan_id = _mk_scan("failed")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 409
    assert "terminal state 'failed'" in resp.json()["detail"]
    assert _scan_status(scan_id) == "failed"


def test_cancel_pending_marks_cancelled(client):
    """Pending scan + /cancel → 202 dispatch, row flips to cancelled."""
    scan_id = _mk_scan("pending")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "cancelled"
    assert body.get("idempotent") is not True
    assert _scan_status(scan_id) == "cancelled"


def test_cancel_cancelled_is_idempotent(client):
    """Cancelled scan + /cancel → 200 with idempotent: true."""
    scan_id = _mk_scan("cancelled")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 200
    assert resp.json()["idempotent"] is True


def test_cancel_unknown_scan_404(client):
    resp = client.post("/api/scans/999999/cancel")
    assert resp.status_code == 404
