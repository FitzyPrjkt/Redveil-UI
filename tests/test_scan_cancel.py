"""POST /api/scans/{id}/cancel — happy path + idempotency (Task 4.2)."""
import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        yield c


def _mk_scan(status: str) -> int:
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


def test_cancel_idempotent_after_cancelled(client):
    """Second cancel on an already-cancelled scan → 200 idempotent."""
    scan_id = _mk_scan("cancelled")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 200
    assert resp.json()["idempotent"] is True
    resp2 = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp2.status_code == 200
    assert resp2.json()["idempotent"] is True


def test_cancel_response_shape(client):
    """The 202/200 payload carries status + scan_id (202 for dispatch)."""
    scan_id = _mk_scan("pending")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "cancelled"
    assert body["scan_id"] == scan_id
