"""Cancel of an already-terminal scan → 409, DB unchanged (spec §14.2)."""
import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
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


def test_cancel_completed_returns_409_and_keeps_status(client):
    scan_id = _mk_scan("completed")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 409
    body = resp.json()
    assert "terminal state 'completed'" in body["detail"]


def test_cancel_failed_returns_409_and_keeps_status(client):
    scan_id = _mk_scan("failed")
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 409
    assert "terminal state 'failed'" in resp.json()["detail"]
