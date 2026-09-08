"""Start/cancel against terminal states — 409 semantics (spec §14.2).

Covers: HTTP 409 (not 200/5xx), error substring naming the terminal
state, guidance toward POST /api/scans for /start conflicts, and the
invariant that terminal rows are never mutated by these calls.
"""
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


def _scan_status(scan_id: int) -> str:
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan

    async def _get() -> str:
        factory = get_session_factory()
        async with factory() as s:
            scan = await s.get(Scan, scan_id)
            return scan.status

    return asyncio.run(_get())


@pytest.mark.parametrize("status", ["completed", "failed", "cancelled"])
def test_start_terminal_conflicts(client, status):
    scan_id = _mk_scan(status)
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert f"terminal state '{status}'" in detail
    assert "POST /api/scans" in detail
    assert _scan_status(scan_id) == status


@pytest.mark.parametrize("status", ["completed", "failed"])
def test_cancel_terminal_conflicts_and_never_mutates(client, status):
    scan_id = _mk_scan(status)
    resp = client.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 409
    assert f"terminal state '{status}'" in resp.json()["detail"]
    assert _scan_status(scan_id) == status
