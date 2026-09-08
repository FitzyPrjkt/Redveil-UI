"""GET /healthz — per-status scan counts (spec §9)."""
import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def _mk_scans(statuses):
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan

    async def _make():
        factory = get_session_factory()
        ids = []
        async with factory() as s:
            for status in statuses:
                scan = Scan(target_id=1, status=status, profile="passive")
                s.add(scan)
                await s.flush()
                ids.append(scan.id)
            await s.commit()
        return ids

    return asyncio.run(_make())


def test_healthz_returns_all_five_status_counts(client):
    _mk_scans(["pending", "running", "completed", "failed", "cancelled"])
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    for status in ("pending", "running", "completed", "failed", "cancelled"):
        assert f"scans_{status}" in body, f"Missing scans_{status} in {body}"


def test_healthz_counts_are_accurate(client):
    before = client.get("/healthz").json()
    _mk_scans(["cancelled", "cancelled", "running"])
    after = client.get("/healthz").json()
    assert after["scans_cancelled"] == before["scans_cancelled"] + 2
    assert after["scans_running"] == before["scans_running"] + 1


def test_healthz_db_ok(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"
