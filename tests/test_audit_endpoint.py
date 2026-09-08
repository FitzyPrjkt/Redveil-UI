"""GET /api/audit — read-only listing (Task 4.5)."""
import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def _mk_audit(action: str, result: str = "allowed") -> int:
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import AuditLog

    async def _make() -> int:
        factory = get_session_factory()
        async with factory() as s:
            row = AuditLog(
                ts="2026-09-08T12:00:00Z",
                actor="loopback",
                action=action,
                target_kind="scan",
                target_id="1",
                request_meta="{}",
                result=result,
                deny_reason=None,
            )
            s.add(row)
            await s.commit()
            await s.refresh(row)
            return row.id

    return asyncio.run(_make())


def test_audit_lists_entries_newest_first(client):
    _mk_audit("scan.create")
    _mk_audit("scan.cancel")
    resp = client.get("/api/audit")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) >= 2
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids, reverse=True)


def test_audit_filter_by_action(client):
    _mk_audit("probe.custom")
    resp = client.get("/api/audit?action=probe.custom")
    assert resp.status_code == 200
    rows = resp.json()
    assert rows
    assert all(r["action"] == "probe.custom" for r in rows)


def test_audit_filter_by_result(client):
    _mk_audit("probe.custom", result="denied")
    resp = client.get("/api/audit?result=denied")
    assert resp.status_code == 200
    rows = resp.json()
    assert rows
    assert all(r["result"] == "denied" for r in rows)


def test_audit_limit_cap(client):
    resp = client.get("/api/audit?limit=1000")
    assert resp.status_code == 422  # le=500 validation
