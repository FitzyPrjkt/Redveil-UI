"""Audit write path carries @retry_on_lock (review note, Phase 1).

Claim under test: a transient 'database is locked' OperationalError on
the audit write does NOT lose the entry — the decorator retries and the
row lands. The DB in test runs is SHARED across the suite (conftest
points REDVEIL_DATA_DIR at data/), so exact-count assertions are
impossible; instead the tests snapshot the before-count for the action
and assert the delta — exactly one NEW row, none lost.
"""
import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from redveil_ui.api.db import get_session_factory
from redveil_ui.api.middleware import AuditLogMiddleware
from redveil_ui.api.models import AuditLog


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        yield c


async def _count_cancel_rows() -> int:
    factory = get_session_factory()
    async with factory() as s:
        rows = (
            await s.execute(select(AuditLog).where(AuditLog.action == "scan.cancel"))
        ).scalars().all()
        return len(list(rows))


def test_audit_write_retries_on_transient_lock(client, monkeypatch):
    """First commit raises 'database is locked', second succeeds.

    Patches AsyncSession.commit — NOT the middleware — so the retry
    path (the real @retry_on_lock wrapper around _write_entry) is what
    actually executes.
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    before = asyncio.run(_count_cancel_rows())
    marker = f"cancel-{uuid.uuid4().hex[:8]}"
    calls = {"n": 0}
    real_commit = AsyncSession.commit

    async def flaky_commit(self):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OperationalError(
                "INSERT INTO audit_log", {}, Exception("database is locked")
            )
        return await real_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", flaky_commit)

    resp = client.post(f"/api/scans/999999/{marker}/cancel")  # audited action, 404
    assert resp.status_code == 404

    # The write retried: commit was attempted more than once.
    assert calls["n"] >= 2, f"expected retry, commit attempted {calls['n']}x"

    # And the entry LANDED — exactly one new row (not lost, not duplicated).
    after = asyncio.run(_count_cancel_rows())
    assert after - before == 1


def test_audit_write_non_lock_errors_are_not_retried(client, monkeypatch):
    """A non-lock OperationalError must propagate immediately (no retry).

    The middleware's log-and-continue handler still shields the request,
    but the commit call count must stay at 1 — retrying programming
    errors would mask them.
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    before = asyncio.run(_count_cancel_rows())
    calls = {"n": 0}
    real_commit = AsyncSession.commit

    async def broken_commit(self):
        calls["n"] += 1
        raise OperationalError(
            "INSERT INTO audit_log", {}, Exception("no such table: audit_log")
        )

    monkeypatch.setattr(AsyncSession, "commit", broken_commit)

    resp = client.post("/api/scans/999999/cancel")
    # Request still succeeds — audit failures never take down the path.
    assert resp.status_code == 404
    # But NO retry happened for a non-lock error.
    assert calls["n"] == 1
    # And nothing was written.
    after = asyncio.run(_count_cancel_rows())
    assert after == before


def test_write_entry_is_wrapped_by_retry_decorator():
    """The decorator is on _write_entry itself (structural check).

    Guard against someone removing the decorator while keeping the
    behavioral tests above passing via a different code path.
    """
    wrapper = AuditLogMiddleware._write_entry
    assert getattr(wrapper, "__wrapped__", None) is not None, (
        "_write_entry lost its @retry_on_lock wrapper"
    )
    # functools.wraps preserves __name__ across the wrapper.
    assert getattr(wrapper, "__name__", "") == "_write_entry"
