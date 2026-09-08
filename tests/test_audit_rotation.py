"""redveil-ui auth audit-rotate — retention deletion (Task 4.6)."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from redveil_ui.cli import app


@pytest.fixture
def client():
    from redveil_ui.api.main import app as fastapi_app

    with TestClient_safe(fastapi_app) as c:
        yield c


def TestClient_safe(app):
    from fastapi.testclient import TestClient

    return TestClient(app)


def _mk_audit(ts: str, action: str = "scan.create") -> int:
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import AuditLog

    async def _make() -> int:
        factory = get_session_factory()
        async with factory() as s:
            row = AuditLog(
                ts=ts,
                actor="loopback",
                action=action,
                target_kind=None,
                target_id=None,
                request_meta="{}",
                result="allowed",
                deny_reason=None,
            )
            s.add(row)
            await s.commit()
            await s.refresh(row)
            return row.id

    return asyncio.run(_make())


def _count_rows() -> int:
    from sqlalchemy import func, select

    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import AuditLog

    async def _count() -> int:
        factory = get_session_factory()
        async with factory() as s:
            return await s.scalar(select(func.count()).select_from(AuditLog))

    return asyncio.run(_count())


def test_audit_rotate_deletes_old_and_logs_itself():
    old_ts = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    recent_ts = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    _mk_audit(old_ts)
    _mk_audit(recent_ts)
    before = _count_rows()
    assert before >= 2

    runner = CliRunner()
    result = runner.invoke(app, ["auth", "audit-rotate", "--days", "90"])
    assert result.exit_code == 0, result.output

    after = _count_rows()
    # 1 old row deleted, +1 audit.rotate self-log row → net unchanged.
    assert after == before
    assert "audit.rotate" in _all_actions()



def _all_actions():
    from sqlalchemy import select

    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import AuditLog

    async def _get():
        factory = get_session_factory()
        async with factory() as s:
            rows = list((await s.execute(select(AuditLog))).scalars().all())
            return [r.action for r in rows]

    return asyncio.run(_get())


def test_audit_rotate_respects_days_flag():
    mid_ts = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    _mk_audit(mid_ts)
    runner = CliRunner()
    result = runner.invoke(app, ["auth", "audit-rotate", "--days", "1"])
    assert result.exit_code == 0, result.output
    assert "audit.rotate" in _all_actions()
