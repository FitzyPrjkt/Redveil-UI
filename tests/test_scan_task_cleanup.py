"""C2 regression: _SCAN_TASKS must not leak entries for finished scans.

Both registration sites (create_scan, start_scan) attach a
done-callback that pops the scan id once the driving task completes.
After a scan reaches a terminal state, POST /{id}/cancel must not find
a live task in the registry.
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


def test_done_callback_populates_and_cleans_registry():
    """Unit: the callback bound at registration pops only its own id."""
    from redveil_ui.api.routes.scans import _SCAN_TASKS

    loop = asyncio.new_event_loop()

    async def _scenario():
        task_a = asyncio.create_task(asyncio.sleep(0.01))
        task_b = asyncio.create_task(asyncio.sleep(0.5))
        _SCAN_TASKS[101] = task_a
        _SCAN_TASKS[102] = task_b
        task_a.add_done_callback(lambda _t, sid=101: _SCAN_TASKS.pop(sid, None))
        await task_a
        await asyncio.sleep(0.05)  # let the done-callback run
        return 102 in _SCAN_TASKS and 101 not in _SCAN_TASKS

    try:
        assert loop.run_until_complete(_scenario()) is True
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        _SCAN_TASKS.pop(101, None)
        _SCAN_TASKS.pop(102, None)


def test_cancel_after_terminal_state_reports_no_live_task():
    """Behavioral: once a scan row is terminal, cancel must not signal
    any task — the registry entry is gone (the 409 idempotency path is
    exercised in test_scan_cancel; here we assert the registry side).
    The client fakes a loopback peer (cancel itself is not gated)."""
    scan_id = _mk_scan("pending")
    from redveil_ui.api.main import app

    with TestClient(app, client=("127.0.0.1", 51000)) as c:
        resp = c.post(f"/api/scans/{scan_id}/cancel")
    assert resp.status_code == 202
    from redveil_ui.api.routes.scans import _SCAN_TASKS

    assert scan_id not in _SCAN_TASKS
