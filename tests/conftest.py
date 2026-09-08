"""Pytest conftest — make redveil_ui.api importable from tests/."""
import os
import sys
from pathlib import Path

# Point the redveil-ui package at the existing data dir BEFORE any
# import that triggers `redveil_ui.api.db` module-load evaluation.
# Tests rely on target_id=1 being seeded in this DB.
_TEST_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
os.environ.setdefault("REDVEIL_DATA_DIR", str(_TEST_DATA_DIR))

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
# `redveil_ui` is the new top-level package (was `ui/backend/redveil_api`).
# `redveil_ui/` must be on sys.path so `from redveil_ui.api.X import Y` works.
REDVEIL_UI_PKG = ROOT / "redveil_ui"

for p in (str(SRC), str(REDVEIL_UI_PKG)):
    if p not in sys.path:
        sys.path.insert(0, p)


import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402


@pytest_asyncio.fixture
async def session(tmp_path):
    """A fresh AsyncSession bound to a per-test SQLite DB.

    Tables are created from the redveil_ui ORM metadata. Used by the
    0.2.0 backend tests (scan recovery, cancelled status, audit log).
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from redveil_ui.api.db import Base

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _seed_probe_target():
    """Seed target_id=1 into the app DB before each test that hits the API.

    test_probe_endpoint_wave14.py (and the e2e suite) have always relied
    on target_id=1 existing, but the seed lived only in a legacy
    data/redveil.db file on one machine — the pre-rename backend DB
    name. On any fresh clone / CI the file is absent and 4 probe tests
    404 on the target. Seed explicitly instead, with the same URL and
    scope_yaml the legacy row carried (scope excludes '/' so probes
    surface scope_rejections).

    Runs before the lifespan-managed app DB is used by a test; the app
    DB file is per-pytest-process (REDVEIL_DATA_DIR below), so the
    insert is idempotent across tests within a run.
    """
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine

    from redveil_ui.api.db import Base, get_engine, get_session_factory
    from redveil_ui.api.models import Target  # noqa: F401  (registration)

    # Idempotently ensure tables exist even if the test never entered the
    # app's lifespan (create_all is a no-op when they already exist).
    async with create_async_engine(str(get_engine().url)).begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = get_session_factory()
    async with factory() as s:
        existing = (
            await s.execute(select(Target).where(Target.id == 1))
        ).scalar_one_or_none()
        if existing is None:
            s.add(
                Target(
                    id=1,
                    url="https://staging.example.com",
                    name=None,
                    scope_yaml=(
                        "allowed_hosts:\n"
                        "  - staging.example.com\n"
                        "allowed_paths:\n"
                        "  - /api/*\n"
                        "  - /account/*\n"
                        "  - /public/*\n"
                        "excluded_paths:\n"
                        "  - /admin/*"
                    ),
                )
            )
            await s.commit()
