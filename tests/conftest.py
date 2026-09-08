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
