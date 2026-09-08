"""SQLAlchemy async engine + session dependency for the redveil-ui package.

The engine is created lazily on first `get_engine()` call, AFTER any
`server.py` code has set `DATA_DIR` (or the `REDVEIL_DATA_DIR` env var).
This is critical for the self-host installer where the data directory
is configured at runtime, not at import time.
"""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# Resolve DATA_DIR ONCE at module load, preferring env var. The engine
# factory uses this at engine-creation time.
_DATA_DIR_OVERRIDE = os.environ.get("REDVEIL_DATA_DIR")
DATA_DIR = (
    Path(_DATA_DIR_OVERRIDE).expanduser().resolve()
    if _DATA_DIR_OVERRIDE
    else (Path(__file__).parent.parent / "data")
)
DB_PATH = DATA_DIR / "redveil-ui.db"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# Importing the models module here (purely for its registration side
# effect) ensures that any code which does ``from redveil_ui.api.db
# import Base`` and then calls ``Base.metadata.create_all(...)`` will
# see Target, Scan, and Finding. Without this, ``create_all`` is a
# silent no-op because ``Base.metadata`` has no tables registered yet.
# The order matters: this import must come AFTER ``Base`` is defined
# and BEFORE the first ``create_all`` call.
from redveil_ui.api import models  # noqa: E402, F401  (registration side effect)


# Engine is created lazily so server.py can override DATA_DIR before
# any module that imports this file actually triggers a connection.
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine() -> AsyncEngine:
    return create_async_engine(
        DATABASE_URL,
        echo=False,
        future=True,
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


def set_engine_for_tests(engine: AsyncEngine) -> None:
    """Allow tests to inject a custom engine (e.g. in-memory)."""
    global _engine, _session_factory
    _engine = engine
    _session_factory = async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields a fresh AsyncSession per request."""
    factory = get_session_factory()
    async with factory() as session:
        yield session
