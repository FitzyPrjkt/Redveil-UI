"""SQLAlchemy async engine + session dependency for the redveil API.

Uses aiosqlite. The DB file lives at /workspace/projects/Redveil/data/redveil.db
so it survives a process restart and can be shared with the CLI scanner.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

DATA_DIR = Path("/workspace/projects/Redveil/data")
DB_PATH = DATA_DIR / "redveil.db"

# Make sure the parent directory exists before we hand the URL to SQLAlchemy.
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# Engine is created lazily so tests can swap it out via get_engine()/set_engine().
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            DATABASE_URL,
            echo=False,
            future=True,
        )
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
