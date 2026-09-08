"""WAL + busy_timeout pragma for SQLite connections.

Attach via register_wal_pragma(engine) BEFORE any session is created.
journal_mode=WAL is persistent at the file level once set, but we
re-issue on every connect for safety under connection reuse and forks.
busy_timeout is per-connection and must be re-issued.
"""
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

_WAL_PRAGMAS = (
    "PRAGMA journal_mode = WAL",
    "PRAGMA busy_timeout = 5000",
    "PRAGMA synchronous = NORMAL",  # WAL + NORMAL is the recommended combo
)

def register_wal_pragma(engine: AsyncEngine) -> None:
    @event.listens_for(engine.sync_engine, "connect")
    def _set_pragmas(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        for pragma in _WAL_PRAGMAS:
            cursor.execute(pragma)
        cursor.close()
