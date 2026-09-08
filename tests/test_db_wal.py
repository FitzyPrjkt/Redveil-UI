import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from redveil_ui.api.db_wal import register_wal_pragma

@pytest.mark.asyncio
async def test_wal_pragma_set_on_connect(tmp_path):
    db_path = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    register_wal_pragma(engine)

    async with engine.connect() as conn:
        from sqlalchemy import text
        result = await conn.execute(text("PRAGMA journal_mode"))
        mode = result.scalar()
        assert mode.lower() == "wal", f"Expected WAL, got {mode}"

    await engine.dispose()
