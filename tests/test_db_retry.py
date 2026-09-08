import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from sqlalchemy.exc import OperationalError
from redveil_ui.api.db_retry import retry_on_lock

@pytest.mark.asyncio
async def test_retry_on_lock_succeeds_after_two_failures():
    call_count = 0

    @retry_on_lock(max_attempts=3, base_delay=0.01)
    async def flaky_write():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise OperationalError("stmt", {}, Exception("database is locked"))
        return "ok"

    result = await flaky_write()
    assert result == "ok"
    assert call_count == 3

@pytest.mark.asyncio
async def test_retry_on_lock_raises_after_max_attempts():
    @retry_on_lock(max_attempts=2, base_delay=0.01)
    async def always_locked():
        raise OperationalError("stmt", {}, Exception("database is locked"))

    with pytest.raises(OperationalError):
        await always_locked()

@pytest.mark.asyncio
async def test_retry_on_lock_does_not_retry_other_errors():
    call_count = 0

    @retry_on_lock(max_attempts=3, base_delay=0.01)
    async def other_error():
        nonlocal call_count
        call_count += 1
        raise OperationalError("stmt", {}, Exception("some other error"))

    with pytest.raises(OperationalError):
        await other_error()
    assert call_count == 1  # No retry for non-lock errors
