"""Retry decorator for SQLite 'database is locked' errors.

SQLite single-writer + concurrent readers can hit lock contention
under high write load. WAL mode + busy_timeout reduces the rate
but does not eliminate it. This decorator adds retry-with-backoff
as a defense-in-depth for write-heavy operations (evidence log,
audit log).
"""
import asyncio
import functools
from sqlalchemy.exc import OperationalError

def _is_lock_error(exc: Exception) -> bool:
    msg = str(exc)
    return "database is locked" in msg.lower()

def retry_on_lock(max_attempts: int = 3, base_delay: float = 0.05):
    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return await fn(*args, **kwargs)
                except OperationalError as exc:
                    if not _is_lock_error(exc):
                        raise
                    last_exc = exc
                    if attempt < max_attempts - 1:
                        # Exponential backoff: 50ms, 200ms, 500ms
                        delay = base_delay * (4 ** attempt)
                        await asyncio.sleep(delay)
            raise last_exc
        return wrapper
    return decorator
