"""Per-scan pub-sub used by the SSE stream endpoint.

`_drive_scan` is the sole owner of the live orchestrator event stream.
The HTTP SSE endpoint needs to observe those same events without
re-running the orchestrator. This module provides a tiny per-scan
pub-sub: any number of SSE clients can ``subscribe(scan_id)`` and
receive the same events that the orchestrator publishes. Subscribers
get ``None`` as a sentinel when the scan terminates.

This is intentionally in-memory only — events are ephemeral and the
DB is the source of truth for findings. A server restart cleanly
forgets in-flight events; SSE clients that reconnect after a restart
see a fresh stream sourced from the latest persisted state.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class _ScanChannel:
    """All subscribers for a single scan_id."""

    def __init__(self) -> None:
        self.subscribers: set[asyncio.Queue[dict[str, Any] | None]] = set()
        self.closed: bool = False


class ScanEventBus:
    """In-process pub-sub keyed by scan_id."""

    def __init__(self) -> None:
        self._channels: dict[int, _ScanChannel] = defaultdict(_ScanChannel)

    def subscribe(self, scan_id: int) -> asyncio.Queue[dict[str, Any] | None]:
        """Register a new subscriber. The queue receives events until
        ``close(scan_id)`` is called for this scan_id, at which point
        ``None`` is enqueued and the channel is torn down.
        """
        ch = self._channels[scan_id]
        q: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        ch.subscribers.add(q)
        return q

    def unsubscribe(self, scan_id: int, q: asyncio.Queue) -> None:
        ch = self._channels.get(scan_id)
        if ch is None:
            return
        ch.subscribers.discard(q)
        if not ch.subscribers and ch.closed:
            # Channel is closed and empty — clean it up.
            self._channels.pop(scan_id, None)

    async def publish(self, scan_id: int, event: dict[str, Any]) -> None:
        ch = self._channels.get(scan_id)
        if ch is None or ch.closed:
            return
        # Snapshot the subscriber set so a subscriber that disconnects
        # mid-fanout doesn't blow up the publisher.
        for q in list(ch.subscribers):
            try:
                await q.put(event)
            except Exception:  # noqa: BLE001
                # Subscriber queue is broken — drop it quietly.
                ch.subscribers.discard(q)

    async def close(self, scan_id: int) -> None:
        """Send None to every subscriber of ``scan_id`` and tear down
        the channel. Idempotent.
        """
        ch = self._channels.get(scan_id)
        if ch is None:
            return
        ch.closed = True
        for q in list(ch.subscribers):
            try:
                await q.put(None)
            except Exception:  # noqa: BLE001
                pass
        self._channels.pop(scan_id, None)


# Process-wide singleton. The bus is per-process, which matches
# uvicorn's single-worker self-host model. Multi-worker deploys would
# need a shared pub-sub (e.g. Redis pub/sub) — out of scope for the
# self-host installer.
_bus = ScanEventBus()


def get_event_bus() -> ScanEventBus:
    return _bus


__all__ = ["ScanEventBus", "get_event_bus"]
