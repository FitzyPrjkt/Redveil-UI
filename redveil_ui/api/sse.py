"""Server-Sent Events (SSE) helpers.

A small wrapper that turns an asyncio.Queue (or any async iterator of dicts)
into the wire format ``data: {json}\\n\\n`` and handles client disconnects.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any


def format_sse(event: str, data: dict[str, Any]) -> bytes:
    """Format a single SSE event.

    Wire format::

        event: <name>
        data: <json>
        \\n
    """
    payload = json.dumps(data, default=str)
    msg = f"event: {event}\ndata: {payload}\n\n"
    return msg.encode("utf-8")


async def event_generator(
    queue: asyncio.Queue[dict[str, Any] | None],
) -> AsyncIterator[bytes]:
    """Yield SSE frames from a queue until a None sentinel is received.

    The producer (a Scanner task) puts dicts shaped like
    ``{"event": "scan.started", "data": {...}}`` onto the queue. We translate
    them to the SSE wire format. A None sentinel terminates the stream.
    """
    while True:
        item = await queue.get()
        if item is None:
            # Final keep-alive close frame; client knows we're done.
            yield b": end-of-stream\n\n"
            return
        event_name = item.get("event", "message")
        event_data = item.get("data", {})
        try:
            yield format_sse(event_name, event_data)
        except (GeneratorExit, asyncio.CancelledError):
            # Client disconnected — propagate so the producer can stop.
            raise
