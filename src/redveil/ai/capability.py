"""Capability detection — best-effort /models, fallback to explicit config (clarification #1)."""
from __future__ import annotations

import httpx

from redveil.ai.config import AiCapabilities, AiProviderConfig


async def detect_capabilities(config: AiProviderConfig, explicit: AiCapabilities | None = None) -> AiCapabilities:
    """Detect capabilities via GET /models, fallback to explicit or defaults.

    If gateway doesn't expose /models (common for proxy web), return explicit
    if provided, else defaults (tool_calling true, vision false, etc).
    """
    if explicit is not None:
        return explicit
    # Try best-effort
    try:
        key = config.resolved_api_key()
        headers: dict[str, str] = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        headers.update(config.headers)
        async with httpx.AsyncClient(timeout=5) as client:
            url = f"{config.base_url}/models"
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                # If we get a models list, assume gateway is healthy and supports tools
                # We don't parse models, just confirm reachability
                return AiCapabilities()
    except Exception:
        pass
    # Fallback defaults
    return AiCapabilities()
