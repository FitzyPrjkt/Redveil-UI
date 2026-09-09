"""InteractshOAST — Interactsh as OASTProvider implementation (default)."""
from __future__ import annotations

import secrets
from typing import Any

import httpx

from redveil.validation.oast import OASTProvider, OASTRegistration


class InteractshOASTProvider(OASTProvider):
    """Interactsh provider — polls https://oast.fun or self-hosted base_url."""

    def __init__(self, base_url: str = "https://oast.fun", api_key: str | None = None, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def register(self) -> OASTRegistration:
        # For now, generate a canary via Interactsh register API if available,
        # else fallback to random subdomain under base_url
        token = secrets.token_hex(6)
        # Try Interactsh API
        try:
            headers: dict[str, str] = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            resp = await self._client.post(f"{self.base_url}/register", json={"token": token}, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                url = data.get("url") or data.get("canary_url") or f"https://{token}.{self.base_url.replace('https://','')}/"
                return OASTRegistration(canary_url=url, token=token, provider="interactsh")
        except Exception:
            pass
        # Fallback: canary as token.base_url
        host = self.base_url.replace("https://", "").replace("http://", "")
        return OASTRegistration(canary_url=f"https://{token}.{host}/", token=token, provider="interactsh")

    async def poll(self, token: str) -> list[dict[str, Any]]:
        try:
            headers: dict[str, str] = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            resp = await self._client.get(f"{self.base_url}/poll", params={"token": token}, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    return data.get("events") or data.get("data") or []
        except Exception:
            pass
        return []

    async def verify(self, token: str) -> bool:
        events = await self.poll(token)
        return len(events) > 0

    async def close(self) -> None:
        await self._client.aclose()
