"""OASTProvider abstraction — provider-agnostic OOB (clarification #2).

Core (ssrf etc) depends on this ABC, not on Interactsh directly. Interactsh
is an implementation/default (src/redveil/validation/oast_interactsh.py).
"""
from __future__ import annotations

import abc
import os
from dataclasses import dataclass
from typing import Any


@dataclass
class OASTRegistration:
    canary_url: str
    token: str
    provider: str = "interactsh"


class OASTProvider(abc.ABC):
    """Provider-agnostic OAST (Interactsh, custom, self-hosted)."""

    @abc.abstractmethod
    async def register(self) -> OASTRegistration:
        """Register a new canary and return its URL + token."""
        raise NotImplementedError

    @abc.abstractmethod
    async def poll(self, token: str) -> list[dict]:
        """Poll for events for token."""
        raise NotImplementedError

    @abc.abstractmethod
    async def verify(self, token: str) -> bool:
        """Verify that an interaction was received."""
        raise NotImplementedError

    async def close(self) -> None:
        pass


class NoopOASTProvider(OASTProvider):
    """No-op provider when OAST is disabled."""

    async def register(self) -> OASTRegistration:
        return OASTRegistration(canary_url="https://example.com/noop", token="noop")

    async def poll(self, token: str) -> list[dict]:
        return []

    async def verify(self, token: str) -> bool:
        return False


def build_oast_provider(config: Any) -> OASTProvider | None:
    """Build OASTProvider from RedVeilConfig (B3).

    Reads ``config.oast`` (OastConfig/dict) and ``config.authorization.out_of_band_callback_domain``.
    Returns None if OAST not configured (scan still runs, LIKELY only).
    Provider failure is isolated — caller must treat None as no-op.
    """
    if config is None:
        return None
    # Resolve authorization domain
    auth = getattr(config, "authorization", None)
    oob_domain: str | None = None
    if auth is not None:
        oob_domain = getattr(auth, "out_of_band_callback_domain", None)
    oast_cfg = getattr(config, "oast", None)

    # No OAST config and no OOB domain -> disabled
    if not oast_cfg and not oob_domain:
        return None

    # Normalize oast_cfg to dict-like
    provider_type = "interactsh"
    base_url: str | None = None
    api_key: str | None = None

    if isinstance(oast_cfg, dict):
        provider_type = oast_cfg.get("provider", "interactsh") or "interactsh"
        base_url = oast_cfg.get("base_url")
        api_key = oast_cfg.get("api_key")
        env = oast_cfg.get("api_key_env")
        if env:
            api_key = os.environ.get(env) or api_key
    elif oast_cfg is not None:
        # Pydantic OastConfig or object with attrs
        provider_type = getattr(oast_cfg, "provider", "interactsh") or "interactsh"
        base_url = getattr(oast_cfg, "base_url", None)
        api_key = getattr(oast_cfg, "api_key", None)
        # resolved_api_key handles env
        try:
            resolved = getattr(oast_cfg, "resolved_api_key", None)
            if callable(resolved):
                api_key = resolved() or api_key
            else:
                env = getattr(oast_cfg, "api_key_env", None)
                if env:
                    api_key = os.environ.get(env) or api_key
        except Exception:
            pass

    # Fallback base_url from OOB domain if not set in oast_cfg
    if not base_url:
        if oob_domain:
            if oob_domain.startswith("http://") or oob_domain.startswith("https://"):
                base_url = oob_domain
            else:
                base_url = f"https://{oob_domain}"
        else:
            base_url = "https://oast.fun"

    # Normalize base_url
    base_url = base_url.rstrip("/")

    # Build provider (only interactsh supported for now; custom maps to interactsh generic)
    try:
        from redveil.validation.oast_interactsh import InteractshOASTProvider

        return InteractshOASTProvider(base_url=base_url, api_key=api_key)
    except Exception:
        return None
