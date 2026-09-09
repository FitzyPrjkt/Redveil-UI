"""OASTProvider abstraction — provider-agnostic OOB (clarification #2).

Core (ssrf etc) depends on this ABC, not on Interactsh directly. Interactsh
is an implementation/default (src/redveil/validation/oast_interactsh.py).
"""
from __future__ import annotations

import abc
from dataclasses import dataclass


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
