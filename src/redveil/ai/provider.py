"""AIProvider ABC — protocol-neutral unified interface (A5 P1).

Core workflow (Analysis → Hypothesis → Validator) depends on this ABC, not on
openai/anthropic directly. Adapters preserve protocol semantics (tools,
structured, streaming, vision, response normalization) per clarification #3.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from redveil.ai.config import AiConfig, AiProviderConfig


@dataclass
class AIResponse:
    """Normalized response from any gateway (OpenAI or Anthropic)."""

    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    model: str = ""
    finish_reason: str | None = None


class AIProvider(abc.ABC):
    """Protocol-neutral provider. Adapters implement complete()."""

    def __init__(self, config: AiProviderConfig, capabilities: Any | None = None):
        self.config = config
        self.capabilities = capabilities

    @abc.abstractmethod
    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        images: list[dict[str, Any]] | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> AIResponse:
        """Send messages to gateway and return normalized AIResponse.

        * messages: [{"role": "system"|"user"|"assistant", "content": str}]
        * tools: OpenAI/Anthropic tool schemas (adapter normalizes)
        * response_format: {"type": "json_schema", "json_schema": {...}} or {"type":"json_object"}
        * images: [{"type":"image_url","image_url":{"url": "data:image/..."}}] for vision
        """
        raise NotImplementedError

    async def close(self) -> None:
        """Optional cleanup (httpx client)."""
        pass


def build_ai_provider(ai_config: AiConfig) -> AIProvider | None:
    """Factory — returns adapter based on protocol, or None if disabled/no provider."""
    if not ai_config.enabled or not ai_config.provider:
        return None
    cfg = ai_config.provider
    # Resolve adapter by protocol, not by type (clarification #3)
    if cfg.protocol == "anthropic":
        from redveil.ai.adapters.anthropic import AnthropicAdapter

        return AnthropicAdapter(cfg, ai_config.capabilities)
    # Default: openai (covers openai, openai_compatible, custom with openai protocol)
    # Also handles openai_compatible with anthropic protocol? Already handled above.
    from redveil.ai.adapters.openai_compatible import OpenAICompatibleAdapter

    # If type is openai and protocol openai, use OpenAIAdapter for stricter handling,
    # otherwise generic compatible
    if cfg.type == "openai" and cfg.protocol == "openai":
        try:
            from redveil.ai.adapters.openai import OpenAIAdapter

            return OpenAIAdapter(cfg, ai_config.capabilities)
        except ImportError:
            pass
    return OpenAICompatibleAdapter(cfg, ai_config.capabilities)
