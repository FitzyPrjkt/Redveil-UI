"""OpenAIAdapter — Chat Completions / Responses (strict, for type=openai)."""
from __future__ import annotations

import os
from typing import Any

import httpx

from redveil.ai.config import AiCapabilities, AiProviderConfig
from redveil.ai.provider import AIProvider, AIResponse


class OpenAIAdapter(AIProvider):
    """Strict OpenAI Chat Completions adapter."""

    def __init__(self, config: AiProviderConfig, capabilities: AiCapabilities | None = None):
        super().__init__(config, capabilities)
        self._client = httpx.AsyncClient(timeout=config.timeout)

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        images: list[dict[str, Any]] | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> AIResponse:
        key = self.config.resolved_api_key()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        headers.update(self.config.headers)

        # Handle images via content array for vision
        payload_messages: list[dict[str, Any]] = []
        for m in messages:
            if images and m.get("role") == "user":
                content: list[dict[str, Any]] = [{"type": "text", "text": m.get("content", "")}]
                for img in images:
                    content.append(img)
                payload_messages.append({"role": m["role"], "content": content})
            else:
                payload_messages.append(m)

        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": payload_messages,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = kwargs.get("tool_choice", "auto")
        if response_format:
            body["response_format"] = response_format
        if stream:
            body["stream"] = True
        if self.config.extra_body:
            body.update(self.config.extra_body)

        url = f"{self.config.base_url}/chat/completions"
        resp = await self._client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        # Normalize
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        text = msg.get("content") or ""
        tool_calls = msg.get("tool_calls") or []
        usage = data.get("usage") or {}
        return AIResponse(
            text=text,
            tool_calls=tool_calls,
            usage=usage,
            raw=data,
            model=data.get("model") or self.config.model,
            finish_reason=choice.get("finish_reason"),
        )

    async def close(self) -> None:
        await self._client.aclose()
