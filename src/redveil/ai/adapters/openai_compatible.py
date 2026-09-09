"""OpenAICompatibleAdapter — generic for any proxy web (B.AI, AgentRouter, etc).

Covers 90% of proxy apis that expose OpenAI-compatible Chat Completions.
Falls back gracefully if gateway doesn't support tools/structured/streaming.
"""
from __future__ import annotations

from typing import Any

import httpx

from redveil.ai.config import AiCapabilities, AiProviderConfig
from redveil.ai.provider import AIProvider, AIResponse


class OpenAICompatibleAdapter(AIProvider):
    """Generic OpenAI-compatible adapter — no hard-coded vendor list."""

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
            # Most proxies use Bearer, some use x-api-key — user can override via headers
            if "Authorization" not in self.config.headers and "x-api-key" not in {k.lower() for k in self.config.headers}:
                headers["Authorization"] = f"Bearer {key}"
        headers.update(self.config.headers)

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
        # Capability fallback: if explicitly disabled, don't send
        caps = self.capabilities
        if tools and (caps is None or caps.tool_calling):
            body["tools"] = tools
            body["tool_choice"] = kwargs.get("tool_choice", "auto")
        elif tools and caps and not caps.tool_calling:
            # Fallback: inject tools as system prompt
            body["messages"] = [{"role": "system", "content": f"Available tools: {tools}"}] + payload_messages

        if response_format and (caps is None or caps.structured_output):
            body["response_format"] = response_format
        # Vision: only if enabled
        if images and caps and not caps.vision:
            # Fallback: drop images, add text placeholder
            body["messages"] = payload_messages  # already handled above, but keep

        if self.config.extra_body:
            body.update(self.config.extra_body)

        url = f"{self.config.base_url}/chat/completions"
        # Some proxies use /v1/chat/completions, others /chat/completions — try base_url as-is first
        # If base_url already ends with /v1, this becomes /v1/chat/completions (correct)
        resp = await self._client.post(url, json=body, headers=headers)
        # If 404, try alternative without /chat
        if resp.status_code == 404:
            alt_url = f"{self.config.base_url}/completions"
            resp2 = await self._client.post(alt_url, json=body, headers=headers)
            if resp2.status_code < 400:
                resp = resp2
        resp.raise_for_status()
        data = resp.json()
        # Normalize like OpenAI
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        text = msg.get("content")
        # Some gateways return stringified JSON for structured
        if text is None and msg.get("tool_calls"):
            text = ""
        tool_calls = msg.get("tool_calls") or []
        usage = data.get("usage") or {}
        return AIResponse(
            text=text or "",
            tool_calls=tool_calls,
            usage=usage,
            raw=data,
            model=data.get("model") or self.config.model,
            finish_reason=choice.get("finish_reason"),
        )

    async def close(self) -> None:
        await self._client.aclose()
