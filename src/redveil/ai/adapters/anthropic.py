"""AnthropicAdapter — Messages API (preserves Anthropic semantics)."""
from __future__ import annotations

from typing import Any

import httpx

from redveil.ai.config import AiCapabilities, AiProviderConfig
from redveil.ai.provider import AIProvider, AIResponse


class AnthropicAdapter(AIProvider):
    """Anthropic Messages API adapter — preserves tool_use, system, etc."""

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
        headers: dict[str, str] = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
        if key:
            headers["x-api-key"] = key
        headers.update(self.config.headers)

        # Anthropic separates system
        system = ""
        anth_messages: list[dict[str, Any]] = []
        for m in messages:
            if m.get("role") == "system":
                system = m.get("content", "")
            else:
                content = m.get("content", "")
                if images and m.get("role") == "user":
                    # Vision: content as array with image
                    arr: list[dict[str, Any]] = [{"type": "text", "text": content}]
                    for img in images:
                        # Convert openai image_url to anthropic image source
                        url = (img.get("image_url") or {}).get("url", "")
                        if url.startswith("data:"):
                            # data:image/png;base64,...
                            try:
                                header, b64 = url.split(",", 1)
                                media_type = header.split(":")[1].split(";")[0]
                                arr.append({"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}})
                            except Exception:
                                arr.append({"type": "text", "text": url})
                        else:
                            arr.append({"type": "text", "text": url})
                    anth_messages.append({"role": m["role"], "content": arr})
                else:
                    anth_messages.append({"role": m["role"], "content": content})

        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": anth_messages,
            "max_tokens": kwargs.get("max_tokens", 1024),
        }
        if system:
            body["system"] = system
        if tools:
            # Tools: Anthropic expects {name, description, input_schema}
            body["tools"] = tools
        if response_format:
            # Anthropic uses tool for structured output: force tool
            # For now, pass via extra_body if needed
            body["_response_format"] = response_format
        if self.config.extra_body:
            body.update(self.config.extra_body)

        url = f"{self.config.base_url}/messages"
        resp = await self._client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        # Normalize: content is array with text + tool_use
        content_arr = data.get("content") or []
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in content_arr:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(block)
        text = "\n".join(text_parts)
        usage = data.get("usage") or {}
        return AIResponse(
            text=text,
            tool_calls=tool_calls,
            usage=usage,
            raw=data,
            model=data.get("model") or self.config.model,
            finish_reason=data.get("stop_reason"),
        )

    async def close(self) -> None:
        await self._client.aclose()
