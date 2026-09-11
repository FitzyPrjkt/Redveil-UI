"""AiConfig — provider-agnostic gateway config (A5 P1).

Supports any proxy web via base_url + protocol + auth + model + headers + capabilities
fallback. No hard-coded vendor list. If gateway doesn't expose /models, user
provides explicit capabilities.
"""
from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AiProviderConfig(BaseModel):
    """Gateway provider config — fully user-defined, no allowlist."""

    type: str = Field(default="openai_compatible", description="Provider type: openai|anthropic|openai_compatible|custom")
    protocol: Literal["openai", "anthropic"] = Field(default="openai", description="API protocol")
    base_url: str = Field(default="", description="Gateway base URL, e.g. https://any-proxy.web.id/v1 or http://localhost:11434/v1 — auto-wraps OPENAI_BASE_URL/REDVEIL_BASE_URL if empty")
    api_key: str | None = Field(default=None, description="API key (prefer api_key_env)")
    api_key_env: str | None = Field(default=None, description="Env var name for API key, e.g. ANY_PROXY_API_KEY — auto-wraps OPENAI_API_KEY/REDVEIL_API_KEY if empty")
    model: str = Field(default="gpt-4o-mini", description="Model identifier, e.g. gpt-4o-mini or custom-model-x — auto-wraps OPENAI_MODEL/REDVEIL_MODEL if empty")
    headers: dict[str, str] = Field(default_factory=dict, description="Extra headers for non-standard proxies")
    timeout: float = Field(default=30.0, ge=1, le=300, description="Request timeout seconds")
    extra_body: dict | None = Field(default=None, description="Extra body fields for gateway quirks")

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, v: str) -> str:
        if not v:
            # Allow empty — will be resolved from env in model_validator
            return v
        if not v.startswith(("http://", "https://")):
            raise ValueError("base_url must be http(s)")
        return v.rstrip("/")

    def resolved_base_url(self) -> str | None:
        """Resolve base_url from explicit value or REDVEIL_/OPENAI_ env wrapping."""
        if self.base_url:
            return self.base_url
        for k in ("REDVEIL_BASE_URL", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"):
            v = os.environ.get(k)
            if v:
                return v.rstrip("/")
        return None

    def resolved_api_key(self) -> str | None:
        """Resolve API key from api_key_env or direct api_key (redacted in logs) — auto-wraps REDVEIL_/OPENAI_ env if empty."""
        if self.api_key_env:
            env_val = os.environ.get(self.api_key_env)
            if env_val:
                return env_val
        if self.api_key:
            return self.api_key
        for k in ("REDVEIL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            v = os.environ.get(k)
            if v:
                return v
        return None

    def resolved_model(self) -> str:
        if self.model and self.model != "gpt-4o-mini":
            return self.model
        for k in ("REDVEIL_MODEL", "OPENAI_MODEL"):
            v = os.environ.get(k)
            if v:
                return v
        return self.model


class AiCapabilities(BaseModel):
    """Explicit capability override when /models not available."""

    tool_calling: bool = True
    vision: bool = False
    structured_output: bool = True
    streaming: bool = False
    context_window: int | None = Field(default=None, description="Context window tokens, if known")


class AiConfig(BaseModel):
    """Root AI config — optional, extra='ignore' keeps old configs compatible."""

    enabled: bool = Field(default=False, description="Master switch — false = AI disabled, scanner still runs")
    provider: AiProviderConfig | None = Field(default=None, description="Gateway provider (required if enabled)")
    capabilities: AiCapabilities | None = Field(default=None, description="Explicit capability override if gateway doesn't expose /models")
    # Optional routing (Phase D): fast/reasoning/vision
    models: dict[str, AiProviderConfig] | None = Field(default=None, description="Per-task provider override: {fast, reasoning, vision}")

    @field_validator("provider", mode="before")
    @classmethod
    def _validate_provider(cls, v):
        # Allow None when disabled
        return v
