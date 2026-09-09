"""Redveil AI package — provider-agnostic gateway (A5 P1).

Re-exports the public AI surface for `from redveil.ai import AIProvider, AiConfig`.
"""
from redveil.ai.config import AiConfig, AiProviderConfig  # noqa: F401
from redveil.ai.provider import AIProvider, AIResponse, build_ai_provider  # noqa: F401

__all__ = ["AIProvider", "AIResponse", "AiConfig", "AiProviderConfig", "build_ai_provider"]
