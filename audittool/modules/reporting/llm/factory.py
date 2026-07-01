"""Select an LLM provider from config + available API keys.

Resolution order when ``reporting.provider`` is ``auto``:
    OPENAI_API_KEY -> GEMINI_API_KEY -> ANTHROPIC_API_KEY ->
    OPENAI_COMPATIBLE_API_KEY -> stub (offline).
A pinned provider name is honored if its key is present, else we fall back to the
stub so the pipeline never hard-fails on a missing key.
"""
from __future__ import annotations

from typing import Optional

from ....core.config import getenv
from .base import LLMProvider
from .providers import (
    AnthropicProvider,
    GeminiProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
)
from .stub import StubProvider


def _models(settings) -> dict:
    return settings.get("reporting.models", {}) or {}


def _common(settings):
    return (
        float(settings.get("reporting.temperature", 0.2)),
        int(settings.get("reporting.max_output_tokens", 2000)),
    )


def _build(name: str, settings) -> Optional[LLMProvider]:
    temperature, max_tokens = _common(settings)
    models = _models(settings)
    if name == "openai":
        key = getenv("OPENAI_API_KEY")
        if key:
            return OpenAIProvider(key, models.get("openai", "gpt-4o"), temperature, max_tokens)
    elif name == "gemini":
        key = getenv("GEMINI_API_KEY")
        if key:
            return GeminiProvider(key, models.get("gemini", "gemini-1.5-pro"), temperature, max_tokens)
    elif name == "anthropic":
        key = getenv("ANTHROPIC_API_KEY")
        if key:
            return AnthropicProvider(key, models.get("anthropic", "claude-sonnet-5"), temperature, max_tokens)
    elif name == "openai_compatible":
        key = getenv("OPENAI_COMPATIBLE_API_KEY")
        cfg = settings.get("reporting.openai_compatible", {}) or {}
        base_url = cfg.get("base_url")
        model = cfg.get("model")
        if key and base_url and model:
            return OpenAICompatibleProvider(key, model, temperature, max_tokens, base_url=base_url)
    return None


def get_provider(settings) -> LLMProvider:
    pinned = (settings.get("reporting.provider", "auto") or "auto").lower()

    if pinned != "auto" and pinned != "stub":
        provider = _build(pinned, settings)
        if provider is not None:
            return provider
        # pinned provider has no key -> fall through to stub

    if pinned == "auto":
        for name in ("openai", "gemini", "anthropic", "openai_compatible"):
            provider = _build(name, settings)
            if provider is not None:
                return provider

    return StubProvider()
