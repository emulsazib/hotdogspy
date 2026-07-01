"""Concrete LLM provider adapters (OpenAI, Gemini, Anthropic, OpenAI-compatible).

Each adapter lazily imports its SDK so the tool runs with only the providers you
actually install. All of them expose the same ``generate(system, user) -> str``.
"""
from __future__ import annotations

from .base import LLMProvider


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o", temperature: float = 0.2,
                 max_tokens: int = 2000, base_url: str = None):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.base_url = base_url

    def generate(self, system: str, user: str) -> str:
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key, base_url=self.base_url) if self.base_url \
            else OpenAI(api_key=self.api_key)
        resp = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""


class OpenAICompatibleProvider(OpenAIProvider):
    """Kimi / Qwen / local servers exposing the OpenAI chat completions API."""

    name = "openai_compatible"


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-1.5-pro",
                 temperature: float = 0.2, max_tokens: int = 2000):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate(self, system: str, user: str) -> str:
        import google.generativeai as genai

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            self.model,
            system_instruction=system,
            generation_config={
                "temperature": self.temperature,
                "max_output_tokens": self.max_tokens,
            },
        )
        resp = model.generate_content(user)
        return resp.text or ""


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-sonnet-5",
                 temperature: float = 0.2, max_tokens: int = 2000):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate(self, system: str, user: str) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)
        resp = client.messages.create(
            model=self.model,
            system=system,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            messages=[{"role": "user", "content": user}],
        )
        # Concatenate text blocks.
        return "".join(getattr(b, "text", "") for b in resp.content)
