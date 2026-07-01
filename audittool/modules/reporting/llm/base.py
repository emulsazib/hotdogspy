"""Provider-agnostic LLM interface."""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Minimal interface every provider adapter implements."""

    name: str = "base"

    @abstractmethod
    def generate(self, system: str, user: str) -> str:
        """Return the model's text response for a system + user prompt."""
        raise NotImplementedError
