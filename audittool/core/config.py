"""Configuration loading + project path resolution."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml

# Project root = two levels up from this file (audittool/core/config.py -> root).
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


class Settings:
    """Thin wrapper around config/settings.yaml with dotted lookups."""

    def __init__(self, data: Dict[str, Any], root: Path = PROJECT_ROOT):
        self.data = data
        self.root = root

    @classmethod
    def load(cls, path: Path = None) -> "Settings":
        path = path or (CONFIG_DIR / "settings.yaml")
        return cls(_load_yaml(path))

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def resolve_path(self, dotted: str, default: str) -> Path:
        value = self.get(dotted, default)
        p = Path(value)
        return p if p.is_absolute() else (self.root / p)

    @property
    def reports_dir(self) -> Path:
        d = self.resolve_path("reports_dir", "data/reports")
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def samples_dir(self) -> Path:
        return self.resolve_path("samples_dir", "data/samples")


def load_env() -> None:
    """Load a .env file if python-dotenv is available (optional)."""
    try:
        from dotenv import load_dotenv

        load_dotenv(PROJECT_ROOT / ".env")
    except Exception:
        # dotenv is optional; env vars may already be set in the shell.
        pass


def getenv(name: str) -> str:
    return os.environ.get(name, "").strip()
