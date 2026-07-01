"""Plugin registry — registers built-in modules and discovers user plugins.

Built-ins are imported explicitly. User plugins are discovered dynamically from
``audittool/plugins/`` (any module exposing a ``ScannerPlugin`` subclass or a
``PLUGIN`` instance / ``get_plugin()`` factory).
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List

from .config import PROJECT_ROOT
from .plugin import ScannerPlugin

PLUGINS_DIR = PROJECT_ROOT / "audittool" / "plugins"


class Registry:
    def __init__(self) -> None:
        self._plugins: Dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"duplicate plugin name: {plugin.name}")
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ScannerPlugin:
        if name not in self._plugins:
            raise KeyError(f"unknown plugin: {name}")
        return self._plugins[name]

    def has(self, name: str) -> bool:
        return name in self._plugins

    def names(self) -> List[str]:
        return list(self._plugins.keys())

    def all(self) -> List[ScannerPlugin]:
        return list(self._plugins.values())


def _register_builtins(reg: Registry) -> None:
    # Imported lazily so optional deps don't break the whole registry.
    from audittool.modules.recon.plugin import ReconPlugin
    from audittool.modules.packet.plugin import PacketPlugin
    from audittool.modules.sqli.plugin import SqliPlugin

    for cls in (ReconPlugin, PacketPlugin, SqliPlugin):
        try:
            reg.register(cls())
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[registry] failed to register {cls.__name__}: {exc}")


def _instantiate_from_module(module) -> List[ScannerPlugin]:
    found: List[ScannerPlugin] = []
    # 1) explicit instance
    if hasattr(module, "PLUGIN") and isinstance(module.PLUGIN, ScannerPlugin):
        found.append(module.PLUGIN)
        return found
    # 2) factory
    if hasattr(module, "get_plugin"):
        obj = module.get_plugin()
        if isinstance(obj, ScannerPlugin):
            found.append(obj)
            return found
    # 3) any ScannerPlugin subclass defined in the module
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, ScannerPlugin) and obj is not ScannerPlugin and obj.__module__ == module.__name__:
            try:
                found.append(obj())
            except Exception:
                pass
    return found


def _discover_user_plugins(reg: Registry) -> None:
    if not PLUGINS_DIR.exists():
        return
    for path in sorted(PLUGINS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        mod_name = f"audittool.plugins.{path.stem}"
        try:
            module = importlib.import_module(mod_name)
        except Exception as exc:
            print(f"[registry] skipping plugin {path.name}: {exc}")
            continue
        for plugin in _instantiate_from_module(module):
            if not reg.has(plugin.name):
                try:
                    reg.register(plugin)
                except Exception as exc:
                    print(f"[registry] failed to register {plugin.name}: {exc}")


def build_registry(include_user_plugins: bool = True) -> Registry:
    reg = Registry()
    _register_builtins(reg)
    if include_user_plugins:
        _discover_user_plugins(reg)
    return reg
