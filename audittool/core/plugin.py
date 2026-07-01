"""Plugin interface shared by built-in modules and user drop-in plugins."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from .config import Settings
from .schema import ModuleResult
from .scope import Scope


@dataclass
class ScanContext:
    """Everything a plugin needs to do its work for one run."""

    target: str
    resolved_ips: List[str]
    settings: Settings
    scope: Scope
    scope_authorized: bool = False
    # Optional per-module inputs supplied by CLI/API (pcap path, URL, etc.).
    options: dict = field(default_factory=dict)


class ScannerPlugin(ABC):
    """Base class for every scanner module.

    Subclass this, set ``name``, and implement :meth:`run`. Built-in modules live
    under ``audittool/modules/``; user plugins are auto-discovered from
    ``audittool/plugins/`` (see :mod:`audittool.core.registry`).
    """

    #: Unique short identifier used on the CLI (e.g. "recon").
    name: str = "unnamed"
    #: Human-readable description shown by `audit-tool plugins`.
    description: str = ""
    #: If True, the plugin performs live network actions and is scope-gated.
    requires_authorization: bool = False

    def requires_met(self, ctx: ScanContext) -> Optional[str]:
        """Return an error string if the plugin cannot run, else None.

        Default implementation blocks authorization-requiring plugins when the
        target is not in scope. Override to add tool/dependency checks.
        """
        if self.requires_authorization and not ctx.scope_authorized:
            return "target not authorized for live actions (scope gate)"
        return None

    @abstractmethod
    def run(self, ctx: ScanContext) -> ModuleResult:
        """Execute the module and return a :class:`ModuleResult`."""
        raise NotImplementedError
