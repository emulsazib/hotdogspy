"""Scope enforcement — the execution boundary for live actions.

Live network actions are only allowed against targets that are explicitly
authorized. Authorization comes from ``config/scope.yaml`` (an allowlist of
domains + networks, guarded by an ``attested: true`` flag). Targets outside the
allowlist require an explicit confirmation callback (interactive prompt in the
CLI, or an ``authorized: true`` field via the API).
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Callable, List, Optional

import yaml

from .config import CONFIG_DIR
from .validation import is_ip_address


class ScopeError(PermissionError):
    """Raised when a target is not authorized and cannot be confirmed."""


# A confirmation callback receives (target, ips) and returns True to authorize.
ConfirmFn = Callable[[str, List[str]], bool]


class Scope:
    def __init__(self, attested: bool, domains: List[str], networks: List[str]):
        self.attested = attested
        self.domains = {d.strip().lower() for d in domains if d and d.strip()}
        self._networks = []
        for n in networks:
            if not n or not str(n).strip():
                continue
            try:
                self._networks.append(ipaddress.ip_network(str(n).strip(), strict=False))
            except ValueError:
                # Non-IP entries in networks are ignored (belong in domains).
                pass

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Scope":
        path = path or (CONFIG_DIR / "scope.yaml")
        data = {}
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        return cls(
            attested=bool(data.get("attested", False)),
            domains=data.get("domains") or [],
            networks=data.get("networks") or [],
        )

    def _ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def is_authorized(self, target: str, ips: List[str]) -> bool:
        """True only when scope is attested AND the target/IPs are allowlisted."""
        if not self.attested:
            return False
        t = target.strip().lower()
        if not is_ip_address(t) and t in self.domains:
            return True
        if is_ip_address(t) and self._ip_in_scope(t):
            return True
        return any(self._ip_in_scope(ip) for ip in ips)

    def enforce(
        self,
        target: str,
        ips: List[str],
        confirm: Optional[ConfirmFn] = None,
    ) -> bool:
        """Return True if the target may be actively scanned.

        Order: allowlist first; if not listed, fall back to the confirmation
        callback (interactive attestation). Raises :class:`ScopeError` if neither
        authorizes the action.
        """
        if self.is_authorized(target, ips):
            return True
        if confirm is not None and confirm(target, ips):
            return True
        raise ScopeError(
            f"Target '{target}' is not in the authorized scope. Add it to "
            "config/scope.yaml (with attested: true) or confirm authorization "
            "to proceed."
        )
