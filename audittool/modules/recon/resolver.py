"""Safe DNS resolution using the standard library (no shell, no external tools)."""
from __future__ import annotations

import socket
from typing import List

from ...core.validation import is_ip_address


def resolve(target: str) -> List[str]:
    """Resolve a hostname to its IPv4/IPv6 addresses.

    If ``target`` is already an IP, it is returned as-is. Returns a de-duplicated
    list, IPv4 first. Never raises on resolution failure — returns an empty list
    so passive/offline modules can still proceed.
    """
    if is_ip_address(target):
        return [target]

    ipv4: List[str] = []
    ipv6: List[str] = []
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror:
        return []
    for family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        if family == socket.AF_INET and addr not in ipv4:
            ipv4.append(addr)
        elif family == socket.AF_INET6 and addr not in ipv6:
            ipv6.append(addr)
    return ipv4 + ipv6
