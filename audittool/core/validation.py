"""Input validation & sanitization.

The single most important defensive control *inside* the tool: user-supplied
targets must never reach a shell or a scanner as anything other than a strictly
validated hostname / IP. We validate structurally (regex + ``ipaddress``) and
reject anything containing shell metacharacters or whitespace.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List

# RFC-1123 hostname: labels of alnum/hyphen, 1-63 chars, dot separated, TLD alpha.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,}$"
)

# Characters that must never appear in a target — defense-in-depth against
# command / argument injection even though we never use shell=True.
_FORBIDDEN = set(" \t\n\r;|&$`<>(){}[]!\\'\"*?~")


class ValidationError(ValueError):
    """Raised when a target fails validation."""


def _has_forbidden_chars(value: str) -> bool:
    return any(c in _FORBIDDEN for c in value)


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value))


def validate_target(raw: str) -> str:
    """Validate and normalize a target (domain or IP).

    Returns the cleaned target (lowercased hostname, or normalized IP string).
    Raises :class:`ValidationError` on anything unsafe or malformed.
    """
    if raw is None:
        raise ValidationError("target is required")
    target = raw.strip()
    if not target:
        raise ValidationError("target is empty")
    if len(target) > 253:
        raise ValidationError("target is too long")
    if _has_forbidden_chars(target):
        raise ValidationError(
            "target contains forbidden characters (possible injection attempt)"
        )
    # Strip an accidental scheme/path if the user pasted a URL host.
    if is_ip_address(target):
        return str(ipaddress.ip_address(target))
    lowered = target.lower()
    if is_hostname(lowered):
        return lowered
    raise ValidationError(f"'{raw}' is not a valid IP address or hostname")


def validate_network(raw: str) -> str:
    """Validate an IP or CIDR range used in the scope allowlist."""
    target = raw.strip()
    if _has_forbidden_chars(target):
        raise ValidationError("network contains forbidden characters")
    try:
        return str(ipaddress.ip_network(target, strict=False))
    except ValueError:
        # allow a bare hostname in scope lists too
        lowered = target.lower()
        if is_hostname(lowered):
            return lowered
        raise ValidationError(f"'{raw}' is not a valid IP/CIDR or hostname")


def validate_url(raw: str) -> str:
    """Light validation for user-supplied URLs (Module C endpoints).

    We only accept http/https and forbid shell metacharacters. Full URL parsing
    is left to ``requests``; this is a gate, not a parser.
    """
    from urllib.parse import urlparse

    target = raw.strip()
    if any(c in target for c in "\t\n\r;|&$`<>\\'\" "):
        raise ValidationError("URL contains forbidden characters")
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("URL must use http or https")
    if not parsed.netloc:
        raise ValidationError("URL is missing a host")
    return target


def hostnames_and_ips(cleaned_target: str, resolved_ips: List[str]) -> List[str]:
    """Convenience: the set of identifiers a scope check should consider."""
    values = [cleaned_target] + list(resolved_ips)
    return list(dict.fromkeys(values))  # de-dupe, preserve order
