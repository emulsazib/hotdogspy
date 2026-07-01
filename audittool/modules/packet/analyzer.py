"""Packet analysis: cleartext-protocol + credential/leak signature detection.

Works on a list of lightweight packet records so the detection logic can be
unit-tested without scapy/tshark. :mod:`capture` produces those records from a
.pcap file or a live capture.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ...core.schema import Finding, Severity

# Well-known cleartext services by port.
CLEARTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    8080: "HTTP-alt",
}

# Signature regexes for potential leaks in cleartext payloads. Kept intentionally
# conservative; each match is a *potential* exposure to be reviewed.
_SIGNATURES = [
    ("Basic auth header", re.compile(rb"[Aa]uthorization:\s*Basic\s+[A-Za-z0-9+/=]+"), Severity.high),
    ("HTTP password param", re.compile(rb"(?:password|passwd|pwd)=([^&\s]+)", re.I), Severity.high),
    ("FTP USER command", re.compile(rb"USER\s+\S+", re.I), Severity.medium),
    ("FTP PASS command", re.compile(rb"PASS\s+\S+", re.I), Severity.high),
    ("API key / token", re.compile(rb"(?:api[_-]?key|token|secret)[\"'\s:=]+[A-Za-z0-9._\-]{12,}", re.I), Severity.high),
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}"), Severity.critical),
    ("Private key block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.critical),
    ("Credit card number", re.compile(rb"\b(?:\d[ -]?){13,16}\b"), Severity.high),
]


@dataclass
class PacketRecord:
    """Minimal normalized packet used by the analyzer."""

    src: str = ""
    dst: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = ""
    payload: bytes = b""


def _redact(match_bytes: bytes) -> str:
    text = match_bytes.decode("utf-8", errors="replace")
    # Redact the tail of anything that looks like a secret.
    if len(text) > 12:
        return text[:8] + "…[redacted]"
    return text[:4] + "…"


def analyze_packets(packets: List[PacketRecord]) -> List[Finding]:
    findings: List[Finding] = []
    cleartext_seen: Dict[int, int] = {}

    for pkt in packets:
        port = pkt.dst_port if pkt.dst_port in CLEARTEXT_PORTS else pkt.src_port
        if port in CLEARTEXT_PORTS:
            cleartext_seen[port] = cleartext_seen.get(port, 0) + 1

        if not pkt.payload:
            continue
        for label, pattern, severity in _SIGNATURES:
            m = pattern.search(pkt.payload)
            if m:
                findings.append(
                    Finding(
                        module="packet",
                        title=f"Potential data leak: {label}",
                        severity=severity,
                        description=(
                            f"Signature '{label}' matched in cleartext traffic "
                            f"{pkt.src}:{pkt.src_port} -> {pkt.dst}:{pkt.dst_port} "
                            f"({pkt.protocol})."
                        ),
                        evidence=_redact(m.group(0)),
                        metadata={
                            "src": pkt.src,
                            "dst": pkt.dst,
                            "dst_port": pkt.dst_port,
                            "signature": label,
                        },
                    )
                )

    # One aggregate finding per cleartext protocol observed.
    for port, count in sorted(cleartext_seen.items()):
        proto = CLEARTEXT_PORTS[port]
        findings.append(
            Finding(
                module="packet",
                title=f"Cleartext protocol observed: {proto} (port {port})",
                severity=Severity.medium,
                description=(
                    f"{count} packet(s) using unencrypted {proto} on port {port}. "
                    "Traffic (including credentials) may be readable on the wire."
                ),
                metadata={"port": port, "protocol": proto, "packet_count": count},
            )
        )

    return findings
