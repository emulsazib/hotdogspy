"""nmap wrapper + XML parser (Module A).

We drive nmap through the ``python-nmap`` library, which invokes the ``nmap``
binary with an argv list (no shell) and returns its ``-oX`` XML. The XML parser
below is factored out so it can be unit-tested against fixtures without running a
live scan.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple

from ...core.schema import Finding, Severity

# Services considered risky when found exposed, mapped to (severity, note).
_RISKY_SERVICES: Dict[str, Tuple[Severity, str]] = {
    "telnet": (Severity.high, "Telnet transmits credentials in cleartext."),
    "ftp": (Severity.medium, "FTP transmits credentials/data in cleartext."),
    "http": (Severity.low, "Unencrypted HTTP; prefer HTTPS/TLS."),
    "smtp": (Severity.low, "Check for STARTTLS enforcement."),
    "pop3": (Severity.medium, "POP3 without TLS exposes credentials."),
    "imap": (Severity.medium, "IMAP without TLS exposes credentials."),
    "rpcbind": (Severity.low, "rpcbind exposure can aid enumeration."),
    "microsoft-ds": (Severity.medium, "SMB exposed to the network."),
    "ms-wbt-server": (Severity.medium, "RDP exposed; ensure NLA + patching."),
    "mysql": (Severity.medium, "Database port exposed to the network."),
    "postgresql": (Severity.medium, "Database port exposed to the network."),
    "mongodb": (Severity.high, "MongoDB exposed; verify auth + binding."),
    "redis": (Severity.high, "Redis exposed; often unauthenticated by default."),
}


def build_scan_arguments(settings, profile_name: str = None) -> str:
    recon = settings.get("recon", {}) or {}
    profiles = recon.get("profiles", {}) or {}
    profile_name = profile_name or recon.get("default_profile", "default")
    profile = profiles.get(profile_name)
    if not profile:
        raise ValueError(f"unknown recon profile: {profile_name}")
    return profile.get("arguments", "-sV")


def run_nmap(target: str, arguments: str) -> str:
    """Run nmap against ``target`` and return the raw XML output.

    Raises RuntimeError if python-nmap / the nmap binary is unavailable.
    """
    try:
        import nmap  # python-nmap
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "python-nmap is not installed (pip install python-nmap) or the nmap "
            "binary is missing"
        ) from exc

    scanner = nmap.PortScanner()
    # python-nmap passes hosts + arguments to the nmap binary as an argv list.
    scanner.scan(hosts=target, arguments=arguments)
    return scanner.get_nmap_last_output().decode("utf-8", errors="replace")


def parse_nmap_xml(xml_text: str) -> Tuple[List[Finding], Dict]:
    """Parse nmap XML into Findings + a compact raw summary.

    Returns (findings, raw_summary). One finding per open port, plus one info
    finding per host for the inferred OS.
    """
    findings: List[Finding] = []
    raw: Dict = {"hosts": []}

    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        state = host.find("status")
        if state is not None and state.get("state") != "up":
            continue

        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else "unknown"
        host_raw = {"address": address, "ports": [], "os": None}

        # Ports / services
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                pstate = port.find("state")
                if pstate is None or pstate.get("state") != "open":
                    continue
                portid = port.get("portid")
                proto = port.get("protocol", "tcp")
                svc = port.find("service")
                name = (svc.get("name") if svc is not None else "") or "unknown"
                product = svc.get("product") if svc is not None else None
                version = svc.get("version") if svc is not None else None
                banner = " ".join(x for x in [product, version] if x) or None

                severity, note = _RISKY_SERVICES.get(name, (Severity.info, ""))
                desc = f"Open {proto}/{portid} running {name}".strip()
                if banner:
                    desc += f" ({banner})"
                if note:
                    desc += f". {note}"

                findings.append(
                    Finding(
                        module="recon",
                        title=f"Open port {portid}/{proto} — {name}",
                        severity=severity,
                        description=desc,
                        evidence=banner,
                        metadata={
                            "address": address,
                            "port": int(portid) if portid else None,
                            "protocol": proto,
                            "service": name,
                            "product": product,
                            "version": version,
                        },
                    )
                )
                host_raw["ports"].append(
                    {"port": portid, "protocol": proto, "service": name, "banner": banner}
                )

        # Inferred OS
        os_el = host.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name")
                accuracy = match.get("accuracy")
                host_raw["os"] = {"name": os_name, "accuracy": accuracy}
                findings.append(
                    Finding(
                        module="recon",
                        title=f"Inferred OS: {os_name}",
                        severity=Severity.info,
                        description=f"nmap inferred operating system '{os_name}' "
                        f"(accuracy {accuracy}%).",
                        metadata={"address": address, "accuracy": accuracy},
                    )
                )

        raw["hosts"].append(host_raw)

    return findings, raw
