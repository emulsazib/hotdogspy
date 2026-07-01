"""Offline rule-based reporter — the zero-key fallback.

Produces deterministic, useful remediation without any external API. Used when no
provider key is configured, or as a safe default for CI / demos.
"""
from __future__ import annotations

import json
from typing import Dict, List

from .base import LLMProvider

# Keyword -> canned remediation guidance, keyed off finding service/title text.
_RULES = [
    ("telnet", "Disable Telnet; use SSH with key-based auth."),
    ("ftp", "Replace FTP with SFTP/FTPS; disable anonymous access."),
    ("http", "Enforce HTTPS (HSTS), redirect port 80, and obtain a valid TLS cert."),
    ("smb", "Restrict SMB to trusted networks; require SMB signing; patch."),
    ("microsoft-ds", "Restrict SMB exposure; enable signing; patch to latest."),
    ("rdp", "Place RDP behind a VPN; require Network Level Authentication."),
    ("ms-wbt-server", "Place RDP behind a VPN; require NLA; enable MFA."),
    ("redis", "Enable Redis AUTH, bind to localhost, and never expose publicly."),
    ("mongodb", "Enable authentication and bind MongoDB to internal interfaces."),
    ("mysql", "Restrict DB port to app hosts; require TLS; strong credentials."),
    ("postgres", "Restrict DB port to app hosts; require TLS; strong credentials."),
    ("sql injection", "Use parameterized queries/ORM; validate input; apply WAF rules."),
    ("cleartext", "Encrypt the channel (TLS); rotate any exposed credentials."),
    ("credential", "Rotate exposed credentials immediately; enforce encryption in transit."),
]


class StubProvider(LLMProvider):
    name = "stub"

    def generate(self, system: str, user: str) -> str:  # pragma: no cover - not used
        # The reporter uses generate_structured directly for the stub.
        return "Rule-based remediation (offline stub)."

    def generate_structured(self, findings: List[Dict]) -> Dict:
        steps = []
        seen = set()
        # Highest severity first.
        rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        ordered = sorted(findings, key=lambda f: rank.get(f.get("severity", "info"), 0), reverse=True)
        priority = 1
        for f in ordered:
            haystack = f"{f.get('title','')} {f.get('description','')}".lower()
            for keyword, action in _RULES:
                if keyword in haystack and keyword not in seen:
                    seen.add(keyword)
                    steps.append(
                        {
                            "priority": priority,
                            "title": f.get("title", "Finding"),
                            "action": action,
                            "related_finding_ids": [f.get("id")],
                            "severity": f.get("severity", "info"),
                        }
                    )
                    priority += 1
                    break
        if not steps and findings:
            steps.append(
                {
                    "priority": 1,
                    "title": "Review findings",
                    "action": "Manually review the findings and apply least-privilege / "
                    "patching best practices.",
                    "related_finding_ids": [f.get("id") for f in findings],
                    "severity": "info",
                }
            )
        summary = (
            f"Rule-based analysis of {len(findings)} finding(s). "
            f"{len(steps)} prioritized remediation step(s) generated offline."
        )
        return {"summary": summary, "prioritized_steps": steps, "generated_by": "stub"}
