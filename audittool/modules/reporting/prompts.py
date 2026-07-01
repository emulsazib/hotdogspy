"""System + user prompt construction for Module D."""
from __future__ import annotations

import json
from typing import Dict

SYSTEM_PROMPT = """You are a senior defensive security engineer. You are given \
the structured JSON findings of an AUTHORIZED security audit. Produce prioritized, \
actionable, DEFENSIVE remediation guidance only. Do not provide exploitation steps.

Rules:
- Rank steps by risk (critical first). Assign an integer priority starting at 1.
- Each step must be concrete and implementable (config, patch, control).
- Reference the finding id(s) each step addresses.
- Respond with ONLY valid JSON, no markdown fencing, matching this schema:
{
  "summary": "<2-3 sentence executive summary>",
  "prioritized_steps": [
    {
      "priority": 1,
      "title": "<short title>",
      "action": "<concrete remediation action>",
      "related_finding_ids": ["<id>"],
      "severity": "critical|high|medium|low|info"
    }
  ]
}
"""


def build_user_prompt(findings_payload: Dict) -> str:
    return (
        "Here are the audit findings as JSON. Generate the remediation plan.\n\n"
        + json.dumps(findings_payload, indent=2, default=str)
    )
