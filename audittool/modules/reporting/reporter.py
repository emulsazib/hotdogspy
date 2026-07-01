"""Module D orchestration: aggregate findings -> LLM/stub -> Remediation."""
from __future__ import annotations

import json
import re
from typing import Dict, List

from ...core.config import Settings
from ...core.schema import Remediation, RemediationStep, ScanReport, Severity
from .llm.factory import get_provider
from .llm.stub import StubProvider
from .prompts import SYSTEM_PROMPT, build_user_prompt


def _findings_payload(report: ScanReport) -> List[Dict]:
    payload = []
    for f in report.findings_by_severity():
        payload.append(
            {
                "id": f.id,
                "module": f.module,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
            }
        )
    return payload


def _extract_json(text: str) -> Dict:
    """Best-effort: pull a JSON object out of an LLM response."""
    text = text.strip()
    # Strip markdown code fences if present.
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    else:
        brace = text.find("{")
        if brace > 0:
            text = text[brace:]
    return json.loads(text)


def _coerce_severity(value) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.info


class Reporter:
    def __init__(self, settings: Settings = None):
        self.settings = settings or Settings.load()

    def generate(self, report: ScanReport) -> Remediation:
        findings = _findings_payload(report)
        if not findings:
            return Remediation(
                summary="No findings were produced; nothing to remediate.",
                prioritized_steps=[],
                generated_by="none",
            )

        provider = get_provider(self.settings)

        # The offline stub builds structured output directly.
        if isinstance(provider, StubProvider):
            data = provider.generate_structured(findings)
            return self._to_remediation(data, "stub")

        # Real LLM: prompt for structured JSON, then parse defensively.
        try:
            raw = provider.generate(SYSTEM_PROMPT, build_user_prompt({"findings": findings}))
            data = _extract_json(raw)
            return self._to_remediation(data, provider.name)
        except Exception:
            # Any failure (network, parse, key) -> deterministic offline fallback.
            data = StubProvider().generate_structured(findings)
            data["generated_by"] = f"stub (fallback from {provider.name})"
            return self._to_remediation(data, data["generated_by"])

    def _to_remediation(self, data: Dict, generated_by: str) -> Remediation:
        steps = []
        for s in data.get("prioritized_steps", []):
            steps.append(
                RemediationStep(
                    priority=int(s.get("priority", len(steps) + 1)),
                    title=s.get("title", "Remediation"),
                    action=s.get("action", ""),
                    related_finding_ids=s.get("related_finding_ids", []) or [],
                    severity=_coerce_severity(s.get("severity", "info")),
                )
            )
        steps.sort(key=lambda x: x.priority)
        return Remediation(
            summary=data.get("summary", ""),
            prioritized_steps=steps,
            generated_by=data.get("generated_by", generated_by),
        )
