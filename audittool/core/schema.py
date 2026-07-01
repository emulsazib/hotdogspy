"""Structured data model shared across the whole pipeline.

This module defines the single canonical contract (:class:`ScanReport`) that the
orchestrator builds, the LLM reporter consumes, the exporters serialize, and the
web API returns. Everything is a pydantic model so we get validation + JSON for
free.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.critical: 5,
            Severity.high: 4,
            Severity.medium: 3,
            Severity.low: 2,
            Severity.info: 1,
        }
        return order[self]


class ModuleStatus(str, Enum):
    ok = "ok"
    error = "error"
    skipped = "skipped"


class Finding(BaseModel):
    """A single security observation produced by a module."""

    id: str = Field(default_factory=_new_id)
    module: str
    title: str
    severity: Severity = Severity.info
    description: str = ""
    evidence: Optional[str] = None
    cvss: Optional[float] = None
    references: List[str] = Field(default_factory=list)
    # Free-form structured detail (e.g. port, service, parameter).
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ModuleResult(BaseModel):
    """The output of running one module/plugin."""

    name: str
    status: ModuleStatus = ModuleStatus.ok
    findings: List[Finding] = Field(default_factory=list)
    error: Optional[str] = None
    # Optional raw tool output kept for auditability (parsed dict, sqlmap data, ...).
    raw: Optional[Dict[str, Any]] = None
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None

    @classmethod
    def error_result(cls, name: str, exc: Exception) -> "ModuleResult":
        return cls(
            name=name,
            status=ModuleStatus.error,
            error=f"{type(exc).__name__}: {exc}",
            finished_at=_utcnow(),
        )

    @classmethod
    def skipped_result(cls, name: str, reason: str) -> "ModuleResult":
        return cls(
            name=name,
            status=ModuleStatus.skipped,
            error=reason,
            finished_at=_utcnow(),
        )


class TargetInfo(BaseModel):
    input: str
    resolved_ips: List[str] = Field(default_factory=list)


class RemediationStep(BaseModel):
    priority: int
    title: str
    action: str
    related_finding_ids: List[str] = Field(default_factory=list)
    severity: Severity = Severity.info


class Remediation(BaseModel):
    summary: str = ""
    prioritized_steps: List[RemediationStep] = Field(default_factory=list)
    generated_by: str = "stub"  # which provider produced this


class ScanReport(BaseModel):
    """Top-level report object — the canonical JSON schema for the whole tool."""

    id: str = Field(default_factory=_new_id)
    target: TargetInfo
    scope_authorized: bool = False
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None
    modules: List[ModuleResult] = Field(default_factory=list)
    remediation: Optional[Remediation] = None

    # ----- construction helpers -----
    @classmethod
    def new(cls, target: str, resolved_ips: List[str], scope_authorized: bool = False) -> "ScanReport":
        return cls(
            target=TargetInfo(input=target, resolved_ips=resolved_ips),
            scope_authorized=scope_authorized,
        )

    def add(self, result: ModuleResult) -> None:
        if result.finished_at is None:
            result.finished_at = _utcnow()
        self.modules.append(result)

    def finalize(self) -> None:
        self.finished_at = _utcnow()

    # ----- derived views -----
    @property
    def all_findings(self) -> List[Finding]:
        out: List[Finding] = []
        for m in self.modules:
            out.extend(m.findings)
        return out

    def findings_by_severity(self) -> List[Finding]:
        return sorted(self.all_findings, key=lambda f: f.severity.rank, reverse=True)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts
