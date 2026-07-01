"""The orchestrator chains the whole pipeline together.

validate -> resolve -> scope gate -> run modules -> collect findings ->
build ScanReport -> Module D remediation -> return report (ready for exporters).

Both the CLI and the web backend call :meth:`Orchestrator.run`; they differ only
in the ``on_progress`` sink and the ``confirm`` callback.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from ..modules.recon.resolver import resolve
from ..modules.reporting.reporter import Reporter
from .config import Settings
from .plugin import ScanContext
from .registry import Registry, build_registry
from .schema import ModuleResult, ScanReport
from .scope import ConfirmFn, Scope
from .validation import validate_target

# on_progress(module_name, status, detail)
ProgressFn = Callable[[str, str, str], None]


class Orchestrator:
    def __init__(
        self,
        registry: Optional[Registry] = None,
        scope: Optional[Scope] = None,
        settings: Optional[Settings] = None,
        on_progress: Optional[ProgressFn] = None,
    ) -> None:
        self.registry = registry or build_registry()
        self.scope = scope or Scope.load()
        self.settings = settings or Settings.load()
        self.on_progress = on_progress or (lambda *_: None)

    def _progress(self, module: str, status: str, detail: str = "") -> None:
        try:
            self.on_progress(module, status, detail)
        except Exception:
            pass

    def run(
        self,
        target: str,
        modules: List[str],
        confirm: Optional[ConfirmFn] = None,
        options: Optional[dict] = None,
        with_remediation: bool = True,
    ) -> ScanReport:
        options = options or {}

        # 1) Validate & sanitize the target (anti-injection).
        self._progress("resolve", "running", "validating target")
        clean = validate_target(target)

        # 2) Resolve to IPs (safe stdlib DNS; never a shell).
        ips = resolve(clean)
        self._progress("resolve", "done", ", ".join(ips) if ips else "no A/AAAA records")

        # 3) Scope gate — authorize live actions for this run.
        authorized = False
        try:
            authorized = self.scope.enforce(clean, ips, confirm=confirm)
        except Exception as exc:
            # Not authorized: passive/offline modules can still run; live modules
            # will self-skip via requires_met(). Record the reason on the report.
            self._progress("scope", "warning", str(exc))

        report = ScanReport.new(target=clean, resolved_ips=ips, scope_authorized=authorized)
        ctx = ScanContext(
            target=clean,
            resolved_ips=ips,
            settings=self.settings,
            scope=self.scope,
            scope_authorized=authorized,
            options=options,
        )

        # 4) Run each requested module in order (A -> B -> C).
        for name in modules:
            if not self.registry.has(name):
                report.add(ModuleResult.skipped_result(name, "unknown module"))
                self._progress(name, "skipped", "unknown module")
                continue
            plugin = self.registry.get(name)
            blocker = plugin.requires_met(ctx)
            if blocker:
                report.add(ModuleResult.skipped_result(name, blocker))
                self._progress(name, "skipped", blocker)
                continue
            self._progress(name, "running", plugin.description)
            try:
                result = plugin.run(ctx)
            except Exception as exc:
                result = ModuleResult.error_result(name, exc)
                self._progress(name, "error", str(exc))
            else:
                self._progress(name, "done", f"{len(result.findings)} finding(s)")
            report.add(result)

        # 5) Module D — AI-driven remediation over the aggregated findings.
        if with_remediation:
            self._progress("reporting", "running", "generating remediation")
            try:
                report.remediation = Reporter(self.settings).generate(report)
                self._progress("reporting", "done", report.remediation.generated_by)
            except Exception as exc:
                self._progress("reporting", "error", str(exc))

        report.finalize()
        self._progress("scan", "done", f"{len(report.all_findings)} finding(s) total")
        return report
