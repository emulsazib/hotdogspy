"""Module C plugin: SQL injection assessment.

Prefers a reachable sqlmap REST API; otherwise uses the built-in safe probes.
Requires an explicit target URL and is scope-gated (active HTTP requests).
"""
from __future__ import annotations

from ...core.plugin import ScanContext, ScannerPlugin
from ...core.schema import ModuleResult, ModuleStatus
from ...core.validation import ValidationError, validate_url
from .payloads import run_probes
from .sqlmap_api import SqlmapApiClient, findings_from_sqlmap


class SqliPlugin(ScannerPlugin):
    name = "sqli"
    description = "SQL injection assessment (sqlmap API or built-in safe probes)."
    requires_authorization = True  # active HTTP probing is scope-gated

    def requires_met(self, ctx: ScanContext):
        blocker = super().requires_met(ctx)
        if blocker:
            return blocker
        if not ctx.options.get("url"):
            return "no target URL provided (pass --url <endpoint>)"
        return None

    def run(self, ctx: ScanContext) -> ModuleResult:
        try:
            url = validate_url(ctx.options["url"])
        except ValidationError as exc:
            return ModuleResult.error_result(self.name, exc)

        params = ctx.options.get("params") or []
        if isinstance(params, str):
            params = [p.strip() for p in params.split(",") if p.strip()]

        # Prefer sqlmap REST API when available.
        api_url = ctx.settings.get("sqli.sqlmap_api_url", "")
        if api_url:
            client = SqlmapApiClient(api_url)
            if client.is_available():
                result = client.scan(url)
                findings = findings_from_sqlmap(result, url)
                return ModuleResult(
                    name=self.name, status=ModuleStatus.ok, findings=findings,
                    raw={"engine": "sqlmap", "url": url},
                )

        # Fallback: built-in safe probes.
        findings = run_probes(url, params, ctx.settings)
        return ModuleResult(
            name=self.name, status=ModuleStatus.ok, findings=findings,
            raw={"engine": "builtin-probes", "url": url, "params": params},
        )
