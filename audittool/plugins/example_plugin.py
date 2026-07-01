"""Example drop-in plugin.

Drop a .py file in this directory that either:
  * defines a ``PLUGIN`` instance,
  * exposes a ``get_plugin()`` factory, or
  * defines a ``ScannerPlugin`` subclass,
and it will be auto-discovered by the registry and available on the CLI/API.

This example flags plaintext (non-HTTPS) recon findings as a reminder to enforce
TLS. It is passive: it only reads context, performs no network actions.
"""
from __future__ import annotations

from audittool.core.plugin import ScanContext, ScannerPlugin
from audittool.core.schema import Finding, ModuleResult, ModuleStatus, Severity


class TlsReminderPlugin(ScannerPlugin):
    name = "tls-reminder"
    description = "Example plugin: reminds you to enforce TLS on the target."
    requires_authorization = False

    def run(self, ctx: ScanContext) -> ModuleResult:
        finding = Finding(
            module=self.name,
            title="Enforce TLS everywhere",
            severity=Severity.info,
            description=(
                f"Reminder for {ctx.target}: ensure all services enforce TLS 1.2+ "
                "and redirect plaintext protocols."
            ),
        )
        return ModuleResult(name=self.name, status=ModuleStatus.ok, findings=[finding])


# Explicit instance the registry will pick up.
PLUGIN = TlsReminderPlugin()
