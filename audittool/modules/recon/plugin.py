"""Module A plugin: network reconnaissance via nmap."""
from __future__ import annotations

from ...core.plugin import ScanContext, ScannerPlugin
from ...core.schema import ModuleResult, ModuleStatus
from .nmap_scan import build_scan_arguments, parse_nmap_xml, run_nmap


class ReconPlugin(ScannerPlugin):
    name = "recon"
    description = "Network reconnaissance (nmap service/version + default scripts)."
    requires_authorization = True  # active scanning is scope-gated

    def run(self, ctx: ScanContext) -> ModuleResult:
        profile = ctx.options.get("profile")
        arguments = build_scan_arguments(ctx.settings, profile)

        # An offline fixture path lets tests / demos parse pre-captured XML.
        fixture = ctx.options.get("nmap_xml")
        if fixture:
            with open(fixture, "r", encoding="utf-8") as fh:
                xml_text = fh.read()
        else:
            xml_text = run_nmap(ctx.target, arguments)

        findings, raw = parse_nmap_xml(xml_text)
        raw["profile"] = profile or "default"
        raw["arguments"] = arguments
        return ModuleResult(
            name=self.name,
            status=ModuleStatus.ok,
            findings=findings,
            raw=raw,
        )
