"""Module B plugin: packet analysis & leak detection."""
from __future__ import annotations

from ...core.plugin import ScanContext, ScannerPlugin
from ...core.schema import ModuleResult, ModuleStatus
from .analyzer import analyze_packets
from .capture import live_capture, read_pcap


class PacketPlugin(ScannerPlugin):
    name = "packet"
    description = "Packet analysis for cleartext protocols & credential leaks."
    requires_authorization = False  # pcap ingestion is passive/offline

    def requires_met(self, ctx: ScanContext):
        # Live capture is the only mode that needs authorization.
        if ctx.options.get("live") and not ctx.scope_authorized:
            return "live capture requires an authorized target (scope gate)"
        if not ctx.options.get("live") and not ctx.options.get("pcap"):
            return "no pcap provided (pass --pcap <file>) and live capture disabled"
        return None

    def run(self, ctx: ScanContext) -> ModuleResult:
        if ctx.options.get("live"):
            cfg = ctx.settings.get("packet", {}) or {}
            if not cfg.get("allow_live_capture", False):
                return ModuleResult.skipped_result(
                    self.name, "live capture disabled in settings.yaml"
                )
            seconds = int(ctx.options.get("seconds", cfg.get("live_capture_seconds", 15)))
            packets = live_capture(
                interface=ctx.options.get("interface", ""),
                seconds=seconds,
                bpf_filter=ctx.options.get("bpf", ""),
            )
            source = f"live:{ctx.options.get('interface', 'default')}"
        else:
            pcap = ctx.options["pcap"]
            packets = read_pcap(pcap)
            source = f"pcap:{pcap}"

        findings = analyze_packets(packets)
        return ModuleResult(
            name=self.name,
            status=ModuleStatus.ok,
            findings=findings,
            raw={"source": source, "packets_analyzed": len(packets)},
        )
