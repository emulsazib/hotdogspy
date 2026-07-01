"""Packet ingestion: read a .pcap (safe default) or live-capture (scope-gated).

Returns normalized :class:`PacketRecord` objects for :mod:`analyzer`. scapy is
imported lazily so the rest of the tool works without it.
"""
from __future__ import annotations

from typing import List

from .analyzer import PacketRecord


def read_pcap(path: str, limit: int = 5000) -> List[PacketRecord]:
    """Read a .pcap/.pcapng file into PacketRecords using scapy."""
    try:
        from scapy.all import IP, IPv6, TCP, UDP, Raw, rdpcap
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("scapy is required to read pcap files (pip install scapy)") from exc

    records: List[PacketRecord] = []
    packets = rdpcap(path)
    for pkt in packets[:limit]:
        src = dst = ""
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst

        src_port = dst_port = None
        proto = ""
        if pkt.haslayer(TCP):
            src_port, dst_port, proto = int(pkt[TCP].sport), int(pkt[TCP].dport), "TCP"
        elif pkt.haslayer(UDP):
            src_port, dst_port, proto = int(pkt[UDP].sport), int(pkt[UDP].dport), "UDP"

        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        records.append(
            PacketRecord(src=src, dst=dst, src_port=src_port, dst_port=dst_port,
                         protocol=proto, payload=payload)
        )
    return records


def live_capture(interface: str, seconds: int, bpf_filter: str = "") -> List[PacketRecord]:
    """Live capture for a bounded window (scope-gated by the plugin).

    Requires appropriate privileges. Prefer pcap ingestion for reproducibility.
    """
    try:
        from scapy.all import IP, IPv6, TCP, UDP, Raw, sniff
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("scapy is required for live capture") from exc

    captured = sniff(iface=interface or None, timeout=seconds, filter=bpf_filter or None)
    records: List[PacketRecord] = []
    for pkt in captured:
        src = dst = ""
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        src_port = dst_port = None
        proto = ""
        if pkt.haslayer(TCP):
            src_port, dst_port, proto = int(pkt[TCP].sport), int(pkt[TCP].dport), "TCP"
        elif pkt.haslayer(UDP):
            src_port, dst_port, proto = int(pkt[UDP].sport), int(pkt[UDP].dport), "UDP"
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        records.append(
            PacketRecord(src=src, dst=dst, src_port=src_port, dst_port=dst_port,
                         protocol=proto, payload=payload)
        )
    return records
