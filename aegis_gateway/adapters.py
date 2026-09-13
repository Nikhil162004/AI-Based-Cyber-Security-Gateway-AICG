"""Adapters that preserve input provenance when importing NS-3 or PCAP evidence."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from .schema import Provenance, TelemetryEvent


def ns3_csv_events(path: Path, scenario_id: str | None = None) -> Iterator[TelemetryEvent]:
    """Map legacy NS-3 feature CSVs into canonical windows without fabricating fields."""
    with path.open(encoding="utf-8", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle)):
            def number(*names: str, integer: bool = False):
                for name in names:
                    value = row.get(name)
                    if value not in (None, ""):
                        return int(float(value)) if integer else float(value)
                return None
            label = row.get("label")
            yield TelemetryEvent(
                source_type="NS3", source_id=path.name, device_id=row.get("source") or "NS3-NODE",
                packet_count=number("packet_count", integer=True), byte_count=number("bytes_total", "byte_count", integer=True),
                packet_rate=number("packets_per_second", "packet_rate"), byte_rate=number("bytes_per_second", "byte_rate"),
                packet_size=number("average_packet_size", "packet_size"), unique_sources=number("unique_sources", integer=True),
                unique_destinations=number("unique_destinations", integer=True), flow_id=f"ns3-{index}", protocol=row.get("protocol"),
                attack_type=None if label in (None, "NORMAL", "BASELINE_V1") else "ns3_controlled_attack",
                label=label, scenario_id=scenario_id or row.get("scenario") or "ns3-import", dataset_id=path.stem,
                provenance=Provenance.SIMULATED.value,
            ).normalize()


def pcap_events(path: Path) -> Iterator[TelemetryEvent]:
    """Replay a local PCAP as REPLAYED observations. Requires the optional Scapy dependency."""
    from scapy.all import ICMP, IP, TCP, UDP, rdpcap  # type: ignore
    for index, packet in enumerate(rdpcap(str(path))):
        if not packet.haslayer(IP):
            continue
        ip = packet[IP]; protocol, sport, dport, flags, icmp_type = str(ip.proto), None, None, None, None
        if packet.haslayer(TCP): protocol, sport, dport, flags = "TCP", int(packet[TCP].sport), int(packet[TCP].dport), str(packet[TCP].flags)
        elif packet.haslayer(UDP): protocol, sport, dport = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
        elif packet.haslayer(ICMP): protocol, icmp_type = "ICMP", str(packet[ICMP].type)
        size = len(packet)
        yield TelemetryEvent(source_type="PCAP_REPLAY", source_id=path.name, src_ip=ip.src, dst_ip=ip.dst, src_port=sport, dst_port=dport,
            protocol=protocol, packet_count=1, byte_count=size, packet_rate=1, byte_rate=size, packet_size=size, flow_id=f"pcap-{index}",
            unique_sources=1, unique_destinations=1, tcp_flags=flags, icmp_type=icmp_type, dataset_id=path.stem,
            provenance=Provenance.REPLAYED.value).normalize()
