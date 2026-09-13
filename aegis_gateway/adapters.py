"""Adapters that preserve input provenance when importing NS-3, PCAP, or Cooja evidence."""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from .schema import Provenance, TelemetryEvent


def ns3_csv_events(path: Path, scenario_id: str | None = None) -> Iterator[TelemetryEvent]:
    """Map legacy NS-3 feature CSVs or packet trace CSVs into canonical windows.

    Preserves provenance as SIMULATED.
    """
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])

        # Case A: Raw packet-level trace (tshark / ns3 packet dumps)
        if "frame.time_epoch" in fieldnames or "frame.len" in fieldnames:
            buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
            for row in reader:
                try:
                    epoch = float(row.get("frame.time_epoch", 0.0))
                    bucket_id = int(epoch)
                except (ValueError, TypeError):
                    bucket_id = 0
                buckets[bucket_id].append(row)

            for bucket_id, packets in sorted(buckets.items()):
                count = len(packets)
                total_bytes = sum(int(p.get("frame.len", 0)) for p in packets)
                srcs = {p.get("ip.src") for p in packets if p.get("ip.src")}
                dsts = {p.get("ip.dst") for p in packets if p.get("ip.dst")}
                first_src = next(iter(srcs), None)
                first_dst = next(iter(dsts), None)
                proto_raw = packets[0].get("ip.proto", "")
                protocol = "UDP" if proto_raw == "17" else "TCP" if proto_raw == "6" else "ICMP" if proto_raw == "1" else "IP"
                is_attack = "attacker" in path.name.lower() or (scenario_id and "attack" in scenario_id.lower())
                label = "ATTACK" if is_attack else "NORMAL"
                attack_type = (scenario_id or "ns3_ddos_udp") if is_attack else None

                yield TelemetryEvent(
                    source_type="NS3",
                    source_id=path.name,
                    device_id=first_src or "NS3-NODE",
                    src_ip=first_src,
                    dst_ip=first_dst,
                    protocol=protocol,
                    packet_count=count,
                    byte_count=total_bytes,
                    packet_rate=float(count),
                    byte_rate=float(total_bytes),
                    packet_size=float(total_bytes / count) if count else 0.0,
                    unique_sources=len(srcs) or 1,
                    unique_destinations=len(dsts) or 1,
                    flow_id=f"ns3-win-{bucket_id}",
                    attack_type=attack_type,
                    label=label,
                    scenario_id=scenario_id or ("ns3_attack" if is_attack else "ns3_normal"),
                    dataset_id=path.stem,
                    provenance=Provenance.SIMULATED.value,
                ).normalize()
            return

        # Case B: Windowed feature CSV (e.g. ns3_low_v1_features.csv)
        for index, row in enumerate(reader):
            def number(*names: str, integer: bool = False):
                for name in names:
                    value = row.get(name)
                    if value not in (None, ""):
                        return int(float(value)) if integer else float(value)
                return None

            raw_label = (row.get("label") or "").upper()
            is_normal = raw_label in ("", "NORMAL", "BASELINE_V1", "BENIGN", "0")
            label = "NORMAL" if is_normal else "ATTACK"
            attack_type = None if is_normal else (scenario_id or row.get("label") or "ns3_controlled_attack")

            packet_count = number("packet_count", "packets_total", integer=True) or 0
            byte_count = number("bytes_total", "byte_count", integer=True) or 0
            packet_rate = number("packets_per_second", "packet_rate")
            if packet_rate is None:
                packet_rate = float(packet_count)
            byte_rate = number("bytes_per_second", "byte_rate")
            if byte_rate is None:
                byte_rate = float(byte_count)
            packet_size = number("average_packet_size", "packet_size")
            if packet_size is None and packet_count > 0:
                packet_size = round(byte_count / packet_count, 2)

            udp_c = number("udp_count", integer=True) or 0
            tcp_c = number("tcp_count", integer=True) or 0
            icmp_c = number("icmp_count", integer=True) or 0
            syn_c = number("syn_count", integer=True) or 0

            protocol = row.get("protocol") or ("UDP" if udp_c >= tcp_c and udp_c >= icmp_c and udp_c > 0 else "TCP" if tcp_c > 0 else "ICMP" if icmp_c > 0 else "UDP")
            tcp_flags = "S" if syn_c > 0 else None

            yield TelemetryEvent(
                source_type="NS3",
                source_id=path.name,
                device_id=row.get("source") or ("ATK-01" if not is_normal else "SENSOR-01"),
                packet_count=packet_count,
                byte_count=byte_count,
                packet_rate=packet_rate,
                byte_rate=byte_rate,
                packet_size=packet_size,
                unique_sources=number("unique_sources", integer=True) or (4 if not is_normal else 2),
                unique_destinations=number("unique_destinations", integer=True) or 1,
                flow_id=f"ns3-{index}",
                protocol=protocol,
                tcp_flags=tcp_flags,
                attack_type=attack_type,
                label=label,
                scenario_id=scenario_id or row.get("scenario") or ("ns3_attack" if not is_normal else "ns3_normal"),
                dataset_id=path.stem,
                provenance=Provenance.SIMULATED.value,
            ).normalize()


def cooja_csv_events(path: Path, scenario_id: str | None = None) -> Iterator[TelemetryEvent]:
    """Map Contiki-NG / Cooja 6LoWPAN mote simulation CSV windows to canonical telemetry.

    Provenance is recorded as SIMULATED (Cooja mote emulation).
    """
    with path.open(encoding="utf-8", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle)):
            def num(name: str, default: float = 0.0) -> float:
                val = row.get(name)
                try:
                    return float(val) if val not in (None, "") else default
                except (ValueError, TypeError):
                    return default

            raw_label = (row.get("label") or "").upper()
            is_normal = raw_label in ("NORMAL", "BENIGN", "0", "")
            label = "NORMAL" if is_normal else "ATTACK"
            attack_type = None if is_normal else (scenario_id or "cooja_mote_flood")

            packet_count = int(num("packets_in_window", 1.0))
            packet_rate = num("packet_rate_mean", float(packet_count))
            byte_rate = num("byte_rate_mean", packet_rate * 40.0)
            radio_ratio = num("radio_activity_ratio_mean", 0.0)
            node_type = row.get("node_type") or "sensor"
            node_id = row.get("node_id") or "1"
            device_id = f"COOJA-{node_type.upper()}-{node_id}"

            yield TelemetryEvent(
                source_type="COOJA",
                source_id=path.name,
                device_id=device_id,
                protocol="IEEE_802_15_4_6LOWPAN",
                protocol_layer="LINK_NETWORK",
                packet_count=packet_count,
                byte_count=round(byte_rate),
                packet_rate=round(packet_rate, 4),
                byte_rate=round(byte_rate, 2),
                packet_size=round(byte_rate / packet_rate, 2) if packet_rate > 0 else 40.0,
                unique_sources=1,
                unique_destinations=1,
                flow_id=f"cooja-{node_id}-{index}",
                radio_tx=round(radio_ratio * 100.0, 2),
                label=label,
                attack_type=attack_type,
                scenario_id=scenario_id or ("cooja_attack" if not is_normal else "cooja_normal"),
                dataset_id=path.stem,
                provenance=Provenance.SIMULATED.value,
            ).normalize()


def pcap_events(path: Path) -> Iterator[TelemetryEvent]:
    """Replay a local PCAP as REPLAYED observations packet-by-packet.

    Requires Scapy. Preserves REPLAYED provenance; no socket transmission occurs.
    """
    from scapy.all import ICMP, IP, TCP, UDP, rdpcap  # type: ignore

    for index, packet in enumerate(rdpcap(str(path))):
        if not packet.haslayer(IP):
            continue
        ip = packet[IP]
        protocol, sport, dport, flags, icmp_type = str(ip.proto), None, None, None, None
        if packet.haslayer(TCP):
            protocol, sport, dport, flags = "TCP", int(packet[TCP].sport), int(packet[TCP].dport), str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol, sport, dport = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            protocol, icmp_type = "ICMP", str(packet[ICMP].type)
        size = len(packet)

        yield TelemetryEvent(
            source_type="PCAP_REPLAY",
            source_id=path.name,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=sport,
            dst_port=dport,
            protocol=protocol,
            packet_count=1,
            byte_count=size,
            packet_rate=1.0,
            byte_rate=float(size),
            packet_size=float(size),
            flow_id=f"pcap-{index}",
            unique_sources=1,
            unique_destinations=1,
            tcp_flags=flags,
            icmp_type=icmp_type,
            dataset_id=path.stem,
            provenance=Provenance.REPLAYED.value,
        ).normalize()


def pcap_window_events(path: Path, window_seconds: float = 1.0, max_windows: int = 100) -> Iterator[TelemetryEvent]:
    """Aggregate a local PCAP into time-windowed observations.

    Prevents historian flooding while providing realistic window telemetry.
    """
    from scapy.all import ICMP, IP, TCP, UDP, rdpcap  # type: ignore

    buckets: dict[int, list[Any]] = defaultdict(list)
    start_time = None
    for packet in rdpcap(str(path)):
        if not packet.haslayer(IP):
            continue
        pkt_time = float(packet.time)
        if start_time is None:
            start_time = pkt_time
        rel_time = max(0.0, pkt_time - start_time)
        bucket_idx = int(rel_time / window_seconds)
        buckets[bucket_idx].append(packet)

    for bucket_idx in sorted(buckets.keys())[:max_windows]:
        pkts = buckets[bucket_idx]
        count = len(pkts)
        total_bytes = sum(len(p) for p in pkts)
        srcs = {p[IP].src for p in pkts}
        dsts = {p[IP].dst for p in pkts}
        tcp_count = sum(1 for p in pkts if p.haslayer(TCP))
        udp_count = sum(1 for p in pkts if p.haslayer(UDP))
        icmp_count = sum(1 for p in pkts if p.haslayer(ICMP))
        has_syn = any(p.haslayer(TCP) and "S" in str(p[TCP].flags) for p in pkts)
        protocol = "UDP" if udp_count >= tcp_count and udp_count >= icmp_count and udp_count > 0 else "TCP" if tcp_count > 0 else "ICMP" if icmp_count > 0 else "IP"

        yield TelemetryEvent(
            source_type="PCAP_REPLAY",
            source_id=path.name,
            src_ip=next(iter(srcs), None),
            dst_ip=next(iter(dsts), None),
            protocol=protocol,
            packet_count=count,
            byte_count=total_bytes,
            packet_rate=round(count / window_seconds, 2),
            byte_rate=round(total_bytes / window_seconds, 2),
            packet_size=round(total_bytes / count, 2) if count else 0.0,
            unique_sources=len(srcs),
            unique_destinations=len(dsts),
            tcp_flags="S" if has_syn else None,
            flow_id=f"pcap-win-{bucket_idx}",
            dataset_id=path.stem,
            provenance=Provenance.REPLAYED.value,
        ).normalize()
