#!/usr/bin/env python3

"""
Live Feature Adapter V1

Converts packet-level traffic_data.csv records into the exact
15-feature representation expected by the legacy ddos_model.pkl.

This component:
- uses fixed 1-second windows
- does NOT require ground-truth labels
- does NOT perform mitigation or packet blocking
- preserves the legacy feature semantics
"""

import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

INPUT_FILE = Path("dataset/traffic_data.csv")
OUTPUT_FILE = Path("dataset/live_features_v1.csv")

WINDOW_SECONDS = 1

FEATURES = [
    "packet_count",
    "bytes_total",
    "packets_per_second",
    "bytes_per_second",
    "unique_sources",
    "unique_destinations",
    "udp_count",
    "tcp_count",
    "icmp_count",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "average_packet_size",
    "flow_count",
]


def parse_timestamp(value):
    return datetime.strptime(
        value,
        "%Y-%m-%d %H:%M:%S.%f"
    )


def build_window_features(rows, window_start):
    packet_count = len(rows)

    bytes_total = 0

    sources = set()
    destinations = set()
    flows = set()

    udp_count = 0
    tcp_count = 0
    icmp_count = 0

    syn_count = 0
    ack_count = 0
    rst_count = 0
    fin_count = 0

    packet_sizes = []

    for row in rows:
        source = row["source_ip"]
        destination = row["destination_ip"]
        protocol = row["protocol"].upper()

        packet_size = int(row["packet_size"])

        bytes_total += packet_size

        sources.add(source)
        destinations.add(destination)

        packet_sizes.append(packet_size)

        flows.add((
            source,
            destination,
            row["source_port"],
            row["destination_port"],
            protocol,
        ))

        if protocol == "UDP":
            udp_count += 1

        elif protocol == "TCP":
            tcp_count += 1

            flags = row.get("tcp_flags", "")

            if "S" in flags:
                syn_count += 1

            if "A" in flags:
                ack_count += 1

            if "R" in flags:
                rst_count += 1

            if "F" in flags:
                fin_count += 1

        elif protocol == "ICMP":
            icmp_count += 1

    packets_per_second = (
        packet_count / WINDOW_SECONDS
    )

    bytes_per_second = (
        bytes_total / WINDOW_SECONDS
    )

    average_packet_size = (
        sum(packet_sizes) / len(packet_sizes)
        if packet_sizes
        else 0
    )

    return {
        "window_start": window_start.strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        ),
        "packet_count": packet_count,
        "bytes_total": bytes_total,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "unique_sources": len(sources),
        "unique_destinations": len(destinations),
        "udp_count": udp_count,
        "tcp_count": tcp_count,
        "icmp_count": icmp_count,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "rst_count": rst_count,
        "fin_count": fin_count,
        "average_packet_size": average_packet_size,
        "flow_count": len(flows),
    }


def load_packets():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        newline="",
        encoding="utf-8",
    ) as f:
        reader = csv.DictReader(f)

        required = {
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "packet_size",
            "tcp_flags",
        }

        actual = set(reader.fieldnames or [])

        missing = required - actual

        if missing:
            raise ValueError(
                "Missing required columns: "
                + ", ".join(sorted(missing))
            )

        packets = []

        for row in reader:
            row["_timestamp"] = parse_timestamp(
                row["timestamp"]
            )
            packets.append(row)

    packets.sort(key=lambda row: row["_timestamp"])

    return packets


def create_windows(packets):
    if not packets:
        return []

    first_timestamp = packets[0]["_timestamp"]

    windows = defaultdict(list)

    for row in packets:
        elapsed = (
            row["_timestamp"] - first_timestamp
        ).total_seconds()

        window_id = int(elapsed / WINDOW_SECONDS)

        windows[window_id].append(row)

    results = []

    for window_id in sorted(windows):
        window_start = (
            first_timestamp
            + __import__("datetime").timedelta(
                seconds=window_id * WINDOW_SECONDS
            )
        )

        results.append(
            build_window_features(
                windows[window_id],
                window_start,
            )
        )

    return results


def write_features(rows):
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "window_start",
        *FEATURES,
    ]

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(row)


def main():
    print("=" * 60)
    print("LIVE FEATURE ADAPTER V1")
    print("=" * 60)

    packets = load_packets()

    print(f"Input packets: {len(packets)}")

    windows = create_windows(packets)

    print(f"Feature windows: {len(windows)}")

    write_features(windows)

    print(f"Output: {OUTPUT_FILE}")

    print("\nFeature schema:")
    for i, feature in enumerate(FEATURES, 1):
        print(f"{i:2d}. {feature}")

    print("\nAdapter completed successfully.")


if __name__ == "__main__":
    main()
