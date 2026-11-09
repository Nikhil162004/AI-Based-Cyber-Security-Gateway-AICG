import csv
import os
from datetime import datetime

INPUT_FILE = "dataset/traffic_data.csv"
OUTPUT_FILE = "dataset/traffic_features.csv"

WINDOW_SECONDS = 10


def parse_timestamp(timestamp):
    return datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S.%f"
    )


def calculate_features(rows, window_start):

    packet_count = len(rows)

    bytes_total = sum(
        int(row["packet_size"])
        for row in rows
        if row["packet_size"]
    )

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
        protocol = row["protocol"]

        sources.add(source)
        destinations.add(destination)

        packet_sizes.append(
            int(row["packet_size"])
        )

        flows.add((
            source,
            destination,
            row["source_port"],
            row["destination_port"],
            protocol
        ))

        if protocol == "UDP":

            udp_count += 1

        elif protocol == "TCP":

            tcp_count += 1

            flags = row.get(
                "tcp_flags",
                ""
            )

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
        "window_start":
            window_start.strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            ),

        "packet_count":
            packet_count,

        "bytes_total":
            bytes_total,

        "packets_per_second":
            round(
                packets_per_second,
                2
            ),

        "bytes_per_second":
            round(
                bytes_per_second,
                2
            ),

        "unique_sources":
            len(sources),

        "unique_destinations":
            len(destinations),

        "udp_count":
            udp_count,

        "tcp_count":
            tcp_count,

        "icmp_count":
            icmp_count,

        "syn_count":
            syn_count,

        "ack_count":
            ack_count,

        "rst_count":
            rst_count,

        "fin_count":
            fin_count,

        "average_packet_size":
            round(
                average_packet_size,
                2
            ),

        "flow_count":
            len(flows)
    }


def write_features(feature_rows):

    fieldnames = [
        "window_start",
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
        "flow_count"
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(feature_rows)


def extract_features():

    if not os.path.exists(INPUT_FILE):

        print(
            f"ERROR: {INPUT_FILE} not found."
        )

        return

    with open(
        INPUT_FILE,
        "r",
        newline=""
    ) as file:

        reader = csv.DictReader(file)
        rows = list(reader)

    if not rows:

        print(
            "ERROR: No traffic data found."
        )

        return

    rows.sort(
        key=lambda row:
        parse_timestamp(
            row["timestamp"]
        )
    )

    feature_rows = []

    window_start = parse_timestamp(
        rows[0]["timestamp"]
    )

    window_rows = []

    for row in rows:

        timestamp = parse_timestamp(
            row["timestamp"]
        )

        elapsed = (
            timestamp - window_start
        ).total_seconds()

        if elapsed < WINDOW_SECONDS:

            window_rows.append(row)

        else:

            if window_rows:

                features = calculate_features(
                    window_rows,
                    window_start
                )

                feature_rows.append(
                    features
                )

            window_start = timestamp
            window_rows = [row]

    if window_rows:

        features = calculate_features(
            window_rows,
            window_start
        )

        feature_rows.append(
            features
        )

    write_features(
        feature_rows
    )

    print("=" * 70)
    print(
        "DDoS FEATURE EXTRACTION COMPLETE"
    )
    print("=" * 70)
    print(
        f"Input file:  {INPUT_FILE}"
    )
    print(
        f"Output file: {OUTPUT_FILE}"
    )
    print(
        f"Windows:     {len(feature_rows)}"
    )
    print("=" * 70)


if __name__ == "__main__":
    extract_features()
