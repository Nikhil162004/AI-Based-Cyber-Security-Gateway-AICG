import csv
from datetime import datetime,timedelta 


NORMAL_INPUT = "dataset/ns3_normal_traffic.csv"
DDOS_INPUT = "dataset/ns3_attacker_traffic.csv"

OUTPUT_FILE = "dataset/ns3_ml_packets.csv"


FIELDNAMES = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "tcp_flags",
    "label"
]


def convert_file(input_file, label, output_rows):

    with open(input_file, "r", newline="") as file:

        reader = csv.DictReader(file)

        for row in reader:

                epoch = float(row["frame.time_epoch"])

                simulation_time = float(
                    row["frame.time_epoch"]
                )

                base_time = datetime(
                    2026,
                    8,
                    21,
                    5,
                    0,
                    0
                )

                timestamp = (
                    base_time +
                    timedelta(seconds=simulation_time)
                ).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )

                protocol_number = row["ip.proto"]

                if protocol_number == "17":
                    protocol = "UDP"
                elif protocol_number == "6":
                    protocol = "TCP"
                elif protocol_number == "1":
                    protocol = "ICMP"
                else:
                    protocol = "OTHER"
                output_rows.append({
                "timestamp": timestamp,

                "source_ip":
                    row["ip.src"],

                "destination_ip":
                    row["ip.dst"],

                "protocol":
                    protocol,

                "source_port":
                    row.get("udp.srcport", ""),

                "destination_port":
                    row.get("udp.dstport", ""),

                "packet_size":
                    row["frame.len"],

                "tcp_flags":
                    "",

                "label":
                    label
            })


def main():

    output_rows = []

    print("=" * 60)
    print("NS-3 DATASET CONVERTER")
    print("=" * 60)

    print("\nReading NORMAL traffic...")
    convert_file(
        NORMAL_INPUT,
        "NORMAL",
        output_rows
    )

    normal_count = len(output_rows)

    print(
        f"Normal packets: {normal_count}"
    )

    print("\nReading DDoS traffic...")

    before_ddos = len(output_rows)

    convert_file(
        DDOS_INPUT,
        "DDOS_UDP",
        output_rows
    )

    ddos_count = (
        len(output_rows) - before_ddos
    )

    print(
        f"DDoS packets: {ddos_count}"
    )

    with open(
        OUTPUT_FILE,
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDNAMES
        )

        writer.writeheader()
        writer.writerows(output_rows)

    print("\n" + "=" * 60)
    print("CONVERSION COMPLETE")
    print("=" * 60)

    print(
        f"Total packets: {len(output_rows)}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print("=" * 60)


if __name__ == "__main__":
    main()
