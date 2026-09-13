from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import os

OUTPUT_FILE = "dataset/traffic_data.csv"

os.makedirs("dataset", exist_ok=True)

FIELDNAMES = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "tcp_flags"
]


def create_dataset():

    if not os.path.exists(OUTPUT_FILE):

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


def process_packet(packet):

    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    packet_size = len(packet)

    source_port = ""
    destination_port = ""
    tcp_flags = ""

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        tcp_flags = str(
            packet[TCP].flags
        )

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif packet.haslayer(ICMP):

        protocol = "ICMP"

    else:

        protocol = str(
            ip_layer.proto
        )

    print(
        f"[{timestamp}] "
        f"{source_ip} -> {destination_ip} | "
        f"{protocol} | "
        f"Size: {packet_size} | "
        f"Flags: {tcp_flags}"
    )

    with open(
        OUTPUT_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDNAMES
        )

        writer.writerow({
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_size": packet_size,
            "tcp_flags": tcp_flags
        })


create_dataset()

print("=" * 70)
print("AI-EDGE DDoS GATEWAY")
print("Network Traffic Monitor")
print("=" * 70)
print(
    f"Saving traffic data to: {OUTPUT_FILE}"
)
print("Monitoring interface: eth0")
print("TCP flag extraction: ENABLED")
print("Press CTRL+C to stop.")
print("=" * 70)


sniff(
    iface="eth0",
    prn=process_packet,
    store=False
)
