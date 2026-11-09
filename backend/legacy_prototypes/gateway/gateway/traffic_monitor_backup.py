from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import os

OUTPUT_FILE = "dataset/traffic_data.csv"

# Create dataset directory if it doesn't exist
os.makedirs("dataset", exist_ok=True)

# Create CSV file and header if it doesn't exist
if not os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "packet_size"
        ])


def process_packet(packet):

    # We are interested in IP packets
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst
    packet_size = len(packet)

    source_port = ""
    destination_port = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    else:
        protocol = ip_layer.proto

    # Display packet information
    print(
        f"[{timestamp}] "
        f"{source_ip} -> {destination_ip} | "
        f"{protocol} | "
        f"Size: {packet_size}"
    )

    # Save packet information
    with open(OUTPUT_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size
        ])


print("=" * 70)
print("AI-EDGE DDoS GATEWAY")
print("Network Traffic Monitor")
print("=" * 70)
print(f"Saving traffic data to: {OUTPUT_FILE}")
print("Starting packet capture...")
print("Press CTRL+C to stop.")
print("=" * 70)

sniff(
    iface="eth0",
    prn=process_packet,
    store=False
)
