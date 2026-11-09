import csv
import os


INPUT_FILE = "dataset/ns3_current_features.csv"
OUTPUT_FILE = "dataset/ns3_current_energy_features.csv"


# ============================================================
# RELATIVE ENERGY MODEL
# ============================================================
#
# These are simulation coefficients, NOT physical joule values.
# They allow us to study relative energy behaviour between
# normal and attack traffic.
#

TX_COST = 1.0
RX_COST = 0.7
CPU_COST = 0.2
IDLE_COST_PER_SECOND = 0.05


def calculate_energy(row):
    packet_count = float(row["packet_count"])
    packets_per_second = float(
        row["packets_per_second"]
    )

    udp_count = float(row["udp_count"])
    tcp_count = float(row["tcp_count"])
    icmp_count = float(row["icmp_count"])

    total_protocol_packets = (
        udp_count +
        tcp_count +
        icmp_count
    )

    # --------------------------------------------------------
    # Estimate transmission activity
    # --------------------------------------------------------

    tx_packet_count = packet_count

    tx_activity = (
        tx_packet_count * TX_COST
    )

    # --------------------------------------------------------
    # Estimate reception activity
    #
    # For the initial traffic-level model we use total observed
    # packets as the reception-side activity signal.
    # --------------------------------------------------------

    rx_packet_count = packet_count

    rx_activity = (
        rx_packet_count * RX_COST
    )

    # --------------------------------------------------------
    # CPU processing activity
    # --------------------------------------------------------

    cpu_activity = (
        total_protocol_packets *
        CPU_COST
    )

    # --------------------------------------------------------
    # Idle/base activity
    # --------------------------------------------------------

    idle_activity = IDLE_COST_PER_SECOND

    # --------------------------------------------------------
    # Total relative energy estimate
    # --------------------------------------------------------

    energy_estimate = (
        tx_activity +
        rx_activity +
        cpu_activity +
        idle_activity
    )

    # --------------------------------------------------------
    # Energy rate
    #
    # Current windows are 1 second.
    # --------------------------------------------------------

    energy_rate = energy_estimate

    # --------------------------------------------------------
    # Energy per packet
    # --------------------------------------------------------

    if packet_count > 0:
        energy_per_packet = (
            energy_estimate /
            packet_count
        )
    else:
        energy_per_packet = 0.0

    return {
        "tx_packet_count": int(
            tx_packet_count
        ),

        "rx_packet_count": int(
            rx_packet_count
        ),

        "tx_activity": round(
            tx_activity,
            4
        ),

        "rx_activity": round(
            rx_activity,
            4
        ),

        "cpu_activity": round(
            cpu_activity,
            4
        ),

        "energy_estimate": round(
            energy_estimate,
            4
        ),

        "energy_rate": round(
            energy_rate,
            4
        ),

        "energy_per_packet": round(
            energy_per_packet,
            6
        ),

        "traffic_intensity": round(
            packets_per_second,
            2
        )
    }


def main():

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
        print("ERROR: No feature data found.")
        return

    energy_rows = []

    for row in rows:

        energy_features = calculate_energy(row)

        combined = dict(row)
        combined.update(
            energy_features
        )

        energy_rows.append(combined)

    fieldnames = list(
        energy_rows[0].keys()
    )

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
        writer.writerows(
            energy_rows
        )

    print("=" * 70)
    print("ENERGY FEATURE CALCULATION COMPLETE")
    print("=" * 70)

    print(
        f"Input : {INPUT_FILE}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print(
        f"Windows: {len(energy_rows)}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
