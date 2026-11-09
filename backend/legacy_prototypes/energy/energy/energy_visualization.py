import csv
import os

import matplotlib.pyplot as plt


INPUT_FILE = "dataset/traffic_energy_analysis.csv"
OUTPUT_DIR = "results/energy_plots"


def read_data():
    with open(INPUT_FILE, "r", newline="") as file:
        return list(csv.DictReader(file))


def average(rows, column):
    return sum(float(row[column]) for row in rows) / len(rows)


def main():

    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    rows = read_data()

    normal = [
        row for row in rows
        if row["label"] == "NORMAL"
    ]

    ddos = [
        row for row in rows
        if row["label"] == "DDOS_UDP"
    ]

    if not normal or not ddos:
        print("ERROR: NORMAL or DDOS data is missing.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    scenarios = ["NORMAL", "DDOS_UDP"]

    packet_rates = [
        average(normal, "packets_per_second"),
        average(ddos, "packets_per_second")
    ]

    energy = [
        average(normal, "energy_estimate"),
        average(ddos, "energy_estimate")
    ]

    tx_activity = [
        average(normal, "tx_activity"),
        average(ddos, "tx_activity")
    ]

    rx_activity = [
        average(normal, "rx_activity"),
        average(ddos, "rx_activity")
    ]

    cpu_activity = [
        average(normal, "cpu_activity"),
        average(ddos, "cpu_activity")
    ]

    # ---------------------------------------------------------
    # 1. PACKET RATE
    # ---------------------------------------------------------

    plt.figure(figsize=(8, 5))

    plt.bar(
        scenarios,
        packet_rates
    )

    plt.title("Normal vs DDoS Packet Rate")
    plt.ylabel("Packets per Second")
    plt.tight_layout()

    plt.savefig(
        f"{OUTPUT_DIR}/packet_rate_comparison.png",
        dpi=150
    )

    plt.close()

    # ---------------------------------------------------------
    # 2. ENERGY
    # ---------------------------------------------------------

    plt.figure(figsize=(8, 5))

    plt.bar(
        scenarios,
        energy
    )

    plt.title("Normal vs DDoS Estimated Energy")
    plt.ylabel("Estimated Energy Activity")
    plt.tight_layout()

    plt.savefig(
        f"{OUTPUT_DIR}/energy_comparison.png",
        dpi=150
    )

    plt.close()

    # ---------------------------------------------------------
    # 3. TX / RX ACTIVITY
    # ---------------------------------------------------------

    plt.figure(figsize=(8, 5))

    x = range(len(scenarios))

    plt.bar(
        [i - 0.2 for i in x],
        tx_activity,
        width=0.4,
        label="TX Activity"
    )

    plt.bar(
        [i + 0.2 for i in x],
        rx_activity,
        width=0.4,
        label="RX Activity"
    )

    plt.xticks(
        list(x),
        scenarios
    )

    plt.title("Normal vs DDoS Network Activity")
    plt.ylabel("Activity")
    plt.legend()
    plt.tight_layout()

    plt.savefig(
        f"{OUTPUT_DIR}/tx_rx_activity.png",
        dpi=150
    )

    plt.close()

    # ---------------------------------------------------------
    # 4. CPU ACTIVITY
    # ---------------------------------------------------------

    plt.figure(figsize=(8, 5))

    plt.bar(
        scenarios,
        cpu_activity
    )

    plt.title("Normal vs DDoS CPU Activity")
    plt.ylabel("CPU Activity")
    plt.tight_layout()

    plt.savefig(
        f"{OUTPUT_DIR}/cpu_activity.png",
        dpi=150
    )

    plt.close()

    # ---------------------------------------------------------
    # 5. ENERGY INCREASE
    # ---------------------------------------------------------

    normal_energy = average(
        normal,
        "energy_estimate"
    )

    ddos_energy = average(
        ddos,
        "energy_estimate"
    )

    increase_percent = (
        (ddos_energy - normal_energy)
        / normal_energy
    ) * 100

    print("=" * 70)
    print("ENERGY VISUALIZATION COMPLETE")
    print("=" * 70)

    print(
        f"Normal energy: {normal_energy:.2f}"
    )

    print(
        f"DDoS energy:   {ddos_energy:.2f}"
    )

    print(
        f"Energy increase: {increase_percent:.2f}%"
    )

    print(
        f"Plots saved in: {OUTPUT_DIR}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
