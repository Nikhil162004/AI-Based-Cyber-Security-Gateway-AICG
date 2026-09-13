import csv
import os


INPUT_FILE = "dataset/traffic_energy_analysis.csv"
OUTPUT_FILE = "results/energy_analysis_summary.csv"


def main():

    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    if not rows:
        print("ERROR: No data found.")
        return

    normal_rows = [
        row for row in rows
        if row["label"] == "NORMAL"
    ]

    ddos_rows = [
        row for row in rows
        if row["label"] == "DDOS_UDP"
    ]

    def average(rows, column):
        if not rows:
            return 0.0

        return sum(
            float(row[column])
            for row in rows
        ) / len(rows)

    summary = [
        {
            "scenario": "NORMAL",
            "windows": len(normal_rows),
            "average_packet_rate":
                round(
                    average(
                        normal_rows,
                        "packets_per_second"
                    ),
                    2
                ),
            "average_energy":
                round(
                    average(
                        normal_rows,
                        "energy_estimate"
                    ),
                    2
                ),
            "average_tx_activity":
                round(
                    average(
                        normal_rows,
                        "tx_activity"
                    ),
                    2
                ),
            "average_rx_activity":
                round(
                    average(
                        normal_rows,
                        "rx_activity"
                    ),
                    2
                ),
            "average_cpu_activity":
                round(
                    average(
                        normal_rows,
                        "cpu_activity"
                    ),
                    2
                ),
            "average_energy_increase_percent":
                round(
                    average(
                        normal_rows,
                        "energy_increase_percent"
                    ),
                    2
                )
        },
        {
            "scenario": "DDOS_UDP",
            "windows": len(ddos_rows),
            "average_packet_rate":
                round(
                    average(
                        ddos_rows,
                        "packets_per_second"
                    ),
                    2
                ),
            "average_energy":
                round(
                    average(
                        ddos_rows,
                        "energy_estimate"
                    ),
                    2
                ),
            "average_tx_activity":
                round(
                    average(
                        ddos_rows,
                        "tx_activity"
                    ),
                    2
                ),
            "average_rx_activity":
                round(
                    average(
                        ddos_rows,
                        "rx_activity"
                    ),
                    2
                ),
            "average_cpu_activity":
                round(
                    average(
                        ddos_rows,
                        "cpu_activity"
                    ),
                    2
                ),
            "average_energy_increase_percent":
                round(
                    average(
                        ddos_rows,
                        "energy_increase_percent"
                    ),
                    2
                )
        }
    ]

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        newline=""
    ) as file:

        fieldnames = [
            "scenario",
            "windows",
            "average_packet_rate",
            "average_energy",
            "average_tx_activity",
            "average_rx_activity",
            "average_cpu_activity",
            "average_energy_increase_percent"
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(summary)

    print("=" * 70)
    print("ENERGY ANALYSIS SUMMARY")
    print("=" * 70)

    for row in summary:

        print(
            f"\nScenario: {row['scenario']}"
        )

        print(
            f"Windows: "
            f"{row['windows']}"
        )

        print(
            f"Average packet rate: "
            f"{row['average_packet_rate']} pkt/s"
        )

        print(
            f"Average energy estimate: "
            f"{row['average_energy']}"
        )

        print(
            f"Average TX activity: "
            f"{row['average_tx_activity']}"
        )

        print(
            f"Average RX activity: "
            f"{row['average_rx_activity']}"
        )

        print(
            f"Average CPU activity: "
            f"{row['average_cpu_activity']}"
        )

        print(
            f"Average energy increase: "
            f"{row['average_energy_increase_percent']}%"
        )

    print("\n" + "=" * 70)
    print(f"Output: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
