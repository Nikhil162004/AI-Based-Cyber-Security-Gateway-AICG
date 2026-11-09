import csv
import os


INPUT_FILE = "dataset/traffic_energy_features.csv"
OUTPUT_FILE = "dataset/traffic_energy_analysis.csv"


def calculate_baseline(rows):
    normal_energy = [
        float(row["energy_estimate"])
        for row in rows
        if row.get("label") == "NORMAL"
    ]

    if not normal_energy:
        raise ValueError(
            "No NORMAL energy observations found."
        )

    return sum(normal_energy) / len(normal_energy)


def determine_cause(row, baseline_energy):
    energy = float(row["energy_estimate"])
    packets_per_second = float(
        row["packets_per_second"]
    )

    deviation = energy - baseline_energy

    if baseline_energy > 0:
        increase_percent = (
            deviation / baseline_energy
        ) * 100
    else:
        increase_percent = 0.0

    label = row.get("label", "")

    # DDoS-specific cause identification
    if (
        label == "DDOS_UDP"
        and packets_per_second > 500
    ):
        cause = "High-rate UDP flooding"

    elif packets_per_second > 100:
        cause = "High network traffic activity"

    elif deviation > 0:
        cause = "Elevated device activity"

    else:
        cause = "Normal traffic activity"

    return (
        round(deviation, 4),
        round(increase_percent, 2),
        cause
    )


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
        print("ERROR: No energy data found.")
        return

    baseline_energy = calculate_baseline(rows)

    analysis_rows = []

    for row in rows:

        (
            deviation,
            increase_percent,
            cause
        ) = determine_cause(
            row,
            baseline_energy
        )

        combined = dict(row)

        combined["baseline_energy"] = round(
            baseline_energy,
            4
        )

        combined["energy_deviation"] = deviation

        combined["energy_increase_percent"] = (
            increase_percent
        )

        combined["energy_cause"] = cause

        analysis_rows.append(combined)

    fieldnames = list(
        analysis_rows[0].keys()
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
            analysis_rows
        )

    print("=" * 70)
    print("ENERGY BASELINE & CAUSE ANALYSIS")
    print("=" * 70)

    print(
        f"Normal baseline energy: "
        f"{baseline_energy:.4f}"
    )

    print(
        f"Input : {INPUT_FILE}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print(
        f"Windows: {len(analysis_rows)}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
