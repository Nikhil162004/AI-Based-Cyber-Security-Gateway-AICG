import csv
import os


INPUT_FILE = "results/energy_aware_detection.csv"
OUTPUT_FILE = "results/mitigation_decisions.csv"

PACKET_RATE_THRESHOLD = 100.0
DDOS_PROBABILITY_THRESHOLD = 0.80


def decide_mitigation(row):

    prediction = row["model_prediction"]

    packet_rate = float(
        row["packet_rate"]
    )

    ddos_probability = float(
        row["ddos_probability"]
    )

    if (
        prediction == "DDOS_UDP"
        and packet_rate >= PACKET_RATE_THRESHOLD
        and ddos_probability >= DDOS_PROBABILITY_THRESHOLD
    ):
        action = "RATE_LIMIT_AND_DROP"
        reason = "High-confidence DDoS traffic"

    elif prediction == "DDOS_UDP":
        action = "RATE_LIMIT"
        reason = "DDoS detected but below mitigation threshold"

    else:
        action = "ALLOW"
        reason = "Normal traffic"

    return action, reason


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

    results = []

    for row in rows:

        action, reason = decide_mitigation(
            row
        )

        results.append({
            "window_start":
                row["window_start"],

            "model_prediction":
                row["model_prediction"],

            "ddos_probability":
                row["ddos_probability"],

            "packet_rate":
                row["packet_rate"],

            "energy_increase_percent":
                row["energy_increase_percent"],

            "energy_cause":
                row["energy_cause"],

            "mitigation_action":
                action,

            "mitigation_reason":
                reason
        })

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    fieldnames = [
        "window_start",
        "model_prediction",
        "ddos_probability",
        "packet_rate",
        "energy_increase_percent",
        "energy_cause",
        "mitigation_action",
        "mitigation_reason"
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
        writer.writerows(results)

    print("=" * 70)
    print("DDoS MITIGATION DECISION ENGINE")
    print("=" * 70)

    print(
        f"Input windows: {len(rows)}"
    )

    print(
        "Mitigation decisions generated successfully."
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
