import pandas as pd
import csv
import os
import joblib


MODEL_FILE = "detection/ddos_model.pkl"
INPUT_FILE = "dataset/traffic_energy_analysis.csv"
OUTPUT_FILE = "results/energy_aware_detection.csv"


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
    "flow_count"
]


def main():

    if not os.path.exists(MODEL_FILE):
        print(f"ERROR: {MODEL_FILE} not found.")
        return

    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    model = joblib.load(MODEL_FILE)

    with open(INPUT_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    if not rows:
        print("ERROR: No input data found.")
        return

    results = []

    for row in rows:

        features = [
            float(row[feature])
            for feature in FEATURES
        ]

        feature_data = pd.DataFrame(
            [features],
            columns=FEATURES
        )

        prediction = model.predict(
            feature_data
        )[0]

        probability = model.predict_proba(
            feature_data
        )[0]

        class_probabilities = dict(
            zip(
                model.classes_,
                probability
            )
        )

        result = {
            "window_start": row["window_start"],
            "model_prediction": prediction,
            "actual_label": row["label"],
            "packet_rate": row["packets_per_second"],
            "energy_estimate": row["energy_estimate"],
            "baseline_energy": row["baseline_energy"],
            "energy_deviation": row["energy_deviation"],
            "energy_increase_percent":
                row["energy_increase_percent"],
            "energy_cause": row["energy_cause"],
            "ddos_probability":
                round(
                    class_probabilities.get(
                        "DDOS_UDP",
                        0.0
                    ),
                    4
                ),
            "normal_probability":
                round(
                    class_probabilities.get(
                        "NORMAL",
                        0.0
                    ),
                    4
                )
        }

        results.append(result)

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    fieldnames = [
        "window_start",
        "model_prediction",
        "actual_label",
        "packet_rate",
        "energy_estimate",
        "baseline_energy",
        "energy_deviation",
        "energy_increase_percent",
        "energy_cause",
        "ddos_probability",
        "normal_probability"
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

    correct = sum(
        1
        for row in results
        if row["model_prediction"]
        == row["actual_label"]
    )

    accuracy = (
        correct / len(results)
    ) * 100

    print("=" * 70)
    print("ENERGY-AWARE DDoS DETECTION")
    print("=" * 70)

    print(
        f"Total windows: {len(results)}"
    )

    print(
        f"Correct predictions: {correct}"
    )

    print(
        f"Agreement with labels: {accuracy:.2f}%"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
