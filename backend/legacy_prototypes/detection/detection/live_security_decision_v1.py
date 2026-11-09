#!/usr/bin/env python3

"""
Live Security Decision V1

Consumes the output of live_ml_inference_v1.py and converts
the ML prediction into a security decision.

This is a DECISION layer only.

It does not:
- block packets
- modify firewall rules
- rate-limit traffic
- isolate devices
- modify routing
- disconnect interfaces
"""

import csv
import math
from pathlib import Path


INPUT_FILE = Path("dataset/live_predictions_v1.csv")
OUTPUT_FILE = Path("results/live_security_decisions_v1.csv")


ALLOWED_PREDICTIONS = {
    "NORMAL",
    "DDOS_UDP",
}


def validate_probability(value, name):
    value = float(value)

    if not math.isfinite(value):
        raise ValueError(
            f"{name} must be finite"
        )

    if not 0.0 <= value <= 1.0:
        raise ValueError(
            f"{name} must be between 0 and 1"
        )

    return value


def decide(row):
    prediction = row["prediction"]

    if prediction not in ALLOWED_PREDICTIONS:
        raise ValueError(
            f"Unsupported prediction: {prediction}"
        )

    ddos_probability = validate_probability(
        row["ddos_probability"],
        "ddos_probability",
    )

    normal_probability = validate_probability(
        row["normal_probability"],
        "normal_probability",
    )

    probability_sum = (
        ddos_probability
        + normal_probability
    )

    if abs(probability_sum - 1.0) > 1e-6:
        raise ValueError(
            "Probabilities must sum to 1"
        )

    if prediction == "DDOS_UDP":
        action = "ALERT"
        severity = "HIGH"
    else:
        action = "ALLOW"
        severity = "NORMAL"

    return {
        "prediction": prediction,
        "ddos_probability": ddos_probability,
        "normal_probability": normal_probability,
        "action": action,
        "severity": severity,
    }


def main():
    print("=" * 70)
    print("LIVE SECURITY DECISION V1")
    print("=" * 70)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        newline="",
        encoding="utf-8",
    ) as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    required = {
        "window_start",
        "packet_count",
        "prediction",
        "ddos_probability",
        "normal_probability",
    }

    actual = set(reader.fieldnames or [])
    missing = required - actual

    if missing:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(sorted(missing))
        )

    results = []

    for row in rows:
        decision = decide(row)

        results.append({
            "window_start": row["window_start"],
            "packet_count": row["packet_count"],
            "packets_per_second": row["packets_per_second"],
            "prediction": decision["prediction"],
            "ddos_probability": (
                f"{decision['ddos_probability']:.6f}"
            ),
            "normal_probability": (
                f"{decision['normal_probability']:.6f}"
            ),
            "action": decision["action"],
            "severity": decision["severity"],
        })

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "window_start",
        "packet_count",
        "packets_per_second",
        "prediction",
        "ddos_probability",
        "normal_probability",
        "action",
        "severity",
    ]

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(results)

    print("\nInput windows:", len(rows))
    print("Output:", OUTPUT_FILE)

    print("\nDecision distribution:")

    decisions = {}

    for result in results:
        key = (
            result["action"],
            result["severity"],
        )
        decisions[key] = decisions.get(key, 0) + 1

    for (action, severity), count in sorted(decisions.items()):
        print(
            f"{action} / {severity}: {count}"
        )

    print("\nLive security decision generation complete.")

    print("=" * 70)
    print("TASK #173 COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
