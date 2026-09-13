#!/usr/bin/env python3

"""
Live Mitigation Decision V1

Consumes live security decisions and live ML features.

This module produces mitigation RECOMMENDATIONS only.

It does NOT:
- drop packets
- rate-limit traffic
- modify firewall rules
- isolate devices
- change routing
- disconnect interfaces
"""

import csv
import math
from pathlib import Path


INPUT_FILE = Path("results/live_security_decisions_v1.csv")
OUTPUT_FILE = Path("results/live_mitigation_decisions_v1.csv")

PACKET_RATE_THRESHOLD = 100.0
DDOS_PROBABILITY_THRESHOLD = 0.80


def validate_probability(value):
    value = float(value)

    if not math.isfinite(value):
        raise ValueError("DDoS probability must be finite")

    if not 0.0 <= value <= 1.0:
        raise ValueError(
            "DDoS probability must be between 0 and 1"
        )

    return value


def validate_packet_rate(value):
    value = float(value)

    if not math.isfinite(value):
        raise ValueError("Packet rate must be finite")

    if value < 0.0:
        raise ValueError("Packet rate cannot be negative")

    return value


def decide_mitigation(row):
    prediction = row["prediction"]

    if prediction not in {"NORMAL", "DDOS_UDP"}:
        raise ValueError(
            f"Unsupported prediction: {prediction}"
        )

    ddos_probability = validate_probability(
        row["ddos_probability"]
    )

    packet_rate = validate_packet_rate(
        row["packets_per_second"]
    )

    if prediction == "NORMAL":
        action = "ALLOW"
        reason = "Normal traffic"

    elif (
        ddos_probability >= DDOS_PROBABILITY_THRESHOLD
        and packet_rate >= PACKET_RATE_THRESHOLD
    ):
        action = "RATE_LIMIT_AND_DROP"
        reason = "High-confidence DDoS with high packet rate"

    else:
        action = "RATE_LIMIT"
        reason = "DDoS detected but below mitigation threshold"

    return {
        "mitigation_action": action,
        "mitigation_reason": reason,
    }


def main():
    print("=" * 70)
    print("LIVE MITIGATION DECISION V1")
    print("=" * 70)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        newline="",
        encoding="utf-8",
    ) as f:
        rows = list(csv.DictReader(f))

    results = []

    for row in rows:
        decision = decide_mitigation(row)

        results.append({
            "window_start": row["window_start"],
            "packet_count": row["packet_count"],
            "packets_per_second": row["packets_per_second"],
            "prediction": row["prediction"],
            "ddos_probability": row["ddos_probability"],
            "normal_probability": row["normal_probability"],
            "security_action": row["action"],
            "severity": row["severity"],
            "mitigation_action": decision["mitigation_action"],
            "mitigation_reason": decision["mitigation_reason"],
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
        "security_action",
        "severity",
        "mitigation_action",
        "mitigation_reason",
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

    print()
    print("Input windows:", len(rows))
    print("Output:", OUTPUT_FILE)

    counts = {}

    for result in results:
        action = result["mitigation_action"]
        counts[action] = counts.get(action, 0) + 1

    print()
    print("Mitigation recommendations:")

    for action, count in sorted(counts.items()):
        print(f"{action}: {count}")

    print()
    print("DRY-RUN ONLY:")
    print("No traffic enforcement was performed.")

    print("=" * 70)
    print("TASK #178A COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
