"""
Security Lifecycle Adapter V1

Additive lifecycle interpretation of the existing validated
security decision and mitigation recommendation outputs.

IMPORTANT:
- This module does NOT enforce network mitigation.
- It does NOT modify firewall rules.
- It does NOT block or drop packets.
- It does NOT modify frozen V1 CSV schemas.
- Lifecycle states describe observed/recommended system state.
"""

from __future__ import annotations

import csv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SECURITY_FILE = (
    PROJECT_ROOT
    / "results"
    / "live_security_decisions_v1.csv"
)

MITIGATION_FILE = (
    PROJECT_ROOT
    / "results"
    / "live_mitigation_decisions_v1.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "results"
    / "security_lifecycle_v1.csv"
)


ALLOWED_STATES = {
    "NORMAL",
    "DETECTED",
    "ALERTED",
    "MITIGATION_RECOMMENDED",
    "MONITORING",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV file safely."""
    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        return list(csv.DictReader(handle))


def derive_lifecycle_state(
    security_row: dict[str, str],
    mitigation_row: dict[str, str],
) -> tuple[str, str, str]:
    """
    Derive a lifecycle state from existing V1 outputs.

    Returns:
        state,
        lifecycle_stage,
        implementation_status
    """

    prediction = security_row.get(
        "prediction",
        "UNKNOWN",
    )

    security_action = security_row.get(
        "action",
        "UNKNOWN",
    )

    severity = security_row.get(
        "severity",
        "UNKNOWN",
    )

    mitigation_action = mitigation_row.get(
        "mitigation_action",
        "UNKNOWN",
    )

    if prediction == "NORMAL":
        return (
            "NORMAL",
            "DETECTION",
            "OBSERVED",
        )

    if prediction == "DDOS_UDP":
        if security_action == "ALERT":
            if mitigation_action in {
                "RATE_LIMIT",
                "RATE_LIMIT_AND_DROP",
            }:
                return (
                    "MITIGATION_RECOMMENDED",
                    "RESPONSE",
                    "RECOMMENDED",
                )

            return (
                "ALERTED",
                "ALERT",
                "OBSERVED",
            )

        return (
            "DETECTED",
            "DETECTION",
            "OBSERVED",
        )

    return (
        "MONITORING",
        "MONITORING",
        "OBSERVED",
    )


def build_lifecycle_rows() -> list[dict[str, str]]:
    """Join existing V1 security and mitigation outputs."""

    security_rows = read_csv(SECURITY_FILE)
    mitigation_rows = read_csv(MITIGATION_FILE)

    mitigation_map = {
        row.get("window_start", ""): row
        for row in mitigation_rows
        if row.get("window_start")
    }

    lifecycle_rows = []

    for security_row in security_rows:

        window = security_row.get(
            "window_start",
            "",
        )

        mitigation_row = mitigation_map.get(
            window,
            {},
        )

        state, stage, implementation_status = (
            derive_lifecycle_state(
                security_row,
                mitigation_row,
            )
        )

        lifecycle_rows.append(
            {
                "window_start": window,
                "prediction": security_row.get(
                    "prediction",
                    "UNKNOWN",
                ),
                "security_action": security_row.get(
                    "action",
                    "UNKNOWN",
                ),
                "severity": security_row.get(
                    "severity",
                    "UNKNOWN",
                ),
                "mitigation_action": mitigation_row.get(
                    "mitigation_action",
                    "UNKNOWN",
                ),
                "mitigation_reason": mitigation_row.get(
                    "mitigation_reason",
                    "",
                ),
                "lifecycle_state": state,
                "lifecycle_stage": stage,
                "implementation_status": implementation_status,
                "enforcement_status": (
                    "NOT_IMPLEMENTED"
                ),
                "recovery_status": (
                    "NOT_IMPLEMENTED"
                ),
            }
        )

    return lifecycle_rows


def write_lifecycle_csv(
    rows: list[dict[str, str]],
) -> None:
    """Write the additive lifecycle output."""

    fieldnames = [
        "window_start",
        "prediction",
        "security_action",
        "severity",
        "mitigation_action",
        "mitigation_reason",
        "lifecycle_state",
        "lifecycle_stage",
        "implementation_status",
        "enforcement_status",
        "recovery_status",
    ]

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def main() -> None:

    rows = build_lifecycle_rows()

    write_lifecycle_csv(rows)

    print(
        "SECURITY LIFECYCLE ADAPTER V1"
    )
    print(
        "Security rows:",
        len(read_csv(SECURITY_FILE)),
    )
    print(
        "Lifecycle rows:",
        len(rows),
    )
    print(
        "Output:",
        OUTPUT_FILE,
    )

    states = {}

    for row in rows:
        state = row["lifecycle_state"]
        states[state] = states.get(state, 0) + 1

    print()
    print("Lifecycle states:")

    for state, count in sorted(states.items()):
        print(
            f"  {state}: {count}"
        )

    print()
    print(
        "Enforcement:",
        "NOT_IMPLEMENTED",
    )
    print(
        "Recovery:",
        "NOT_IMPLEMENTED",
    )


if __name__ == "__main__":
    main()
