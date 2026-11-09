"""
Observed Identity Context Adapter V1

Purpose:
    Connect observed source IP addresses from the live traffic capture
    CSV to the local IAM/device identity registry.

This module is dashboard/context enrichment only.

It does NOT:
    - modify ML features
    - modify frozen ML models
    - authenticate network devices
    - perform cryptographic identity verification
    - enforce authorization
    - block packets
    - modify firewall rules
    - isolate devices
    - change security decisions
    - change mitigation decisions
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

try:
    from .device_identity_context_v1 import resolve_device_context
except ImportError:
    from device_identity_context_v1 import resolve_device_context


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRAFFIC_FILE = PROJECT_ROOT / "dataset" / "traffic_data.csv"


DEFAULT_OBSERVED_CONTEXT: dict[str, Any] = {
    "observed_source_count": 0,
    "observed_sources": [],
    "known_device_count": 0,
    "unknown_device_count": 0,
    "device_contexts": [],
}


def _empty_context() -> dict[str, Any]:
    """Return a fresh empty observed-context structure."""
    return {
        "observed_source_count": 0,
        "observed_sources": [],
        "known_device_count": 0,
        "unknown_device_count": 0,
        "device_contexts": [],
    }


def _normalize_timestamp(value: str) -> str:
    """Normalize a CSV timestamp for exact dashboard-window comparison."""
    return str(value or "").strip()


def get_observed_identity_context(
    window_start: str,
    traffic_path: Path = TRAFFIC_FILE,
) -> dict[str, Any]:
    """
    Resolve IAM context for source IPs observed in the specified window.

    The function uses exact timestamp-prefix matching so it does not invent
    a time relationship when the live feature pipeline uses a window_start
    value.

    Unknown source IPs remain UNKNOWN and are not classified as malicious.
    """
    context = _empty_context()
    target_window = _normalize_timestamp(window_start)

    if not target_window:
        return context

    source_ips: set[str] = set()

    try:
        with traffic_path.open(newline="") as handle:
            reader = csv.DictReader(handle)

            for row in reader:
                timestamp = _normalize_timestamp(row.get("timestamp", ""))

                if not timestamp:
                    continue

                # Match the complete dashboard window prefix.
                if not timestamp.startswith(target_window):
                    continue

                source_ip = str(row.get("source_ip", "")).strip()

                if source_ip:
                    source_ips.add(source_ip)

    except (FileNotFoundError, OSError, csv.Error):
        return context

    sorted_sources = sorted(source_ips)

    device_contexts = []

    for source_ip in sorted_sources:
        device = resolve_device_context(source_ip)

        device_contexts.append(device)

    known_count = sum(
        1
        for device in device_contexts
        if device.get("identity_status") == "KNOWN"
    )

    unknown_count = sum(
        1
        for device in device_contexts
        if device.get("identity_status") == "UNKNOWN"
    )

    context["observed_source_count"] = len(sorted_sources)
    context["observed_sources"] = sorted_sources
    context["known_device_count"] = known_count
    context["unknown_device_count"] = unknown_count
    context["device_contexts"] = device_contexts

    return context


def get_observed_identity_context_for_sources(
    source_ips: list[str],
) -> dict[str, Any]:
    """
    Resolve IAM context directly for an explicit list of observed sources.

    This helper is useful for deterministic testing and future integrations.
    """
    context = _empty_context()

    normalized_sources = sorted(
        {
            str(source_ip).strip()
            for source_ip in source_ips
            if str(source_ip).strip()
        }
    )

    device_contexts = [
        resolve_device_context(source_ip)
        for source_ip in normalized_sources
    ]

    context["observed_source_count"] = len(normalized_sources)
    context["observed_sources"] = normalized_sources
    context["known_device_count"] = sum(
        1
        for device in device_contexts
        if device.get("identity_status") == "KNOWN"
    )
    context["unknown_device_count"] = sum(
        1
        for device in device_contexts
        if device.get("identity_status") == "UNKNOWN"
    )
    context["device_contexts"] = device_contexts

    return context


def main() -> None:
    """Run a deterministic standalone adapter test."""
    print("=" * 70)
    print("OBSERVED IDENTITY CONTEXT ADAPTER V1")
    print("=" * 70)

    result = get_observed_identity_context_for_sources(
        [
            "127.0.0.1",
            "192.0.2.10",
        ]
    )

    print("Observed source count:", result["observed_source_count"])
    print("Known device count:", result["known_device_count"])
    print("Unknown device count:", result["unknown_device_count"])

    for device in result["device_contexts"]:
        print()
        print(
            device["ip_address"],
            "->",
            device["device_id"],
            "|",
            device["identity_status"],
        )

    print()
    print("Adapter test complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
