"""
Energy Context Adapter V1

Purpose:
    Expose existing controlled/modelled NS-3 energy analysis as
    dashboard context without modifying the existing live ML pipeline.

Important:
    The energy values exposed here are modelled/simulation-derived
    estimates. They are NOT physical hardware measurements.
"""

import csv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

ENERGY_ANALYSIS_FILE = (
    PROJECT_ROOT
    / "dataset"
    / "ns3_current_energy_analysis.csv"
)


ENERGY_FIELDS = (
    "window_start",
    "energy_estimate",
    "energy_rate",
    "energy_per_packet",
    "baseline_energy",
    "energy_deviation",
    "energy_increase_percent",
    "tx_activity",
    "rx_activity",
    "cpu_activity",
    "energy_cause",
)


def _empty_energy_context(window_start=""):
    """Return a safe unavailable energy context."""

    return {
        "available": False,
        "window_start": window_start,
        "energy_estimate": None,
        "energy_rate": None,
        "energy_per_packet": None,
        "baseline_energy": None,
        "energy_deviation": None,
        "energy_increase_percent": None,
        "tx_activity": None,
        "rx_activity": None,
        "cpu_activity": None,
        "energy_cause": "UNAVAILABLE",
        "source": "NS3_CURRENT_ENERGY_ANALYSIS",
        "environment": "CONTROLLED_SIMULATION",
        "measurement_status": "MODELLED",
        "hardware_measured": False,
    }


def _load_energy_rows():
    """Load existing energy analysis rows without modifying the file."""

    if not ENERGY_ANALYSIS_FILE.exists():
        return []

    with ENERGY_ANALYSIS_FILE.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as handle:
        return list(csv.DictReader(handle))


def _to_float(value):
    """Convert a CSV value to float, preserving missing values."""

    if value in (None, ""):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _build_context(row):
    """Convert one energy-analysis row into dashboard-safe context."""

    context = {
        "available": True,
        "window_start": row.get("window_start", ""),
        "energy_estimate": _to_float(
            row.get("energy_estimate")
        ),
        "energy_rate": _to_float(
            row.get("energy_rate")
        ),
        "energy_per_packet": _to_float(
            row.get("energy_per_packet")
        ),
        "baseline_energy": _to_float(
            row.get("baseline_energy")
        ),
        "energy_deviation": _to_float(
            row.get("energy_deviation")
        ),
        "energy_increase_percent": _to_float(
            row.get("energy_increase_percent")
        ),
        "tx_activity": _to_float(
            row.get("tx_activity")
        ),
        "rx_activity": _to_float(
            row.get("rx_activity")
        ),
        "cpu_activity": _to_float(
            row.get("cpu_activity")
        ),
        "energy_cause": (
            row.get("energy_cause")
            or "UNSPECIFIED"
        ),
        "source": "NS3_CURRENT_ENERGY_ANALYSIS",
        "environment": "CONTROLLED_SIMULATION",
        "measurement_status": "MODELLED",
        "hardware_measured": False,
    }

    return context


def get_energy_context(window_start):
    """
    Resolve energy context for an exact dashboard window.

    Exact matching is intentional. We do not fabricate temporal
    correlations when a dashboard window has no matching energy row.
    """

    requested_window = str(window_start or "")

    if not requested_window:
        return _empty_energy_context()

    for row in _load_energy_rows():
        if row.get("window_start") == requested_window:
            return _build_context(row)

    return _empty_energy_context(requested_window)


def get_all_energy_context():
    """
    Return all existing controlled/modelled NS-3 energy contexts.

    This exposes the complete controlled energy dataset without
    modifying the source CSV or changing the live security pipeline.
    """
    return [
        _build_context(row)
        for row in _load_energy_rows()
    ]


def get_energy_context_for_row(row):
    """Convenience helper for a dashboard row."""

    if not isinstance(row, dict):
        return _empty_energy_context()

    return get_energy_context(
        row.get("window_start", "")
    )


if __name__ == "__main__":
    print("============================================================")
    print("ENERGY CONTEXT ADAPTER V1")
    print("============================================================")
    print("Source:", ENERGY_ANALYSIS_FILE)
    print("Exists:", ENERGY_ANALYSIS_FILE.exists())

    rows = _load_energy_rows()

    print("Energy rows:", len(rows))

    if rows:
        first = get_energy_context(
            rows[0].get("window_start", "")
        )

        print()
        print("FIRST WINDOW:")
        print(first)

    print()
    print("Adapter status: READY")
