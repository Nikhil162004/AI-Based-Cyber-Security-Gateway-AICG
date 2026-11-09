"""Canonical telemetry/event schema shared by every gateway source."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class Provenance(str, Enum):
    MEASURED = "MEASURED"
    SIMULATED = "SIMULATED"
    MODELLED = "MODELLED"
    SYNTHETIC = "SYNTHETIC"
    DERIVED = "DERIVED"
    REPLAYED = "REPLAYED"
    UNKNOWN = "UNKNOWN"


CANONICAL_FIELDS = [
    "event_id", "timestamp", "source_type", "source_id", "device_id", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "protocol_layer", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "packet_size", "flow_id", "unique_sources", "unique_destinations",
    "tcp_flags", "icmp_type", "attack_type", "traffic_type", "label", "confidence", "model_version",
    "feature_version", "scenario_id", "dataset_id", "provenance", "energy_consumed", "energy_rate",
    "energy_baseline", "energy_deviation", "energy_cause", "cpu_activity", "memory_activity", "radio_tx",
    "radio_rx", "radio_idle", "resource_state", "iam_identity", "authentication_status",
    "authorization_status", "role", "access_request", "access_decision", "trust_score", "severity",
    "response_action", "response_mode", "lifecycle_state",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class TelemetryEvent:
    """A normalized traffic window; unavailable values remain ``None``.

    Values must only describe the source named by ``provenance``.  In
    particular energy fields calculated by this package have ``MODELLED``
    provenance recorded in their explanation and must not be read as a meter.
    """

    event_id: str | None = None
    timestamp: str | None = None
    source_type: str = "UNKNOWN"
    source_id: str | None = None
    device_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    protocol_layer: str | None = None
    packet_count: int | None = None
    byte_count: int | None = None
    packet_rate: float | None = None
    byte_rate: float | None = None
    packet_size: float | None = None
    flow_id: str | None = None
    unique_sources: int | None = None
    unique_destinations: int | None = None
    tcp_flags: str | None = None
    icmp_type: str | None = None
    attack_type: str | None = None
    traffic_type: str | None = None
    label: str | None = None
    confidence: float | None = None
    model_version: str | None = None
    feature_version: str = "telemetry-v1"
    scenario_id: str | None = None
    dataset_id: str | None = None
    provenance: str = Provenance.UNKNOWN.value
    energy_consumed: float | None = None
    energy_rate: float | None = None
    energy_baseline: float | None = None
    energy_deviation: float | None = None
    energy_cause: str | None = None
    cpu_activity: float | None = None
    memory_activity: float | None = None
    radio_tx: float | None = None
    radio_rx: float | None = None
    radio_idle: float | None = None
    resource_state: str | None = None
    iam_identity: str | None = None
    authentication_status: str | None = None
    authorization_status: str | None = None
    role: str | None = None
    access_request: str | None = None
    access_decision: str | None = None
    trust_score: float | None = None
    severity: str | None = None
    response_action: str | None = None
    response_mode: str | None = None
    lifecycle_state: str | None = None
    auth_token: str | None = field(default=None, repr=False)

    def normalize(self) -> "TelemetryEvent":
        self.event_id = self.event_id or str(uuid4())
        self.timestamp = self.timestamp or utc_now()
        self.source_type = str(self.source_type or "UNKNOWN").upper()
        self.provenance = str(self.provenance or Provenance.UNKNOWN.value).upper()
        if self.provenance not in {item.value for item in Provenance}:
            raise ValueError(f"Unsupported provenance: {self.provenance}")
        for name in ("packet_count", "byte_count", "unique_sources", "unique_destinations"):
            value = getattr(self, name)
            if value is not None and int(value) < 0:
                raise ValueError(f"{name} cannot be negative")
        for name in ("packet_rate", "byte_rate", "packet_size", "confidence", "trust_score"):
            value = getattr(self, name)
            if value is not None and float(value) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.confidence is not None and self.confidence > 1:
            raise ValueError("confidence must be in [0, 1]")
        if self.trust_score is not None and self.trust_score > 100:
            raise ValueError("trust_score must be in [0, 100]")
        return self

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("auth_token", None)
        return d

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "TelemetryEvent":
        known = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known}).normalize()


def public_event(event: TelemetryEvent | dict[str, Any]) -> dict[str, Any]:
    """Return JSON-safe canonical data without adding invented source values."""
    d = event.to_dict() if isinstance(event, TelemetryEvent) else dict(event)
    d.pop("auth_token", None)
    return d
