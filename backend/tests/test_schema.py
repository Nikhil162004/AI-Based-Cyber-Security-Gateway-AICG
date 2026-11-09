"""Tests for canonical telemetry schema, normalization, and provenance."""

import pytest
from aegis_gateway.schema import CANONICAL_FIELDS, Provenance, TelemetryEvent, public_event


def test_canonical_fields_present():
    assert "event_id" in CANONICAL_FIELDS
    assert "provenance" in CANONICAL_FIELDS
    assert "energy_deviation" in CANONICAL_FIELDS
    assert "trust_score" in CANONICAL_FIELDS
    assert "lifecycle_state" in CANONICAL_FIELDS


def test_telemetry_normalization():
    event = TelemetryEvent(
        packet_count=10,
        packet_rate=10.5,
        byte_count=1000,
        byte_rate=1050.0,
        provenance=Provenance.SIMULATED.value,
    ).normalize()

    assert event.event_id is not None
    assert event.timestamp is not None
    assert event.provenance == "SIMULATED"
    assert event.source_type == "UNKNOWN"
    assert event.packet_count == 10
    assert event.confidence is None


def test_invalid_provenance_raises():
    with pytest.raises(ValueError, match="Unsupported provenance"):
        TelemetryEvent(provenance="INVALID_SOURCE").normalize()


def test_negative_values_raise():
    with pytest.raises(ValueError, match="packet_count cannot be negative"):
        TelemetryEvent(packet_count=-1, provenance=Provenance.SIMULATED.value).normalize()

    with pytest.raises(ValueError, match="packet_rate cannot be negative"):
        TelemetryEvent(packet_rate=-5.0, provenance=Provenance.SIMULATED.value).normalize()


def test_confidence_and_trust_bounds():
    with pytest.raises(ValueError, match="confidence must be in"):
        TelemetryEvent(confidence=1.5, provenance=Provenance.SIMULATED.value).normalize()

    with pytest.raises(ValueError, match="trust_score must be in"):
        TelemetryEvent(trust_score=105.0, provenance=Provenance.SIMULATED.value).normalize()


def test_dict_serialization_and_roundtrip():
    event = TelemetryEvent(
        device_id="SENSOR-01",
        packet_count=20,
        packet_rate=20.0,
        label="NORMAL",
        provenance=Provenance.SYNTHETIC.value,
    ).normalize()

    d = event.to_dict()
    assert d["device_id"] == "SENSOR-01"
    assert d["label"] == "NORMAL"

    roundtrip = TelemetryEvent.from_mapping(d)
    assert roundtrip.event_id == event.event_id
    assert roundtrip.device_id == event.device_id
    assert roundtrip.provenance == "SYNTHETIC"


def test_public_event_helper():
    event = TelemetryEvent(device_id="ATK-01", provenance=Provenance.SIMULATED.value).normalize()
    pub = public_event(event)
    assert isinstance(pub, dict)
    assert pub["device_id"] == "ATK-01"
