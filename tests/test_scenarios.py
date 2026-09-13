"""Tests for scenario catalogue, generation, and repeatability."""

import pytest
from aegis_gateway.scenarios import CATALOGUE, catalogue, generate_window


def test_catalogue_contents():
    cat = catalogue()
    assert len(cat) >= 11
    ids = {s["scenario_id"] for s in cat}
    assert "normal" in ids
    assert "udp_flood" in ids
    assert "syn_flood" in ids
    assert "icmp_flood" in ids
    assert "burst_exhaustion" in ids
    assert "slow_rate" in ids
    assert "coap_anomaly" in ids
    assert "mqtt_anomaly" in ids
    assert "rpl_anomaly" in ids
    assert "modbus_anomaly" in ids
    assert "mixed_vector" in ids


def test_generate_window_normal():
    event = generate_window("normal", intensity=1, sequence=0)
    assert event.label == "NORMAL"
    assert event.attack_type is None
    assert event.packet_rate is not None
    assert 5 <= event.packet_rate <= 30
    assert event.device_id.startswith("SENSOR-0")


def test_generate_window_attack_profiles():
    for sc_id in ["udp_flood", "syn_flood", "icmp_flood", "burst_exhaustion", "slow_rate", "mixed_vector"]:
        event = generate_window(sc_id, intensity=3, sequence=0)
        assert event.label == "ATTACK"
        assert event.attack_type == sc_id
        assert event.provenance == "SIMULATED"
        assert event.device_id == "ATK-01"


def test_generate_window_reproducibility():
    ev1 = generate_window("udp_flood", intensity=3, sequence=4, seed=42)
    ev2 = generate_window("udp_flood", intensity=3, sequence=4, seed=42)
    assert ev1.packet_rate == ev2.packet_rate
    assert ev1.byte_count == ev2.byte_count


def test_unknown_scenario_raises():
    with pytest.raises(KeyError, match="Unknown scenario"):
        generate_window("nonexistent_attack_scenario")
