"""Tests for SQLite historian, append operations, trust history, actions, and data export."""

import json
from pathlib import Path
from aegis_gateway.scenarios import generate_window
from aegis_gateway.storage import GatewayStore


def test_storage_telemetry_append_and_query(tmp_path: Path):
    store = GatewayStore(tmp_path / "historian.sqlite3")

    ev1 = generate_window("normal", intensity=1, sequence=0)
    ev2 = generate_window("udp_flood", intensity=3, sequence=0)
    store.append_telemetry(ev1)
    store.append_telemetry(ev2)

    rows = store.telemetry(limit=10)
    assert len(rows) == 2
    assert rows[0]["device_id"] == ev1.device_id
    assert rows[1]["device_id"] == ev2.device_id


def test_storage_iam_and_trust_history(tmp_path: Path):
    store = GatewayStore(tmp_path / "historian.sqlite3")

    store.record_iam({
        "identity": "SENSOR-01",
        "role": "sensor",
        "decision": "ALLOW",
        "reason": "authenticated role"
    })

    store.record_trust("ATK-01", score=35.0, delta=-20.0, reason="Attack flood detection")
    store.record_trust("ATK-01", score=15.0, delta=-20.0, reason="Repeated flood detection")

    history = store.trust("ATK-01")
    assert len(history) == 2
    assert history[0]["score"] == 35.0
    assert history[1]["score"] == 15.0


def test_storage_actions_and_export(tmp_path: Path):
    store = GatewayStore(tmp_path / "historian.sqlite3")

    ev = generate_window("syn_flood", intensity=3, sequence=0)
    store.append_telemetry(ev)
    inc = store.create_incident(ev, ["SYN anomaly"], "CPU/RAM")

    store.record_action(
        event_id=ev.event_id,
        incident_id=inc["incident_id"],
        action="RATE_LIMIT",
        reason="SYN flood mitigation",
        policy="hybrid-v1",
        mode="DRY_RUN",
        result="SIMULATED_NOT_ENFORCED"
    )

    # Export Telemetry CSV
    csv_telemetry = store.export("telemetry", "csv")
    assert "packet_rate" in csv_telemetry

    # Export Telemetry JSON
    json_telemetry = store.export("telemetry", "json")
    parsed_tel = json.loads(json_telemetry)
    assert len(parsed_tel) == 1

    # Export Incidents CSV & JSON
    csv_incidents = store.export("incidents", "csv")
    assert inc["incident_id"] in csv_incidents
    json_incidents = json.loads(store.export("incidents", "json"))
    assert len(json_incidents) == 1

    # Export Actions CSV & JSON
    csv_actions = store.export("actions", "csv")
    assert "RATE_LIMIT" in csv_actions
    json_actions = json.loads(store.export("actions", "json"))
    assert len(json_actions) == 1
