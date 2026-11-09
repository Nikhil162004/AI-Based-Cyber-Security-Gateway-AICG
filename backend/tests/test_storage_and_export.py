"""Tests for SQLite historian, append operations, trust history, actions, and data export."""

import json
from pathlib import Path
import pytest
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


def test_storage_audit_and_alerts_export(tmp_path: Path):
    store = GatewayStore(tmp_path / "historian.sqlite3")

    # Record an audit log entry
    audit_entry = store.record_audit(
        username="admin",
        role="ADMIN",
        action="CONFIG_UPDATE",
        resource="/api/settings/mode",
        resource_id="ACTIVE",
        result="SUCCESS",
        details="Updated mitigation policy mode",
        source_ip="127.0.0.1",
    )

    # Create an alert entry
    ev = generate_window("syn_flood", intensity=3, sequence=0)
    store.append_telemetry(ev)
    inc = store.create_incident(ev, ["SYN flood detected"], "SENSOR-01")
    alert = store.create_or_update_alert(inc, ev)

    # 1. Audit CSV export
    csv_audit = store.export("audit", "csv")
    assert "event_id" in csv_audit
    assert "timestamp" in csv_audit
    assert "username" in csv_audit
    assert "role" in csv_audit
    assert "action" in csv_audit
    assert "resource" in csv_audit
    assert "resource_id" in csv_audit
    assert "result" in csv_audit
    assert "source_ip" in csv_audit
    assert "details" in csv_audit
    assert "prev_hash" in csv_audit
    assert "record_hash" in csv_audit
    assert audit_entry["event_id"] in csv_audit
    assert "CONFIG_UPDATE" in csv_audit

    # 2. Audit JSON export
    json_audit_str = store.export("audit", "json")
    parsed_audit = json.loads(json_audit_str)
    assert len(parsed_audit) >= 1
    found_audit = [a for a in parsed_audit if a["event_id"] == audit_entry["event_id"]]
    assert len(found_audit) == 1
    record = found_audit[0]
    for field in [
        "event_id", "timestamp", "username", "role", "action",
        "resource", "resource_id", "result", "source_ip",
        "details", "prev_hash", "record_hash"
    ]:
        assert field in record

    # 3. Alerts CSV export
    csv_alerts = store.export("alerts", "csv")
    assert alert["alert_id"] in csv_alerts
    assert "severity" in csv_alerts
    assert "evidence" in csv_alerts

    # 4. Alerts JSON export
    json_alerts_str = store.export("alerts", "json")
    parsed_alerts = json.loads(json_alerts_str)
    assert len(parsed_alerts) == 1
    assert parsed_alerts[0]["alert_id"] == alert["alert_id"]
    assert isinstance(parsed_alerts[0]["evidence"], list)

    # 5. Unsupported export kind -> ValueError
    with pytest.raises(ValueError, match="Export kind must be"):
        store.export("unsupported_kind", "json")

    # 6. Unsupported export format -> ValueError
    with pytest.raises(ValueError, match="Export format must be csv or json"):
        store.export("audit", "xml")


def test_cli_export_audit_and_alerts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_gateway.cli import main as cli_main

    db_file = tmp_path / "cli_historian.sqlite3"
    monkeypatch.setenv("AEGIS_DATABASE_PATH", str(db_file))

    store = GatewayStore(db_file)
    store.record_audit(
        username="admin",
        role="ADMIN",
        action="CLI_TEST",
        resource="system",
        resource_id="1",
        result="SUCCESS",
        details="CLI test audit log",
    )
    ev = generate_window("syn_flood", intensity=1, sequence=0)
    store.append_telemetry(ev)
    inc = store.create_incident(ev, ["CLI alert test"], "TEST-DEV")
    store.create_or_update_alert(inc, ev)

    audit_out_json = tmp_path / "cli_audit.json"
    audit_out_csv = tmp_path / "cli_audit.csv"
    alerts_out_json = tmp_path / "cli_alerts.json"
    alerts_out_csv = tmp_path / "cli_alerts.csv"

    # Test CLI export audit json
    ret1 = cli_main(["export", "audit", "--format", "json", "--output", str(audit_out_json)])
    assert ret1 == 0
    assert audit_out_json.exists()
    assert "CLI_TEST" in audit_out_json.read_text(encoding="utf-8")

    # Test CLI export audit csv
    ret2 = cli_main(["export", "audit", "--format", "csv", "--output", str(audit_out_csv)])
    assert ret2 == 0
    assert audit_out_csv.exists()
    assert "CLI_TEST" in audit_out_csv.read_text(encoding="utf-8")

    # Test CLI export alerts json
    ret3 = cli_main(["export", "alerts", "--format", "json", "--output", str(alerts_out_json)])
    assert ret3 == 0
    assert alerts_out_json.exists()
    assert "CLI alert test" in alerts_out_json.read_text(encoding="utf-8")

    # Test CLI export alerts csv
    ret4 = cli_main(["export", "alerts", "--format", "csv", "--output", str(alerts_out_csv)])
    assert ret4 == 0
    assert alerts_out_csv.exists()
    assert "CLI alert test" in alerts_out_csv.read_text(encoding="utf-8")
