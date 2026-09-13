"""Tests for policy planner, dry-run safety, incident correlation, and recovery lifecycle."""

from pathlib import Path
import pytest
from aegis_gateway.detection import Decision
from aegis_gateway.policy import ResponseEngine
from aegis_gateway.scenarios import generate_window
from aegis_gateway.storage import GatewayStore


def test_policy_planning_auto_mode():
    engine = ResponseEngine(mode="DRY_RUN", auto=True)

    normal_dec = Decision("NORMAL", 0.95, "INFO", ["baseline"], 0.05, None, None, "rules")
    plan = engine.plan(generate_window("normal"), normal_dec)
    assert plan.action == "ALERT"
    assert plan.requires_incident is False

    critical_dec = Decision("ATTACK", 0.95, "CRITICAL", ["flood"], 0.95, "ATTACK", 0.9, "model")
    plan = engine.plan(generate_window("mixed_vector"), critical_dec)
    assert plan.action == "ISOLATE"
    assert plan.requires_incident is True
    assert plan.result == "SIMULATED_NOT_ENFORCED"


def test_policy_planning_manual_mode():
    engine = ResponseEngine(mode="MANUAL", auto=False)
    attack_dec = Decision("ATTACK", 0.85, "HIGH", ["flood"], 0.85, "ATTACK", None, "model")
    plan = engine.plan(generate_window("udp_flood"), attack_dec)
    assert plan.mode == "MANUAL"
    assert plan.result == "PENDING_OPERATOR"
    assert plan.requires_incident is True


def test_incident_correlation_and_lifecycle(tmp_path: Path):
    store = GatewayStore(tmp_path / "test_store.sqlite3")

    ev1 = generate_window("udp_flood", intensity=3, sequence=0)
    ev1.severity = "HIGH"
    ev1.confidence = 0.88
    ev1.response_action = "BLOCK"

    # First attack window creates incident
    inc1 = store.create_incident(ev1, ["Rate spike", "UDP flood"], "CPU/RAM")
    inc_id = inc1["incident_id"]
    assert inc1["lifecycle_state"] == "DETECTED"

    # Find active incident
    active = store.find_active_incident(device_id=ev1.device_id, attack_type=ev1.attack_type)
    assert active is not None
    assert active["incident_id"] == inc_id

    # Second attack window correlates into existing incident instead of duplicating
    ev2 = generate_window("udp_flood", intensity=4, sequence=1)
    ev2.severity = "CRITICAL"
    ev2.confidence = 0.96
    ev2.response_action = "ISOLATE"

    correlated = store.correlate_incident(inc_id, ev2, ["Isolation Forest anomaly"], "Window 2 correlated")
    assert correlated["incident_id"] == inc_id
    assert correlated["severity"] == "CRITICAL"
    assert correlated["confidence"] == 0.96
    assert len(correlated["evidence"]) >= 3

    # Lifecycle state transitions
    t1 = store.transition_incident(inc_id, "RESPONDING", "operator", "Starting simulated response")
    assert t1["lifecycle_state"] == "RESPONDING"

    t2 = store.transition_incident(inc_id, "CONTAINED", "system", "Containment simulated")
    assert t2["lifecycle_state"] == "CONTAINED"

    t3 = store.transition_incident(inc_id, "RECOVERING", "system", "Traffic returning to normal")
    assert t3["lifecycle_state"] == "RECOVERING"

    t4 = store.transition_incident(inc_id, "RESOLVED", "system", "Recovery verified")
    assert t4["lifecycle_state"] == "RESOLVED"
    assert t4["recovery_state"] == "VERIFIED"
    assert t4["resolved_at"] is not None

    t5 = store.transition_incident(inc_id, "CLOSED", "operator", "Incident closed")
    assert t5["lifecycle_state"] == "CLOSED"


def test_invalid_lifecycle_transition_raises(tmp_path: Path):
    store = GatewayStore(tmp_path / "test_store.sqlite3")
    ev = generate_window("syn_flood", intensity=3, sequence=0)
    inc = store.create_incident(ev, ["SYN flood"], "CPU")

    # DETECTED cannot jump straight to RESOLVED without containment/recovery
    with pytest.raises(ValueError, match="Invalid transition"):
        store.transition_incident(inc["incident_id"], "RESOLVED", "operator", "Invalid shortcut")


def test_separate_campaigns_create_separate_incidents(tmp_path: Path):
    store = GatewayStore(tmp_path / "test_store_multi.sqlite3")

    # Campaign A: Node ATK-01 doing udp_flood
    ev_a1 = generate_window("udp_flood", intensity=3, sequence=0)
    inc_a = store.create_incident(ev_a1, ["UDP flood from ATK-01"], "CPU/Radio")

    # Campaign B: Node SENSOR-02 doing syn_flood
    ev_b1 = generate_window("syn_flood", intensity=3, sequence=0)
    ev_b1.device_id = "SENSOR-02"

    active_b = store.find_active_incident(device_id=ev_b1.device_id, attack_type=ev_b1.attack_type)
    assert active_b is None, "Campaign B from separate node must not match active Campaign A incident"

    inc_b = store.create_incident(ev_b1, ["SYN flood from SENSOR-02"], "Memory")
    assert inc_b["incident_id"] != inc_a["incident_id"]

    open_incidents = store.incidents()
    assert len(open_incidents) == 2
    ids = {i["incident_id"] for i in open_incidents}
    assert inc_a["incident_id"] in ids
    assert inc_b["incident_id"] in ids
