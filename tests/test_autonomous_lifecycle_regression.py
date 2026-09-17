"""Regression tests for autonomous attack-response lifecycle and baseline recovery.

Verifies:
1. Autonomous state progression: ATTACK -> CONTAINED -> RECOVERING (streak 3) -> RESOLVED (streak 5).
2. SENSOR-01, SENSOR-02, SENSOR-03 seeded as authenticated sensors with 100.0 trust posture.
3. /api/status displays latest_mitigation_action="NONE" and latest_security_action="MONITOR" during baseline normal.
4. Incident closure atomically synchronizes linked admin_alerts to CLOSED in SQLite.
5. POST /api/simulations/reset enforces RBAC (401 unauth, 403 operator, 200 admin) and restores baseline identities.
"""

from pathlib import Path
import pytest

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.security import (
    DEFAULT_SIMULATED_MFA_TOKEN,
    ROLE_ADMIN,
    ROLE_OPERATOR,
)


@pytest.fixture
def gateway_fixture(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_regression.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


def test_autonomous_lifecycle_streak_progression(gateway_fixture):
    runtime, _ = gateway_fixture

    # 1. Ingest attack window -> incident created
    attack_win = generate_window("syn_flood")
    runtime.ingest(attack_win)

    incidents = runtime.store.incidents()
    assert len(incidents) >= 1
    active_inc = incidents[0]
    assert active_inc["lifecycle_state"] in ("RESPONDING", "CONTAINED")

    # If it is in RESPONDING, advance to CONTAINED
    if active_inc["lifecycle_state"] == "RESPONDING":
        runtime.store.transition_incident(active_inc["incident_id"], "CONTAINED", actor="system", note="Auto containment")

    # 2. Ingest 3 consecutive normal windows -> verify autonomous transition to RECOVERING
    for _ in range(3):
        norm_win = generate_window("normal")
        runtime.ingest(norm_win)

    inc = runtime.store.incident(active_inc["incident_id"])
    assert inc["lifecycle_state"] == "RECOVERING"

    # 3. Ingest 2 more consecutive normal windows (total streak 5) -> verify autonomous transition to RESOLVED
    for _ in range(2):
        norm_win = generate_window("normal")
        runtime.ingest(norm_win)

    inc = runtime.store.incident(active_inc["incident_id"])
    assert inc["lifecycle_state"] == "RESOLVED"

    # 4. Final operator sign-off -> transition to CLOSED
    closed_inc = runtime.store.transition_incident(active_inc["incident_id"], "CLOSED", actor="operator", note="Operator closed")
    assert closed_inc["lifecycle_state"] == "CLOSED"


def test_sensor_identities_and_baseline_trust_posture(gateway_fixture):
    runtime, app = gateway_fixture

    # Verify SENSOR-01, SENSOR-02, SENSOR-03 are seeded with 100.0 trust and authenticated
    for sensor_id in ["SENSOR-01", "SENSOR-02", "SENSOR-03"]:
        ident = runtime.iam.get(sensor_id)
        assert ident is not None
        assert ident.role == "sensor"
        assert ident.authenticated is True
        assert ident.trust_score == 100.0
        assert ident.mfa_status == "NOT_REQUIRED"

    # Ingest baseline normal windows cycling across all sensors
    for _ in range(12):
        norm_win = generate_window("normal")
        runtime.ingest(norm_win)

    # Check /api/status trust score
    with app.test_client() as client:
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.get_json()
        assert data["summary"]["trust_score"] == 100.0

    # Ensure all sensor identities maintain 100.0 trust
    for sensor_id in ["SENSOR-01", "SENSOR-02", "SENSOR-03"]:
        ident = runtime.iam.get(sensor_id)
        assert ident.trust_score == 100.0


def test_baseline_normal_status_mitigation_action_none(gateway_fixture):
    runtime, app = gateway_fixture

    # Ingest a baseline normal window
    runtime.ingest(generate_window("normal"))

    with app.test_client() as client:
        # Status endpoint is readable
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.get_json()

        assert data["summary"]["latest_prediction"] == "NORMAL"
        assert data["summary"]["latest_mitigation_action"] == "NONE"
        assert data["summary"]["latest_security_action"] == "MONITOR"


def test_incident_closure_atomically_syncs_admin_alerts(gateway_fixture):
    runtime, _ = gateway_fixture

    # Ingest attack window -> creates incident and linked alert
    runtime.ingest(generate_window("syn_flood"))
    incidents = runtime.store.incidents()
    assert len(incidents) >= 1
    inc_id = incidents[0]["incident_id"]

    alerts = runtime.store.list_alerts()
    linked_alerts = [a for a in alerts if a["incident_id"] == inc_id]
    assert len(linked_alerts) >= 1
    assert linked_alerts[0]["status"] == "ACTIVE"

    # Ingest 5 normal windows -> incident transitions to RESOLVED
    for _ in range(5):
        runtime.ingest(generate_window("normal"))

    inc = runtime.store.incident(inc_id)
    assert inc["lifecycle_state"] == "RESOLVED"

    # Verify alert status is automatically RESOLVED
    alerts_resolved = [a for a in runtime.store.list_alerts() if a["incident_id"] == inc_id]
    assert alerts_resolved[0]["status"] == "RESOLVED"
    assert alerts_resolved[0]["lifecycle_state"] == "RESOLVED"

    # Operator closes incident
    runtime.store.transition_incident(inc_id, "CLOSED", actor="operator", note="Operator closing incident")

    # Verify alert status is atomically CLOSED
    alerts_closed = [a for a in runtime.store.list_alerts() if a["incident_id"] == inc_id]
    assert alerts_closed[0]["status"] == "CLOSED"
    assert alerts_closed[0]["lifecycle_state"] == "CLOSED"


def test_simulation_reset_endpoint_rbac_and_behavior(gateway_fixture):
    runtime, app = gateway_fixture

    # Reduce attacker trust score to simulate an attack history
    atk = runtime.iam.get("ATK-01")
    atk.trust_score = 5.0
    runtime.iam.identities["ATK-01"] = atk

    with app.test_client() as client:
        # 1. Unauthenticated request -> 401
        res_unauth = client.post("/api/simulations/reset", json={})
        assert res_unauth.status_code == 401

        # 2. Operator login -> 403 Forbidden
        login_op = client.post("/api/auth/login", json={
            "username": "operator",
            "password": "Operator@AICG2026!",
            "mfa_code": DEFAULT_SIMULATED_MFA_TOKEN,
        })
        assert login_op.status_code == 200

        res_operator = client.post("/api/simulations/reset", json={})
        assert res_operator.status_code == 403
        assert res_operator.get_json()["code"] == "FORBIDDEN_PERMISSION"

        # Logout operator
        client.post("/api/auth/logout")

        # 3. Admin login -> 200 OK
        login_admin = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": DEFAULT_SIMULATED_MFA_TOKEN,
        })
        assert login_admin.status_code == 200

        res_admin = client.post("/api/simulations/reset", json={})
        assert res_admin.status_code == 200
        data = res_admin.get_json()
        assert data["status"] == "RESET"

        # Verify attacker trust reset to 35.0
        assert runtime.iam.get("ATK-01").trust_score == 35.0

        # Verify sensors are 100.0
        assert runtime.iam.get("SENSOR-01").trust_score == 100.0
        assert runtime.iam.get("SENSOR-02").trust_score == 100.0
        assert runtime.iam.get("SENSOR-03").trust_score == 100.0

        # Verify audit event was logged
        audit_events = runtime.store.list_audit_logs(action="SIMULATION_RESET")
        assert len(audit_events) >= 1
        assert audit_events[0]["username"] == "admin"
