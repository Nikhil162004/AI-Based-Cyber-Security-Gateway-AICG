"""Comprehensive tests for the AICG Administrative Security Layer.

Verifies:
- Authentication & Session Management (Admin/Operator login, logout, enumeration protection)
- Simulated MFA Verification Flow
- Server-Side Role-Based Access Control (RBAC) Enforcement
- Automatic Security Alert Generation, Deduplication, & Incident Lifecycle Synchronization
- Administrative Audit Logging (Append-Only, Redacted Credentials)
- Zero-Trust Posture & Safety Guarantees (DRY_RUN, Non-Enforcing, Zero External Packets)
"""

from pathlib import Path
import pytest
from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.security import (
    DEFAULT_SIMULATED_MFA_TOKEN,
    PERM_ACK_ALERT,
    PERM_ADMIN_CONTROLS,
    PERM_CLOSE_INCIDENT,
    PERM_MANAGE_INCIDENT,
    PERM_MANAGE_USERS,
    PERM_VIEW_AUDIT,
    PERM_VIEW_DASHBOARD,
    PERM_VIEW_INCIDENTS,
    PERM_VIEW_SECURITY_POSTURE,
    PERM_VIEW_SYSTEM_STATUS,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    has_permission,
    hash_password,
    verify_password,
    verify_simulated_mfa,
)


@pytest.fixture
def admin_app(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_admin_sec.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


# =============================================================================
# 1. AUTHENTICATION & SESSION TESTS
# =============================================================================

def test_password_hashing_and_verification():
    h1 = hash_password("Admin@AICG2026!")
    assert verify_password("Admin@AICG2026!", h1) is True
    assert verify_password("WrongPassword!", h1) is False
    assert verify_password("", h1) is False


def test_simulated_mfa_token_validation():
    assert verify_simulated_mfa("123456") is True
    assert verify_simulated_mfa(" 123456 ") is True
    assert verify_simulated_mfa("000000") is False
    assert verify_simulated_mfa("invalid") is False
    assert verify_simulated_mfa("") is False


def test_admin_login_success(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        # Step 1: Initial auth request
        res = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": DEFAULT_SIMULATED_MFA_TOKEN
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["authenticated"] is True
        assert data["user"]["username"] == "admin"
        assert data["user"]["role"] == ROLE_ADMIN
        assert data["user"]["mfa_status"] == "SIMULATED_VERIFIED"
        assert PERM_ADMIN_CONTROLS in data["permissions"]

        # Step 2: Verify auth status endpoint
        st_res = client.get("/api/auth/status")
        assert st_res.status_code == 200
        st_data = st_res.get_json()
        assert st_data["authenticated"] is True
        assert st_data["user"]["username"] == "admin"


def test_operator_login_success(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        res = client.post("/api/auth/login", json={
            "username": "operator",
            "password": "Operator@AICG2026!",
            "mfa_code": "123456"
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["user"]["role"] == ROLE_OPERATOR
        assert PERM_ACK_ALERT in data["permissions"]
        assert PERM_MANAGE_USERS not in data["permissions"]


def test_login_invalid_credentials_and_enumeration_resistance(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        # Wrong password
        res_bad_pass = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "BadPassword123!"
        })
        assert res_bad_pass.status_code == 401
        assert res_bad_pass.get_json()["error"] == "Invalid administrative credentials"

        # Non-existent user
        res_non_exist = client.post("/api/auth/login", json={
            "username": "non_existent_hacker",
            "password": "BadPassword123!"
        })
        assert res_non_exist.status_code == 401
        assert res_non_exist.get_json()["error"] == "Invalid administrative credentials"


def test_simulated_mfa_step_and_invalid_mfa(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        # Request without MFA code prompts for simulated MFA
        res_prompt = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!"
        })
        assert res_prompt.status_code == 200
        assert res_prompt.get_json()["mfa_required"] is True

        # Provide invalid MFA code
        res_bad_mfa = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "999999"
        })
        assert res_bad_mfa.status_code == 401
        assert "Invalid simulated MFA" in res_bad_mfa.get_json()["error"]


def test_logout_clears_session(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456"
        })
        assert client.get("/api/auth/status").get_json()["authenticated"] is True

        # Logout
        res_logout = client.post("/api/auth/logout")
        assert res_logout.status_code == 200
        assert client.get("/api/auth/status").get_json()["authenticated"] is False


def test_unauthenticated_protected_route_rejection(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        # Overview endpoint
        r1 = client.get("/api/admin/overview")
        assert r1.status_code == 401
        assert r1.get_json()["code"] == "AUTH_REQUIRED"

        # Alerts endpoint
        r2 = client.get("/api/admin/alerts")
        assert r2.status_code == 401

        # Users endpoint
        r3 = client.get("/api/admin/users")
        assert r3.status_code == 401

        # Audit endpoint
        r4 = client.get("/api/admin/audit")
        assert r4.status_code == 401


# =============================================================================
# 2. RBAC AUTHORIZATION TESTS
# =============================================================================

def test_rbac_permission_matrix():
    assert has_permission(ROLE_ADMIN, PERM_VIEW_DASHBOARD) is True
    assert has_permission(ROLE_ADMIN, PERM_VIEW_INCIDENTS) is True
    assert has_permission(ROLE_ADMIN, PERM_ACK_ALERT) is True
    assert has_permission(ROLE_ADMIN, PERM_MANAGE_INCIDENT) is True
    assert has_permission(ROLE_ADMIN, PERM_CLOSE_INCIDENT) is True
    assert has_permission(ROLE_ADMIN, PERM_VIEW_AUDIT) is True
    assert has_permission(ROLE_ADMIN, PERM_MANAGE_USERS) is True
    assert has_permission(ROLE_ADMIN, PERM_VIEW_SECURITY_POSTURE) is True
    assert has_permission(ROLE_ADMIN, PERM_VIEW_SYSTEM_STATUS) is True
    assert has_permission(ROLE_ADMIN, PERM_ADMIN_CONTROLS) is True

    assert has_permission(ROLE_OPERATOR, PERM_VIEW_DASHBOARD) is True
    assert has_permission(ROLE_OPERATOR, PERM_VIEW_INCIDENTS) is True
    assert has_permission(ROLE_OPERATOR, PERM_ACK_ALERT) is True
    assert has_permission(ROLE_OPERATOR, PERM_MANAGE_INCIDENT) is True
    assert has_permission(ROLE_OPERATOR, PERM_VIEW_SECURITY_POSTURE) is True
    assert has_permission(ROLE_OPERATOR, PERM_VIEW_SYSTEM_STATUS) is True

    # Denied for operator
    assert has_permission(ROLE_OPERATOR, PERM_CLOSE_INCIDENT) is False
    assert has_permission(ROLE_OPERATOR, PERM_MANAGE_USERS) is False
    assert has_permission(ROLE_OPERATOR, PERM_ADMIN_CONTROLS) is False
    assert has_permission(ROLE_OPERATOR, PERM_VIEW_AUDIT) is False


def test_operator_denied_admin_only_endpoints(admin_app):
    runtime, app = admin_app
    with app.test_client() as client:
        client.post("/api/auth/login", json={
            "username": "operator",
            "password": "Operator@AICG2026!",
            "mfa_code": "123456"
        })

        # Operator trying to access users management -> 403
        r_users = client.get("/api/admin/users")
        assert r_users.status_code == 403
        assert r_users.get_json()["code"] == "FORBIDDEN_ROLE"

        # Operator trying to create user -> 403
        r_create = client.post("/api/admin/users", json={
            "username": "newuser",
            "password": "password123",
            "role": "OPERATOR"
        })
        assert r_create.status_code == 403

        # Operator trying to view audit logs -> 403
        r_audit = client.get("/api/admin/audit")
        assert r_audit.status_code == 403

        # Operator trying to modify operating mode -> 403
        r_mode = client.post("/api/settings/mode", json={"mode": "MANUAL"})
        assert r_mode.status_code == 403
        assert r_mode.get_json()["code"] == "FORBIDDEN_ROLE"


def test_admin_allowed_privileged_endpoints(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456"
        })

        # List users
        r_users = client.get("/api/admin/users")
        assert r_users.status_code == 200
        assert r_users.get_json()["count"] >= 2

        # Create new lab user
        r_create = client.post("/api/admin/users", json={
            "username": "auditor_lab",
            "password": "Auditor@Lab2026!",
            "role": "OPERATOR"
        })
        assert r_create.status_code == 201
        created = r_create.get_json()
        assert created["username"] == "auditor_lab"

        # View audit logs
        r_audit = client.get("/api/admin/audit")
        assert r_audit.status_code == 200
        assert r_audit.get_json()["count"] >= 1

        # Modify operating mode
        r_mode = client.post("/api/settings/mode", json={"mode": "DRY_RUN", "auto": True})
        assert r_mode.status_code == 200


# =============================================================================
# 3. ALERT PIPELINE & DEDUPLICATION TESTS
# =============================================================================

def test_attack_creates_single_alert_and_deduplicates(admin_app):
    runtime, app = admin_app
    with app.test_client() as client:
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456"
        })

        # Ingest first attack observation
        res1 = runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))
        inc1 = res1.get("incident")
        alert1 = res1.get("alert")
        assert inc1 is not None
        assert alert1 is not None
        assert alert1["incident_id"] == inc1["incident_id"]
        assert alert1["attack_type"] == "udp_flood"
        assert alert1["status"] == "ACTIVE"
        assert alert1["acknowledgement_state"] == "UNACKNOWLEDGED"

        # Ingest repeated attack telemetry from ongoing campaign
        res2 = runtime.ingest(generate_window("udp_flood", intensity=3, sequence=1))
        alert2 = res2.get("alert")
        assert alert2 is not None

        # CRITICAL DEDUPLICATION CHECK: Exactly one primary alert updated, no duplicate IDs
        assert alert1["alert_id"] == alert2["alert_id"]

        # Alert Center lists exactly 1 alert
        alerts_res = client.get("/api/admin/alerts")
        assert alerts_res.status_code == 200
        alerts_list = alerts_res.get_json()["alerts"]
        assert len(alerts_list) == 1
        assert alerts_list[0]["alert_id"] == alert1["alert_id"]


def test_alert_acknowledgement(admin_app):
    runtime, app = admin_app
    with app.test_client() as client:
        client.post("/api/auth/login", json={
            "username": "operator",
            "password": "Operator@AICG2026!",
            "mfa_code": "123456"
        })

        res = runtime.ingest(generate_window("syn_flood", intensity=3, sequence=0))
        alert = res["alert"]
        alert_id = alert["alert_id"]

        # Operator acknowledges alert (permitted by ACK_ALERT permission)
        ack_res = client.post(f"/api/admin/alerts/{alert_id}/acknowledge")
        assert ack_res.status_code == 200
        ack_data = ack_res.get_json()
        assert ack_data["acknowledgement_state"] == "ACKNOWLEDGED"
        assert ack_data["acknowledged_by"] == "operator"
        assert ack_data["acknowledged_at"] is not None


def test_alert_lifecycle_follows_incident_resolution(admin_app):
    runtime, app = admin_app
    with app.test_client() as client:
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456"
        })

        res = runtime.ingest(generate_window("slow_rate", intensity=3, sequence=0))
        inc_id = res["incident"]["incident_id"]
        alert_id = res["alert"]["alert_id"]

        # Transition incident through recovery to RESOLVED
        runtime.store.transition_incident(inc_id, "RECOVERING", "system", "Traffic recovering toward baseline")
        resolved_inc = runtime.store.transition_incident(inc_id, "RESOLVED", "system", "Baseline sustained")
        synced_alert = runtime.store.sync_alert_with_incident(resolved_inc)

        assert synced_alert["status"] == "RESOLVED"
        assert synced_alert["lifecycle_state"] == "RESOLVED"

        # Explicit Admin close
        close_res = client.post(f"/api/incidents/{inc_id}/transition", json={
            "state": "CLOSED",
            "actor": "admin",
            "note": "SOC operator completed audit and closed incident."
        })
        assert close_res.status_code == 200

        alert_check = client.get(f"/api/admin/alerts/{alert_id}").get_json()
        assert alert_check["status"] == "CLOSED"
        assert alert_check["lifecycle_state"] == "CLOSED"


# =============================================================================
# 4. ADMINISTRATIVE AUDIT LOG TESTS
# =============================================================================

def test_audit_logs_record_administrative_events_without_passwords(admin_app):
    runtime, app = admin_app
    with app.test_client() as client:
        # Successful login
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456"
        })

        # Failed login attempt
        client.post("/api/auth/login", json={
            "username": "intruder",
            "password": "SuperSecretPassword123!"
        })

        # Inspect audit logs
        logs = runtime.store.list_audit_logs(limit=50)
        assert len(logs) >= 2

        # Verify password privacy
        for log_entry in logs:
            details_str = str(log_entry.get("details", "")).lower()
            assert "supersecretpassword123!" not in details_str
            assert "admin@aicg2026!" not in details_str


# =============================================================================
# 5. ZERO-TRUST POSTURE & SAFETY TESTS
# =============================================================================

def test_zero_trust_posture_endpoint(admin_app):
    _, app = admin_app
    with app.test_client() as client:
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456"
        })

        res = client.get("/api/admin/security/posture")
        assert res.status_code == 200
        posture = res.get_json()

        assert posture["identity"]["type"] == "LOCAL LAB IDENTITY REGISTRY"
        assert posture["authentication"]["status"] == "AUTHENTICATED"
        assert posture["mfa"]["status"] == "SIMULATED_VERIFIED"
        assert posture["authorization"]["enforced"] is True
        assert posture["trust"]["score"] == 100.0
        assert posture["access_decision"]["mode"] == "DRY_RUN"
        assert posture["access_decision"]["host_enforcement"] is False
        assert posture["access_decision"]["network_transmission"] is False
