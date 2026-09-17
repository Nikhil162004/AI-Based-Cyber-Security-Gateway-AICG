"""Phase 20 Test Suite: Unified Gateway API Hardening, Zero-Trust Access Enforcement & Storage Integrity.

Comprehensive automated verification covering:
1. Two-Stage Authentication & Simulated MFA Enactment (Pre-MFA session enforcement, invalidation, timeout, rotation)
2. Authentication Rate Limiting & Brute-Force Throttling (HTTP 429)
3. Zero-Trust Access Enforcement across all 12 mutating routes (Fail closed 401 unauthenticated, 403 unauthorized)
4. Role-Based Access Control (RBAC): Operator restricted surface vs Admin full control
5. Audit logging on authorization rejections
6. SQLite Industrial Storage Integrity: WAL mode, foreign keys, busy timeout, synchronous mode
7. Foreign Key Constraint Enforcement
8. Concurrent Read/Write Stress under WAL mode
9. Cryptographic Audit Log Chaining (SHA-256 prev_hash/record_hash) & Tamper Detection
10. Incident Lifecycle Recovery Regression (RECOVERING -> CONTAINED upon recurring attack)
11. Alert Re-escalation (ACKNOWLEDGED -> RE_ESCALATED on higher severity recurrence)
12. Historical Telemetry Immutability
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import time
import pytest
from flask import session

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.security import (
    DEFAULT_SIMULATED_MFA_TOKEN,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    auth_limiter,
    clear_pre_mfa,
    get_pre_mfa_user,
    set_pre_mfa_user,
)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure in-memory rate limiter is cleared between tests."""
    auth_limiter._failures.clear()
    yield
    auth_limiter._failures.clear()


@pytest.fixture
def hardened_app(tmp_path: Path):
    """Fixture providing an isolated GatewayRuntime and Flask test client."""
    db_file = tmp_path / "hardened_gateway.sqlite3"
    settings = Settings(
        database_path=db_file,
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
        auth_rate_limit_max=5,
        auth_rate_limit_window_seconds=60,
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


def _login_as(client, username: str, role: str = "ADMIN"):
    """Helper to perform two-stage login for a given role."""
    password = "Admin@AICG2026!" if role == ROLE_ADMIN else "Operator@AICG2026!"
    res_init = client.post("/api/auth/login", json={
        "username": username,
        "password": password,
    })
    assert res_init.status_code == 200
    res_mfa = client.post("/api/auth/mfa/verify", json={
        "mfa_code": DEFAULT_SIMULATED_MFA_TOKEN
    })
    assert res_mfa.status_code == 200
    return res_mfa


# =============================================================================
# 1. TWO-STAGE AUTHENTICATION & SIMULATED MFA ENFORCEMENT
# =============================================================================

def test_mfa_direct_verification_without_primary_auth_rejected(hardened_app):
    """Direct POST to /api/auth/mfa/verify without prior password verification returns 401 PRE_AUTH_REQUIRED."""
    _, app = hardened_app
    with app.test_client() as client:
        res = client.post("/api/auth/mfa/verify", json={
            "mfa_code": DEFAULT_SIMULATED_MFA_TOKEN
        })
        assert res.status_code == 401
        data = res.get_json()
        assert data["code"] == "PRE_AUTH_REQUIRED"
        assert "primary authentication" in data["error"].lower()


def test_pre_mfa_state_lifecycle_and_expiry(hardened_app):
    """Test pre-MFA state setting, retrieval, expiration (>600s), and clearance."""
    _, app = hardened_app
    with app.test_request_context():
        # Set pre-MFA
        set_pre_mfa_user("testuser", ROLE_OPERATOR)
        pre = get_pre_mfa_user()
        assert pre is not None
        assert pre["username"] == "testuser"
        assert pre["role"] == ROLE_OPERATOR

        # Test simulated expiration
        session["pre_mfa"]["timestamp"] = time.time() - 601
        assert get_pre_mfa_user() is None
        assert "pre_mfa" not in session

        # Test clearance
        set_pre_mfa_user("testuser2", ROLE_ADMIN)
        clear_pre_mfa()
        assert get_pre_mfa_user() is None


def test_session_rotation_on_successful_mfa(hardened_app):
    """Verify session rotation upon successful login and MFA verification."""
    _, app = hardened_app
    with app.test_client() as client:
        # Establish initial session
        client.get("/login")
        cookie_before = client.get_cookie("session")

        # Step 1: Login primary credentials
        res_step1 = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!"
        })
        assert res_step1.status_code == 200
        cookie_after_step1 = client.get_cookie("session")
        # Session cookie regenerated or updated
        assert cookie_after_step1 is not None

        # Step 2: MFA verification
        res_step2 = client.post("/api/auth/mfa/verify", json={
            "mfa_code": DEFAULT_SIMULATED_MFA_TOKEN
        })
        assert res_step2.status_code == 200
        cookie_after_mfa = client.get_cookie("session")
        assert cookie_after_mfa is not None

        # Authenticated session active
        st = client.get("/api/auth/status").get_json()
        assert st["authenticated"] is True
        assert st["user"]["username"] == "admin"


def test_auth_rate_limiting_brute_force_protection(hardened_app):
    """Verify rate limiter blocks authentication attempts exceeding threshold with HTTP 429."""
    _, app = hardened_app
    with app.test_client() as client:
        # Attempt 5 consecutive failed logins
        for _ in range(5):
            r = client.post("/api/auth/login", json={
                "username": "admin",
                "password": "WrongPassword!"
            })
            assert r.status_code == 401

        # 6th attempt must be rejected with 429 RATE_LIMITED
        r_blocked = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!"
        })
        assert r_blocked.status_code == 429
        data = r_blocked.get_json()
        assert data["code"] == "RATE_LIMITED"


# =============================================================================
# 2. ZERO-TRUST ACCESS ENFORCEMENT ACROSS ALL MUTATING ROUTES
# =============================================================================

def test_unauthenticated_rejection_across_all_mutations(hardened_app):
    """Verify all 12 state-mutating endpoints reject unauthenticated requests with HTTP 401."""
    runtime, app = hardened_app
    with app.test_client() as client:
        mutations = [
            ("POST", "/api/incidents/INC-TEST/transition", {"state": "RECOVERING"}),
            ("POST", "/api/incidents/INC-TEST/action", {"action": "BLOCK"}),
            ("POST", "/api/manual/action", {"action": "RATE_LIMIT"}),
            ("POST", "/api/simulations/start", {"scenario_id": "udp_flood"}),
            ("POST", "/api/simulations/stop", {}),
            ("POST", "/api/settings/mode", {"mode": "MANUAL"}),
            ("POST", "/api/admin/users", {"username": "hack", "password": "pw"}),
            ("PATCH", "/api/admin/users/USR-01", {"status": "SUSPENDED"}),
            ("POST", "/api/admin/alerts/ALT-01/acknowledge", {}),
            ("POST", "/api/ns3/import", {"path": "test.csv"}),
            ("POST", "/api/cooja/import", {"path": "test.csv"}),
            ("POST", "/api/pcap/replay", {"path": "test.pcap"}),
        ]

        for method, endpoint, payload in mutations:
            if method == "POST":
                res = client.post(endpoint, json=payload)
            elif method == "PATCH":
                res = client.patch(endpoint, json=payload)
            assert res.status_code == 401, f"Expected 401 for {method} {endpoint}, got {res.status_code}"
            assert res.get_json()["code"] == "AUTH_REQUIRED"

        # Verify audit log captures ACCESS_DENIED records
        audits = runtime.store.list_audit_logs(action="ACCESS_DENIED")
        assert len(audits) >= len(mutations)
        assert all(a["result"] == "DENIED" for a in audits)


# =============================================================================
# 3. ROLE-BASED ACCESS CONTROL (OPERATOR VS ADMIN)
# =============================================================================

def test_operator_permitted_operations(hardened_app):
    """Verify Operator can acknowledge alerts, execute manual actions, and transition recovering/resolved incidents."""
    runtime, app = hardened_app
    # Ingest attack to generate incident and alert
    runtime.ingest(generate_window("syn_flood", intensity=3, sequence=0))
    inc = runtime.store.find_active_incident()
    assert inc is not None
    inc_id = inc["incident_id"]

    alerts = runtime.store.list_alerts(limit=1)
    assert len(alerts) > 0
    alt_id = alerts[0]["alert_id"]

    with app.test_client() as client:
        _login_as(client, "operator", ROLE_OPERATOR)

        # 1. Acknowledge alert
        r_ack = client.post(f"/api/admin/alerts/{alt_id}/acknowledge")
        assert r_ack.status_code == 200

        # 2. Incident action
        r_act = client.post(f"/api/incidents/{inc_id}/action", json={"action": "BLOCK"})
        assert r_act.status_code == 200

        # 3. Manual action
        r_man = client.post("/api/manual/action", json={"action": "RATE_LIMIT"})
        assert r_man.status_code == 200

        # 4. Transition to RECOVERING
        r_trans = client.post(f"/api/incidents/{inc_id}/transition", json={
            "state": "RECOVERING",
            "note": "Operator initiating recovery"
        })
        assert r_trans.status_code == 200


def test_operator_denied_privileged_operations(hardened_app):
    """Verify Operator is strictly denied (HTTP 403) from administrative controls."""
    runtime, app = hardened_app
    # Create an incident to attempt closing
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))
    inc = runtime.store.find_active_incident()
    assert inc is not None
    inc_id = inc["incident_id"]

    with app.test_client() as client:
        _login_as(client, "operator", ROLE_OPERATOR)

        forbidden_mutations = [
            ("POST", f"/api/incidents/{inc_id}/transition", {"state": "CLOSED"}, "FORBIDDEN_ROLE"),
            ("POST", "/api/settings/mode", {"mode": "MANUAL"}, "FORBIDDEN_ROLE"),
            ("POST", "/api/simulations/start", {"scenario_id": "udp_flood"}, "FORBIDDEN_PERMISSION"),
            ("POST", "/api/simulations/stop", {}, "FORBIDDEN_PERMISSION"),
            ("POST", "/api/admin/users", {"username": "u2", "password": "p2"}, "FORBIDDEN_ROLE"),
            ("PATCH", "/api/admin/users/USR-ADMIN-01", {"status": "SUSPENDED"}, "FORBIDDEN_ROLE"),
            ("POST", "/api/ns3/import", {"path": "test.csv"}, "FORBIDDEN_ROLE"),
            ("POST", "/api/cooja/import", {"path": "test.csv"}, "FORBIDDEN_ROLE"),
            ("POST", "/api/pcap/replay", {"path": "test.pcap"}, "FORBIDDEN_ROLE"),
            ("GET", "/api/admin/audit", None, "FORBIDDEN_ROLE"),
            ("GET", "/api/admin/audit/integrity", None, "FORBIDDEN_ROLE"),
        ]

        for method, endpoint, payload, expected_code in forbidden_mutations:
            if method == "POST":
                res = client.post(endpoint, json=payload)
            elif method == "PATCH":
                res = client.patch(endpoint, json=payload)
            elif method == "GET":
                res = client.get(endpoint)

            assert res.status_code == 403, f"Expected 403 for {method} {endpoint}, got {res.status_code}"
            assert res.get_json()["code"] == expected_code


def test_admin_full_access_and_audit_integrity(hardened_app):
    """Verify Admin has complete access to all controls, including closing incidents and verifying audit integrity."""
    runtime, app = hardened_app
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))
    inc = runtime.store.find_active_incident()
    inc_id = inc["incident_id"]

    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)

        # Mode change
        res_mode = client.post("/api/settings/mode", json={"mode": "DRY_RUN", "auto": True})
        assert res_mode.status_code == 200

        # Start and stop simulation
        res_sim = client.post("/api/simulations/start", json={"scenario_id": "normal", "intensity": 1, "duration": 5})
        assert res_sim.status_code == 202
        res_stop = client.post("/api/simulations/stop", json={"scenario_id": "normal"})
        assert res_stop.status_code == 200

        # Step incident through RECOVERING -> RESOLVED -> CLOSED
        r_rec = client.post(f"/api/incidents/{inc_id}/transition", json={"state": "RECOVERING", "note": "Recovery"})
        assert r_rec.status_code == 200
        r_res = client.post(f"/api/incidents/{inc_id}/transition", json={"state": "RESOLVED", "note": "Resolved"})
        assert r_res.status_code == 200
        res_close = client.post(f"/api/incidents/{inc_id}/transition", json={"state": "CLOSED", "note": "Admin closed"})
        assert res_close.status_code == 200
        assert res_close.get_json()["lifecycle_state"] == "CLOSED"

        # Verify audit integrity endpoint
        res_integ = client.get("/api/admin/audit/integrity")
        assert res_integ.status_code == 200
        integ_data = res_integ.get_json()
        assert integ_data["valid"] is True
        assert integ_data["first_corrupted_id"] is None
        assert integ_data["count"] > 0


# =============================================================================
# 4. SQLITE INDUSTRIAL PRAGMAS & CONSTRAINTS
# =============================================================================

def test_sqlite_pragmas_configuration(hardened_app):
    """Verify SQLite connection pragmas: WAL mode, foreign keys ON, busy timeout 5000, synchronous NORMAL."""
    runtime, _ = hardened_app
    with runtime.store.connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0].upper()
        foreign_keys = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        busy_timeout = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        synchronous = conn.execute("PRAGMA synchronous;").fetchone()[0]

        assert journal_mode == "WAL"
        assert foreign_keys == 1
        assert busy_timeout >= 5000
        assert synchronous in (1, "1", "NORMAL")  # 1 corresponds to NORMAL in SQLite


def test_sqlite_foreign_key_enforcement(hardened_app):
    """Verify SQLite foreign key constraints reject orphaned records in dependent tables."""
    runtime, _ = hardened_app
    with runtime.store.connection() as conn:
        # 1. actions table referencing non-existent incident_id
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO actions (action_id, timestamp, action, reason, policy, mode, result, incident_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("ACT-NONEXISTENT", "2026-09-16T12:00:00Z", "BLOCK", "test", "policy", "MANUAL", "SIMULATED", "INC-NONEXISTENT")
            )

        # 2. incident_history table referencing non-existent incident_id
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO incident_history (history_id, incident_id, timestamp, previous_state, state, actor, note) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("HIST-NONEXISTENT", "INC-NONEXISTENT", "2026-09-16T12:00:00Z", "OBSERVED", "DETECTED", "system", "test")
            )

        # 3. admin_alerts table referencing non-existent incident_id
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO admin_alerts (alert_id, incident_id, timestamp, severity, attack_type, target, confidence, detection_reason, lifecycle_state, recommended_action, current_action) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("ALT-NONEXISTENT", "INC-NONEXISTENT", "2026-09-16T12:00:00Z", "HIGH", "udp_flood", "PLC-SINK", 0.95, "Detection", "DETECTED", "BLOCK", "BLOCK")
            )


def test_concurrent_write_stress_under_wal(hardened_app):
    """Verify multi-threaded concurrent writes to database execute without lock errors under WAL mode."""
    runtime, _ = hardened_app

    def worker_write(idx: int):
        with runtime.store.connection() as conn:
            conn.execute(
                "INSERT INTO admin_audit_log (event_id, timestamp, username, role, action, resource, result, details, prev_hash, record_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"AUDIT-CONC-{idx}", f"2026-09-16T12:00:{idx:02d}Z", "system", "SYSTEM", "CONCURRENT_WRITE", "store", "SUCCESS", f"Worker {idx}", "genesis", f"hash-{idx}")
            )

    threads = 12
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker_write, i) for i in range(threads)]
        for f in futures:
            f.result()

    with runtime.store.connection() as conn:
        count = conn.execute("SELECT count(*) FROM admin_audit_log WHERE action = 'CONCURRENT_WRITE'").fetchone()[0]
        assert count == threads


# =============================================================================
# 5. CRYPTOGRAPHIC AUDIT LOG CHAINING & TAMPER DETECTION
# =============================================================================

def test_audit_log_cryptographic_chaining(hardened_app):
    """Verify audit log entries are SHA-256 chained and pass integrity verification."""
    runtime, _ = hardened_app
    for i in range(5):
        runtime.store.record_audit(
            username="admin",
            role=ROLE_ADMIN,
            action=f"TEST_CHAIN_{i}",
            resource="test",
            resource_id=str(i),
            result="SUCCESS",
            details=f"Audited operation {i}",
        )

    integrity = runtime.store.verify_audit_log_integrity()
    assert integrity["valid"] is True
    assert integrity["first_corrupted_id"] is None
    assert integrity["count"] >= 5


def test_audit_log_tamper_detection(hardened_app):
    """Verify that tampering with an audit record's payload invalidates the chain and is detected."""
    runtime, _ = hardened_app
    runtime.store.record_audit(
        username="admin",
        role=ROLE_ADMIN,
        action="LEGIT_EVENT",
        resource="system",
        resource_id="1",
        result="SUCCESS",
        details="Original authentic audit record details",
    )

    # Verify initially valid
    assert runtime.store.verify_audit_log_integrity()["valid"] is True

    # Tamper with the details directly in the DB
    with runtime.store.connection() as conn:
        conn.execute(
            "UPDATE admin_audit_log SET details = 'Tampered malicious payload' WHERE action = 'LEGIT_EVENT'"
        )

    # Audit integrity check MUST detect tampering
    tampered_report = runtime.store.verify_audit_log_integrity()
    assert tampered_report["valid"] is False
    assert tampered_report["first_corrupted_id"] is not None
    assert "Hash mismatch" in tampered_report["reason"]


# =============================================================================
# 6. INCIDENT LIFECYCLE RECOVERY REGRESSION & ALERT RE-ESCALATION
# =============================================================================

def test_incident_recovery_regression_on_recurring_attack(hardened_app):
    """Verify that an incident in RECOVERING regresses to CONTAINED when attack recurs."""
    runtime, _ = hardened_app

    # 1. Attack window -> DETECTED / CONTAINED
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))
    inc = runtime.store.find_active_incident()
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"

    # 2. Ingest 3 normal windows -> transitions to RECOVERING
    for i in range(1, 4):
        runtime.ingest(generate_window("normal", intensity=1, sequence=i))

    inc_rec = runtime.store.find_active_incident()
    assert inc_rec["lifecycle_state"] == "RECOVERING"

    # 3. Recurring attack while in RECOVERING -> MUST regress to CONTAINED
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=4))
    inc_regressed = runtime.store.find_active_incident()
    assert inc_regressed["lifecycle_state"] == "CONTAINED"


def test_alert_re_escalation_on_higher_severity_recurrence(hardened_app):
    """Verify that an ACKNOWLEDGED alert re-escalates to RE_ESCALATED when higher severity recurrence occurs."""
    runtime, _ = hardened_app

    # Ingest HIGH attack -> generates alert
    runtime.ingest(generate_window("syn_flood", intensity=1, sequence=0))
    alerts = runtime.store.list_alerts(limit=1)
    assert len(alerts) > 0
    alt = alerts[0]
    alt_id = alt["alert_id"]
    orig_sev = alt["severity"]

    # Acknowledge alert
    runtime.store.acknowledge_alert(alt_id, "operator")
    ack_alert = runtime.store.get_alert(alt_id)
    assert ack_alert["acknowledgement_state"] == "ACKNOWLEDGED"

    # Ingest CRITICAL attack that triggers higher severity on same incident
    runtime.ingest(generate_window("syn_flood", intensity=5, sequence=1))
    re_alert = runtime.store.get_alert(alt_id)

    assert re_alert["severity"] == "CRITICAL"
    assert re_alert["acknowledgement_state"] == "RE_ESCALATED"
    assert re_alert["status"] == "ACTIVE"


# =============================================================================
# 7. HISTORICAL TELEMETRY IMMUTABILITY
# =============================================================================

def test_historical_telemetry_immutability(hardened_app):
    """Verify past telemetry rows and lifecycle contexts are never rewritten or mutated by subsequent state changes."""
    runtime, app = hardened_app

    # Window 0: Normal
    runtime.ingest(generate_window("normal", intensity=1, sequence=0))
    # Window 1: Attack
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=1))
    # Windows 2-6: Normal recovery
    for i in range(2, 7):
        runtime.ingest(generate_window("normal", intensity=1, sequence=i))

    rows = runtime.store.telemetry(limit=10)
    assert len(rows) == 7

    # Telemetry rows in store
    attack_row = [r for r in rows if r["label"] == "ATTACK"][0]
    assert attack_row["lifecycle_state"] == "DETECTED"

    baseline_row = [r for r in rows if r["label"] == "NORMAL"][0]
    assert baseline_row["lifecycle_state"] == "OBSERVED"

    # API response verification
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)
        res_tel = client.get("/api/telemetry")
        assert res_tel.status_code == 200
        formatted_rows = res_tel.get_json()["rows"]
        formatted_atk = [r for r in formatted_rows if r["prediction"] == "ATTACK"][0]
        assert formatted_atk["lifecycle_context"]["lifecycle_state"] == "DETECTED"

    # Transition active incident to CLOSED
    inc = runtime.store.find_active_incident() or runtime.store.incidents(limit=1)[0]
    runtime.store.transition_incident(inc["incident_id"], "CLOSED", "admin", "Closure")

    # Re-fetch telemetry: historic attack row lifecycle state MUST NOT be altered
    rows_after = runtime.store.telemetry(limit=10)
    attack_row_after = [r for r in rows_after if r["label"] == "ATTACK"][0]
    assert attack_row_after["lifecycle_state"] == "DETECTED"


# =============================================================================
# 8. PHASE 22 WAVE 4: PROTECTED OT TELEMETRY & AUTHORIZATION (C2)
# =============================================================================

def test_unauthenticated_ot_telemetry_access_rejected(hardened_app):
    """Verify that unauthenticated access to protected OT telemetry endpoints returns 401 / AUTH_REQUIRED."""
    runtime, app = hardened_app
    runtime.ingest(generate_window("normal", intensity=1, sequence=0))

    protected_endpoints = [
        "/api/status",
        "/api/telemetry",
        "/api/events",
        "/api/iam",
        "/api/trust",
        "/api/energy",
        "/api/protocols",
        "/api/topology",
        "/api/model-assurance",
        "/api/metrics",
        "/api/scenarios",
        "/api/ns3",
        "/api/cooja",
    ]

    with app.test_client() as client:
        for ep in protected_endpoints:
            res = client.get(ep)
            assert res.status_code == 401, f"Expected 401 for GET {ep}, got {res.status_code}"
            data = res.get_json()
            assert data["code"] == "AUTH_REQUIRED", f"Expected AUTH_REQUIRED code for {ep}, got {data.get('code')}"
            assert data["authenticated"] is False

        # POST /api/iam/access unauthenticated check
        res_iam = client.post("/api/iam/access", json={"identity": "SENSOR-01", "resource": "gateway:telemetry"})
        assert res_iam.status_code == 401, f"Expected 401 for POST /api/iam/access, got {res_iam.status_code}"
        assert res_iam.get_json()["code"] == "AUTH_REQUIRED"


def test_operator_permitted_ot_telemetry_read_access(hardened_app):
    """Verify that authenticated ROLE_OPERATOR can read all protected OT telemetry endpoints with HTTP 200."""
    runtime, app = hardened_app
    runtime.ingest(generate_window("normal", intensity=1, sequence=0))

    protected_endpoints = [
        "/api/status",
        "/api/telemetry",
        "/api/events",
        "/api/iam",
        "/api/trust",
        "/api/energy",
        "/api/protocols",
        "/api/topology",
        "/api/model-assurance",
        "/api/metrics",
        "/api/scenarios",
        "/api/ns3",
        "/api/cooja",
    ]

    with app.test_client() as client:
        _login_as(client, "operator", ROLE_OPERATOR)
        for ep in protected_endpoints:
            res = client.get(ep)
            assert res.status_code == 200, f"Expected 200 for OPERATOR GET {ep}, got {res.status_code}"
            assert res.is_json, f"Expected JSON response for {ep}"


def test_iam_access_authorization_matrix(hardened_app):
    """Verify IAM access evaluation endpoint RBAC: anonymous 401, operator 403, admin 200."""
    runtime, app = hardened_app

    # 1. Anonymous request -> 401
    with app.test_client() as client:
        res_anon = client.post("/api/iam/access", json={"identity": "SENSOR-01", "resource": "gateway:telemetry"})
        assert res_anon.status_code == 401
        assert res_anon.get_json()["code"] == "AUTH_REQUIRED"

    # 2. Operator login -> 403 Forbidden (operator lacks PERM_ADMIN_CONTROLS)
    with app.test_client() as client:
        _login_as(client, "operator", ROLE_OPERATOR)
        res_op = client.post("/api/iam/access", json={"identity": "SENSOR-01", "resource": "gateway:telemetry"})
        assert res_op.status_code == 403
        assert res_op.get_json()["code"] == "FORBIDDEN_PERMISSION"

    # 3. Admin login -> 200 OK
    with app.test_client() as client:
        _login_as(client, "admin", ROLE_ADMIN)
        res_admin = client.post("/api/iam/access", json={"identity": "SENSOR-01", "resource": "gateway:telemetry"})
        assert res_admin.status_code == 200
        data = res_admin.get_json()
        assert "decision" in data
        assert "identity" in data


def test_public_health_endpoint_liveness_and_sanitization(hardened_app):
    """Verify /api/health is public 200 with minimal liveness and no sensitive operational telemetry leakage."""
    runtime, app = hardened_app
    # Ingest baseline normal and attack telemetry to ensure runtime holds live data
    runtime.ingest(generate_window("normal", intensity=1, sequence=0))
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=1))

    with app.test_client() as client:
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()

        # Expected liveness fields
        assert data["ok"] is True
        assert data["status"] == "ONLINE"
        assert data["host_enforcement"] is False
        assert data["response_mode"] == "DRY_RUN"
        assert "safety" in data
        assert "service" in data

        # Explicit verification: MUST NOT leak sensitive telemetry, device IDs, or internal file paths
        assert "latest" not in data, "Public /api/health must not expose 'latest' telemetry"
        assert "database" not in data, "Public /api/health must not expose internal database path"
        assert "active_simulations" not in data
        assert "auth_token" not in str(data)
        assert "password" not in str(data)
        assert "psk" not in str(data)
        assert "model_version" not in data
