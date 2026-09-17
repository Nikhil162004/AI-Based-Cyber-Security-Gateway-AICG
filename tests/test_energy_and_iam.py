"""Tests for cause-based energy model, IAM access decisions, and dynamic trust governance."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from aegis_gateway.config import Settings
from aegis_gateway.energy import EnergyModel
from aegis_gateway.iam import IAMService, compute_device_token
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.schema import utc_now
from aegis_gateway.storage import GatewayStore


def test_energy_correlation_normal_vs_attack():
    model = EnergyModel()
    norm_event = generate_window("normal", intensity=1, sequence=0)
    model.correlate(norm_event)

    assert norm_event.resource_state == "NORMAL"
    assert norm_event.energy_rate is not None
    assert norm_event.energy_deviation is not None
    assert norm_event.energy_cause.startswith("MODELLED:")
    assert norm_event.cpu_activity is not None

    atk_event = generate_window("udp_flood", intensity=4, sequence=0)
    model.correlate(atk_event)

    assert atk_event.resource_state in ("ELEVATED", "CRITICAL")
    assert atk_event.energy_rate > norm_event.energy_rate
    assert atk_event.energy_consumed > norm_event.energy_consumed
    assert atk_event.energy_deviation > norm_event.energy_deviation
    assert atk_event.cpu_activity > norm_event.cpu_activity
    assert atk_event.radio_rx > norm_event.radio_rx


def test_iam_access_decisions():
    iam = IAMService()

    # Authenticated sensor with high trust -> ALLOW
    sensor_acc = iam.access("SENSOR-01")
    assert sensor_acc["decision"] == "ALLOW"
    assert sensor_acc["authorization_status"] == "AUTHORIZED"
    assert sensor_acc["authentication_status"] == "AUTHENTICATED"

    # Untrusted attacker -> DENY
    atk_acc = iam.access("ATK-01")
    assert atk_acc["decision"] == "DENY"
    assert atk_acc["authorization_status"] == "DENIED"

    # Unknown device -> DENY until verified
    unknown_acc = iam.access("ROGUE-NODE")
    assert unknown_acc["identity"] == "ROGUE-NODE"
    assert unknown_acc["role"] == "unknown"


def test_dynamic_trust_decay_and_recovery():
    iam = IAMService()
    identity_name = "TEST-NODE"

    # Initial state
    ident = iam.get(identity_name)
    assert ident.trust_score == 45.0

    # Suspicious detection penalty (-20)
    ident, delta, reason = iam.adjust_trust(identity_name, attack=True)
    assert delta == -20.0
    assert ident.trust_score == 25.0

    # Authentication failure penalty (-15)
    ident, delta, reason = iam.adjust_trust(identity_name, attack=False, auth_failure=True)
    assert delta == -15.0
    assert ident.trust_score == 10.0

    # Recovery observation rewards (+3)
    ident, delta, reason = iam.adjust_trust(identity_name, attack=False, recovered=True)
    assert delta == 3.0
    assert ident.trust_score == 13.0

    # Bound check: trust score never drops below 0
    for _ in range(10):
        iam.adjust_trust(identity_name, attack=True)
    assert iam.get(identity_name).trust_score >= 0.0

    # Bound check: trust score never exceeds 100
    for _ in range(50):
        iam.adjust_trust(identity_name, attack=False, recovered=True)
    assert iam.get(identity_name).trust_score <= 100.0


def test_unknown_sensor_identity_rejected():
    """Gap C1 verification: Unknown SENSOR-* identity is NEVER dynamically auto-trusted."""
    iam = IAMService()
    rogue = iam.get("SENSOR-ROGUE-99")
    assert rogue.identity == "SENSOR-ROGUE-99"
    assert rogue.role == "unknown"
    assert rogue.authenticated is False
    assert rogue.status == "UNREGISTERED"
    assert rogue.trust_score == 45.0

    acc = iam.access("SENSOR-ROGUE-99")
    assert acc["decision"] == "DENY"
    assert acc["authentication_status"] == "FAILED_OR_UNVERIFIED"
    assert acc["authorization_status"] == "DENIED"


def test_sensor_hmac_cryptographic_verification():
    """Verify per-device HMAC token verification and replay window."""
    iam = IAMService()
    now_ts = utc_now()
    flow = "sensor-stream-01"

    # Valid token
    valid_token = compute_device_token("SENSOR-01", now_ts, flow)
    ok, reason = iam.authenticate_device("SENSOR-01", valid_token, now_ts, flow)
    assert ok is True
    assert "verified" in reason.lower()

    # Corrupted / tampered token
    bad_token = "deadbeef" * 8
    ok, reason = iam.authenticate_device("SENSOR-01", bad_token, now_ts, flow)
    assert ok is False
    assert "cryptographic token verification failed" in reason.lower()

    # Missing token
    ok, reason = iam.authenticate_device("SENSOR-01", None, now_ts, flow)
    assert ok is False
    assert "missing" in reason.lower()

    # Expired token (beyond 300s replay drift window)
    old_ts = (datetime.now(timezone.utc) - timedelta(seconds=350)).isoformat()
    old_token = compute_device_token("SENSOR-01", old_ts, flow)
    ok, reason = iam.authenticate_device("SENSOR-01", old_token, old_ts, flow)
    assert ok is False
    assert "expired" in reason.lower()


def test_anti_impersonation_protection(tmp_path: Path):
    """Verify attacker claiming SENSOR-01 cannot degrade legitimate sensor's trust score."""
    settings = Settings(database_path=tmp_path / "test_impersonation.sqlite3")
    runtime = GatewayRuntime(settings=settings)

    # Initial state: SENSOR-01 is enrolled with trust 100.0
    initial_trust = runtime.iam.get("SENSOR-01").trust_score
    assert initial_trust == 100.0

    # Malicious actor sends attack traffic impersonating SENSOR-01 with bad/missing token
    spoofed = generate_window("udp_flood", intensity=4, sequence=0)
    spoofed.device_id = "SENSOR-01"
    spoofed.auth_token = None  # No valid cryptographic token

    res = runtime.ingest(spoofed)

    # Access must be denied
    assert res["event"]["access_decision"] == "DENY"
    assert res["event"]["authentication_status"] == "FAILED_OR_UNVERIFIED"
    assert res["event"]["authorization_status"] == "DENIED"

    # Legitimate sensor's trust score MUST NOT be decayed!
    assert runtime.iam.get("SENSOR-01").trust_score == 100.0
    db_sensor = runtime.store.get_device_identity("SENSOR-01")
    assert db_sensor is not None
    assert db_sensor["trust_score"] == 100.0


def test_persistent_device_identity_across_restarts(tmp_path: Path):
    """Verify device trust score and enrollment persist in SQLite across runtime restart."""
    db_path = tmp_path / "persist.sqlite3"
    settings = Settings(database_path=db_path)

    # Runtime 1: Decay SENSOR-01 trust via legitimate authenticated attack detection
    r1 = GatewayRuntime(settings=settings)
    assert r1.iam.get("SENSOR-01").trust_score == 100.0

    # Valid authenticated event that triggers detection
    valid_ts = utc_now()
    valid_token = compute_device_token("SENSOR-01", valid_ts, "atk-1")
    ev = generate_window("udp_flood", intensity=3, sequence=1)
    ev.device_id = "SENSOR-01"
    ev.timestamp = valid_ts
    ev.flow_id = "atk-1"
    ev.auth_token = valid_token

    r1.ingest(ev)
    decayed_score = r1.iam.get("SENSOR-01").trust_score
    assert decayed_score == 80.0  # -20 for suspicious detection

    # Enroll a new device SENSOR-99
    enroll_res = r1.iam.enroll_device("SENSOR-99", role="sensor")
    assert enroll_res["status"] == "ENROLLED"

    # Simulate process termination & restart: Runtime 2 on the SAME database
    r2 = GatewayRuntime(settings=settings)

    # SENSOR-01 trust score MUST be restored from SQLite (80.0, NOT 100.0)
    assert r2.iam.get("SENSOR-01").trust_score == 80.0

    # SENSOR-99 MUST still be enrolled
    s99 = r2.iam.get("SENSOR-99")
    assert s99.status == "ENROLLED"
    assert s99.role == "sensor"
    assert s99.authenticated is True


def test_device_enrollment_and_revocation(tmp_path: Path):
    """Verify device enrollment, authentication, and revocation lifecycle."""
    store = GatewayStore(tmp_path / "lifecycle.sqlite3")
    iam = IAMService(storage=store)

    # 1. Enroll new sensor
    enrolled = iam.enroll_device("SENSOR-TEST-01", role="sensor")
    assert enrolled["device_id"] == "SENSOR-TEST-01"
    assert enrolled["status"] == "ENROLLED"
    assert enrolled["auth_key_hash"] != ""

    # 2. Authenticate with valid token
    ts = utc_now()
    token = compute_device_token("SENSOR-TEST-01", ts, "flow-1")
    ok, reason = iam.authenticate_device("SENSOR-TEST-01", token, ts, "flow-1")
    assert ok is True

    # 3. Revoke sensor
    revoked = iam.revoke_device("SENSOR-TEST-01")
    assert revoked["status"] == "REVOKED"
    assert revoked["authenticated"] is False

    # 4. Authentication now rejected
    ok2, reason2 = iam.authenticate_device("SENSOR-TEST-01", token, ts, "flow-1")
    assert ok2 is False
    assert "revoked" in reason2.lower()

    # 5. Access denied
    acc = iam.access("SENSOR-TEST-01")
    assert acc["decision"] == "DENY"


def test_api_device_management_endpoints(tmp_path: Path):
    """Verify admin REST endpoints for device enrollment and revocation."""
    from aegis_gateway.api import create_app
    settings = Settings(database_path=tmp_path / "api_iam.sqlite3")
    runtime = GatewayRuntime(settings=settings)
    app = create_app(runtime)

    with app.test_client() as client:
        # Admin login
        login_res = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@AICG2026!",
            "mfa_code": "123456",
        })
        assert login_res.status_code == 200

        # 1. Enroll device
        res_enroll = client.post("/api/iam/devices", json={
            "action": "enroll",
            "device_id": "SENSOR-API-01",
            "role": "sensor",
        })
        assert res_enroll.status_code == 201
        data_enroll = res_enroll.get_json()
        assert data_enroll["ok"] is True
        assert data_enroll["device"]["device_id"] == "SENSOR-API-01"

        # 2. List devices (GET) - auth_key_hash must be sanitized/absent
        res_list = client.get("/api/iam/devices")
        assert res_list.status_code == 200
        dev_list = res_list.get_json()["devices"]
        dev_ids = [d["device_id"] for d in dev_list]
        assert "SENSOR-API-01" in dev_ids
        for d in dev_list:
            assert "auth_key_hash" not in d

        # 3. Revoke device
        res_revoke = client.post("/api/iam/devices", json={
            "action": "revoke",
            "device_id": "SENSOR-API-01",
        })
        assert res_revoke.status_code == 200
        assert res_revoke.get_json()["device"]["status"] == "REVOKED"

        # 4. Verify audit log recorded both events
        enroll_audits = runtime.store.list_audit_logs(action="DEVICE_ENROLLED")
        assert len(enroll_audits) >= 1
        revoke_audits = runtime.store.list_audit_logs(action="DEVICE_REVOKED")
        assert len(revoke_audits) >= 1


def test_auth_token_transient_and_never_persisted_or_exposed(tmp_path: Path):
    """Verify auth_token is transient: authenticates correctly but never persisted or exposed."""
    from aegis_gateway.api import create_app

    settings = Settings(database_path=tmp_path / "test_auth_token_exposure.sqlite3")
    runtime = GatewayRuntime(settings=settings)
    app = create_app(runtime)

    # 1. Valid sensor HMAC event with auth_token attached
    event = generate_window("normal", intensity=1, sequence=0)
    assert event.auth_token is not None
    token_value = event.auth_token

    # Verify repr(event) does NOT expose auth_token
    assert token_value not in repr(event)
    assert token_value not in str(event)

    # Verify event.to_dict() does NOT contain auth_token
    d = event.to_dict()
    assert "auth_token" not in d

    # 2. Ingest valid event: authentication and authorization succeed
    result = runtime.ingest(event)
    assert result["event"]["authentication_status"] == "AUTHENTICATED"
    assert result["event"]["authorization_status"] == "AUTHORIZED"
    assert result["event"]["access_decision"] == "ALLOW"

    # Verify ingest result does NOT contain auth_token
    assert "auth_token" not in result["event"]
    assert token_value not in json.dumps(result, default=str)

    # 3. Verify auth_token is absent from SQLite persisted raw_json
    with runtime.store.connection() as con:
        rows = con.execute("SELECT raw_json FROM telemetry").fetchall()
    assert len(rows) >= 1
    for r in rows:
        assert "auth_token" not in r["raw_json"]
        assert token_value not in r["raw_json"]
        parsed = json.loads(r["raw_json"])
        assert "auth_token" not in parsed

    # 4. Verify auth_token is absent from /api/telemetry
    with app.test_client() as client:
        res = client.get("/api/telemetry")
        assert res.status_code == 200
        telemetry_data = res.get_json()
        assert len(telemetry_data["rows"]) >= 1
        for row in telemetry_data["rows"]:
            assert "auth_token" not in row
            assert token_value not in json.dumps(row)

    # 5. Verify auth_token is absent from runtime SSE broadcast message
    assert len(runtime._recent) >= 1
    for msg in runtime._recent:
        serialized_msg = json.dumps(msg, default=str)
        assert "auth_token" not in serialized_msg
        assert token_value not in serialized_msg

    # 6. Verify invalid HMAC still fails
    spoofed = generate_window("normal", intensity=1, sequence=1)
    spoofed.auth_token = "invalid_token_xyz_12345"
    res_bad = runtime.ingest(spoofed)
    assert res_bad["event"]["authentication_status"] == "FAILED_OR_UNVERIFIED"
    assert res_bad["event"]["authorization_status"] == "DENIED"
    assert res_bad["event"]["access_decision"] == "DENY"
    assert "auth_token" not in res_bad["event"]
