"""Tests for software-level in-process mitigation enforcement.

Verifies:
1. Normal authenticated device -> ALLOW -> detector executes.
2. Device becomes ISOLATED -> next event is filtered before detector.
3. Device becomes BLOCKED -> next event is filtered before detector.
4. RATE_LIMIT allows events while tokens exist.
5. RATE_LIMIT drops excess events immediately.
6. Rate-limit bucket refills using monotonic time.
7. Filtered event is auditable (recorded in telemetry, auth_token sanitized).
8. Filtered event does not create a duplicate incident.
9. Filtered event does not increment _normal_streak.
10. Multiple isolated devices remain independent.
11. Releasing one device does not release another.
12. Incident RESOLVED releases mitigation.
13. Simulation reset clears mitigation state.
14. Gateway restart reconstruction semantics.
15. Unknown device is still rejected by IAM.
16. Invalid HMAC cannot modify policy state.
17. Sensor impersonation cannot modify legitimate sensor mitigation state.
18. attack_type=None can still produce BLOCK/ISOLATE/RATE_LIMIT from observable signals.
19. attack_type remains preserved as incident/campaign metadata.
20. DRY_RUN remains True.
21. No host/network enforcement commands are invoked.
"""

from pathlib import Path
import subprocess
import time
from unittest.mock import patch
import pytest

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.detection import Decision
from aegis_gateway.iam import compute_device_token
from aegis_gateway.policy import InProcessPolicyEnforcer, ResponseEngine, ResponsePlan, TokenBucket
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.schema import TelemetryEvent, utc_now
from aegis_gateway.security import DEFAULT_SIMULATED_MFA_TOKEN


@pytest.fixture
def runtime_app(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_enforcement.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


def _login(client, username="admin", password="Admin@AICG2026!"):
    res = client.post("/api/auth/login", json={
        "username": username,
        "password": password,
        "mfa_code": DEFAULT_SIMULATED_MFA_TOKEN,
    })
    assert res.status_code == 200
    return res


def test_normal_authenticated_device_allowed(runtime_app):
    """1. Normal authenticated device -> ALLOW -> detector executes."""
    runtime, _ = runtime_app
    norm_event = generate_window("normal", intensity=1, sequence=0)
    res = runtime.ingest(norm_event)

    assert res["event"]["response_action"] == "ALERT"
    assert res["event"]["lifecycle_state"] == "OBSERVED"
    assert res["decision"]["prediction"] == "NORMAL"
    assert res.get("mitigation_enforced") is not True


def test_isolated_device_filtered_before_detector(runtime_app):
    """2. Device becomes ISOLATED -> next event is filtered before detector."""
    runtime, _ = runtime_app

    # Event 1: Critical attack triggers ISOLATE
    ev1 = generate_window("udp_flood", intensity=4, sequence=0)
    res1 = runtime.ingest(ev1)
    assert res1["response"]["action"] == "ISOLATE"
    assert "ATK-01" in runtime.response.enforcer.active_isolates

    # Mock detector to ensure it is NOT called on subsequent event
    with patch.object(runtime.detector, "analyze", side_effect=AssertionError("Detector must not be called")):
        ev2 = generate_window("udp_flood", intensity=4, sequence=1)
        res2 = runtime.ingest(ev2)

        assert res2["mitigation_enforced"] is True
        assert res2["response"]["action"] == "DROP"
        assert res2["response"]["result"] == "SOFTWARE_INTERCEPT"
        assert res2["event"]["lifecycle_state"] == "FILTERED"
        assert res2["event"]["response_action"] == "DROP"


def test_blocked_device_filtered_before_detector(runtime_app):
    """3. Device becomes BLOCKED -> next event is filtered before detector."""
    runtime, _ = runtime_app

    # Establish manual or auto BLOCK on a device
    runtime.response.enforcer.isolate("SENSOR-02", "BLOCK", "Test manual block")

    with patch.object(runtime.detector, "analyze", side_effect=AssertionError("Detector must not be called")):
        ts = utc_now()
        token = compute_device_token("SENSOR-02", ts, "flow-1")
        ev = TelemetryEvent(
            device_id="SENSOR-02",
            timestamp=ts,
            flow_id="flow-1",
            auth_token=token,
            packet_count=20,
            byte_count=1200,
            packet_rate=20.0,
            byte_rate=1200.0,
            protocol="UDP",
        )
        res = runtime.ingest(ev)
        assert res["mitigation_enforced"] is True
        assert res["response"]["action"] == "DROP"
        assert res["event"]["lifecycle_state"] == "FILTERED"


def test_rate_limit_token_bucket_allows_then_drops():
    """4 & 5. RATE_LIMIT allows events while tokens exist, drops excess immediately."""
    limiter = TokenBucket(capacity=5.0, refill_rate=1.0)

    # First 5 events consume tokens successfully
    for _ in range(5):
        assert limiter.consume(1.0) is True

    # 6th event has no tokens left -> immediate drop
    assert limiter.consume(1.0) is False


def test_rate_limit_bucket_refills_using_monotonic_time():
    """6. Rate-limit bucket refills using monotonic time."""
    limiter = TokenBucket(capacity=10.0, refill_rate=10.0)

    # Empty the bucket
    assert limiter.consume(10.0) is True
    assert limiter.consume(1.0) is False

    # Mock time.monotonic to advance by 0.5s (should refill 5 tokens)
    current_time = limiter.last_update
    with patch("time.monotonic", return_value=current_time + 0.5):
        assert limiter.consume(4.0) is True
        assert limiter.consume(2.0) is False  # Only 1 token remained


def test_filtered_event_is_auditable_and_sanitizes_credentials(runtime_app):
    """7. Filtered event is auditable in store with credentials sanitized."""
    runtime, _ = runtime_app
    runtime.response.enforcer.isolate("SENSOR-03", "ISOLATE", "Audit test isolation")

    ts = utc_now()
    token = compute_device_token("SENSOR-03", ts, "flow-audit")
    ev = TelemetryEvent(
        device_id="SENSOR-03",
        timestamp=ts,
        flow_id="flow-audit",
        auth_token=token,
        packet_count=45,
        byte_count=3500,
        packet_rate=45.0,
        byte_rate=3500.0,
        protocol="UDP",
    )
    res = runtime.ingest(ev)
    assert res["mitigation_enforced"] is True

    # Check store row
    rows = runtime.store.telemetry(limit=5)
    matching = [r for r in rows if r.get("device_id") == "SENSOR-03"]
    assert len(matching) >= 1
    stored_row = matching[-1]
    assert stored_row["lifecycle_state"] == "FILTERED"
    assert stored_row["response_action"] == "DROP"
    assert stored_row.get("auth_token") is None

    # Check action log
    actions = runtime.store.actions(limit=5)
    drop_actions = [a for a in actions if a["action"] == "DROP"]
    assert len(drop_actions) >= 1
    assert drop_actions[0]["result"] == "SOFTWARE_INTERCEPT"


def test_filtered_event_does_not_create_duplicate_incident(runtime_app):
    """8. Filtered event does not create a duplicate incident."""
    runtime, _ = runtime_app

    # Event 1: Initial attack -> creates 1 incident
    ev1 = generate_window("udp_flood", intensity=4, sequence=0)
    runtime.ingest(ev1)
    incidents_initial = runtime.store.incidents()
    assert len(incidents_initial) == 1
    initial_id = incidents_initial[0]["incident_id"]

    # Events 2..5: Dropped by policy enforcement
    for s in range(1, 5):
        ev = generate_window("udp_flood", intensity=4, sequence=s)
        res = runtime.ingest(ev)
        assert res["mitigation_enforced"] is True

    # Verify incident count remains 1 and matches initial ID
    incidents_after = runtime.store.incidents()
    assert len(incidents_after) == 1
    assert incidents_after[0]["incident_id"] == initial_id


def test_filtered_event_does_not_increment_normal_streak(runtime_app):
    """9. Filtered event does not increment _normal_streak."""
    runtime, _ = runtime_app

    # Ingest attack -> incident created, streak=0
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0))
    assert runtime._normal_streak == 0

    # Ingest 3 filtered events from isolated attacker
    for s in range(1, 4):
        res = runtime.ingest(generate_window("udp_flood", intensity=4, sequence=s))
        assert res["mitigation_enforced"] is True
        assert runtime._normal_streak == 0, "Filtered attack events must NEVER increment _normal_streak!"


def test_multiple_isolated_devices_remain_independent(runtime_app):
    """10 & 11. Multiple isolated devices remain independent and release independently."""
    runtime, _ = runtime_app
    enforcer = runtime.response.enforcer

    enforcer.isolate("DEVICE-A", "ISOLATE", "Threat A")
    enforcer.isolate("DEVICE-B", "BLOCK", "Threat B")

    dec_a = enforcer.evaluate("DEVICE-A", TelemetryEvent(device_id="DEVICE-A"))
    dec_b = enforcer.evaluate("DEVICE-B", TelemetryEvent(device_id="DEVICE-B"))
    dec_c = enforcer.evaluate("DEVICE-C", TelemetryEvent(device_id="DEVICE-C"))

    assert dec_a.drop is True
    assert dec_b.drop is True
    assert dec_c.drop is False

    # Release DEVICE-A only
    enforcer.release("DEVICE-A")
    assert enforcer.evaluate("DEVICE-A", TelemetryEvent(device_id="DEVICE-A")).drop is False
    assert enforcer.evaluate("DEVICE-B", TelemetryEvent(device_id="DEVICE-B")).drop is True


def test_incident_resolved_releases_mitigation(runtime_app):
    """12. Incident RESOLVED releases in-process mitigation."""
    runtime, _ = runtime_app

    # Attack window isolates ATK-01
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0))
    assert "ATK-01" in runtime.response.enforcer.active_isolates

    # 3 normal windows -> RECOVERING
    for i in range(1, 4):
        runtime.ingest(generate_window("normal", intensity=1, sequence=i, device_id="ATK-01"))

    inc = runtime.store.find_active_incident()
    assert inc["lifecycle_state"] == "RECOVERING"

    # 2 more normal windows (streak 5) -> RESOLVED
    for i in range(4, 6):
        runtime.ingest(generate_window("normal", intensity=1, sequence=i, device_id="ATK-01"))

    inc_resolved = runtime.store.find_active_incident()
    assert inc_resolved is None  # No active unclosed/unresolved incidents

    # ATK-01 must be released from active isolates
    assert "ATK-01" not in runtime.response.enforcer.active_isolates
    assert "ATK-01" not in runtime.response.simulated_isolates


def test_simulation_reset_clears_mitigation_state(runtime_app):
    """13. Simulation reset clears mitigation state and token buckets."""
    runtime, app = runtime_app
    runtime.response.enforcer.isolate("ATK-01", "ISOLATE", "Simulation active")
    runtime.response.enforcer.set_rate_limit("SENSOR-01")
    assert "ATK-01" in runtime.response.enforcer.active_isolates

    with app.test_client() as client:
        _login(client)
        res = client.post("/api/simulations/reset", json={})
        assert res.status_code == 200

    assert len(runtime.response.enforcer.active_isolates) == 0
    assert len(runtime.response.enforcer.rate_limiters) == 0
    assert len(runtime.response.simulated_isolates) == 0


def test_gateway_restart_reconstructs_active_incidents(tmp_path: Path):
    """14. Gateway restart reconstructs active incidents into in-memory enforcer."""
    db_path = tmp_path / "restart_test.sqlite3"
    settings = Settings(database_path=db_path)

    # Runtime 1: Ingest attack, establish CONTAINED incident
    rt1 = GatewayRuntime(settings)
    rt1.ingest(generate_window("udp_flood", intensity=4, sequence=0))
    inc1 = rt1.store.find_active_incident()
    assert inc1["lifecycle_state"] == "CONTAINED"

    # Runtime 2: Reboot gateway with same database
    rt2 = GatewayRuntime(settings)
    # Verify in-memory enforcer reconstructed containment for ATK-01
    assert "ATK-01" in rt2.response.enforcer.active_isolates
    assert rt2.response.enforcer.active_isolates["ATK-01"]["action"] == "ISOLATE"


def test_unknown_device_rejected_by_iam(runtime_app):
    """15. Unknown device is still rejected by IAM."""
    runtime, _ = runtime_app
    ev = TelemetryEvent(
        device_id="ROGUE-99",
        timestamp=utc_now(),
        packet_count=10,
        byte_count=600,
        packet_rate=10.0,
        byte_rate=600.0,
        protocol="UDP",
    )
    res = runtime.ingest(ev)
    assert res["event"]["authentication_status"] == "FAILED_OR_UNVERIFIED"
    assert res["event"]["access_decision"] == "DENY"


def test_invalid_hmac_cannot_modify_policy_state(runtime_app):
    """16 & 17. Invalid HMAC cannot modify legitimate sensor policy state."""
    runtime, _ = runtime_app

    # Legitimate sensor has 100.0 trust and ALLOW policy
    sensor_id = "SENSOR-01"
    assert runtime.iam.get(sensor_id).trust_score == 100.0
    assert sensor_id not in runtime.response.enforcer.active_isolates

    # Impersonator sends packet claiming to be SENSOR-01 with bad HMAC token
    bad_ev = TelemetryEvent(
        device_id=sensor_id,
        timestamp=utc_now(),
        auth_token="bad-hmac-token-12345",
        packet_count=500,
        byte_count=30000,
        packet_rate=500.0,
        byte_rate=30000.0,
        protocol="UDP",
    )
    res = runtime.ingest(bad_ev)

    assert res["event"]["authentication_status"] == "FAILED_OR_UNVERIFIED"
    assert res["event"]["access_decision"] == "DENY"
    # SENSOR-01 trust and policy state MUST NOT be altered
    assert runtime.iam.get(sensor_id).trust_score == 100.0
    assert sensor_id not in runtime.response.enforcer.active_isolates


def test_attack_type_none_decoupled_policy_planning():
    """18. attack_type=None produces proper action from observable signals."""
    engine = ResponseEngine(mode="DRY_RUN", auto=True)

    # 1. Critical severity -> ISOLATE
    crit_dec = Decision("ATTACK", 0.95, "CRITICAL", ["anomaly"], 0.95, "ATTACK", 0.9, "model")
    plan1 = engine.plan(TelemetryEvent(attack_type=None, packet_rate=400.0), crit_dec)
    assert plan1.action == "ISOLATE"

    # 2. Elevated rate with SYN flag -> RATE_LIMIT
    high_syn_dec = Decision("ATTACK", 0.75, "HIGH", ["syn spike"], 0.75, "ATTACK", None, "model")
    plan2 = engine.plan(TelemetryEvent(attack_type=None, packet_rate=60.0, tcp_flags="S"), high_syn_dec)
    assert plan2.action == "RATE_LIMIT"

    # 3. High flood without SYN -> BLOCK
    high_flood_dec = Decision("ATTACK", 0.75, "HIGH", ["udp spike"], 0.75, "ATTACK", None, "model")
    plan3 = engine.plan(TelemetryEvent(attack_type=None, packet_rate=150.0, tcp_flags=None), high_flood_dec)
    assert plan3.action == "BLOCK"


def test_attack_type_preserved_as_incident_metadata(runtime_app):
    """19. attack_type is preserved as incident and alert metadata."""
    runtime, _ = runtime_app
    ev = generate_window("slow_rate", intensity=2, sequence=0)
    assert ev.attack_type == "slow_rate"

    res = runtime.ingest(ev)
    assert res["incident"]["attack_type"] == "slow_rate"
    assert res["alert"]["attack_type"] == "slow_rate"


def test_dry_run_invariant_and_no_host_enforcement(runtime_app):
    """20 & 21. DRY_RUN remains True and no host network commands are invoked."""
    runtime, _ = runtime_app
    assert runtime.settings.response_mode == "DRY_RUN"
    assert runtime.response.mode == "DRY_RUN"

    # Intercept subprocess.run and os.system to verify no network commands are executed
    with patch("subprocess.run") as mock_sub, patch("os.system") as mock_sys:
        # Ingest attack and subsequent filtered event
        runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0))
        runtime.ingest(generate_window("udp_flood", intensity=4, sequence=1))

        mock_sub.assert_not_called()
        mock_sys.assert_not_called()


def test_feature_flag_settings_runtime_behavior(tmp_path: Path):
    """Proves Settings(in_process_enforcement=False) bypasses software short-circuit,

    while Settings(in_process_enforcement=True) causes the event to be filtered.
    """
    # 1. Enforcement Enabled: already-isolated device is filtered at software boundary
    settings_enabled = Settings(
        database_path=tmp_path / "enforcement_enabled.sqlite3",
        in_process_enforcement=True,
    )
    runtime_enabled = GatewayRuntime(settings_enabled)
    runtime_enabled.response.isolate("ATK-01", "ISOLATE", "Threat isolation")
    assert "ATK-01" in runtime_enabled.response.enforcer.active_isolates
    assert "ATK-01" in runtime_enabled.response.simulated_isolates

    with patch.object(runtime_enabled.detector, "analyze", side_effect=AssertionError("Detector must not be called when filtered")) as mock_analyze:
        ev_enabled = generate_window("udp_flood", intensity=4, sequence=1)
        res_enabled = runtime_enabled.ingest(ev_enabled)

        mock_analyze.assert_not_called()
        assert res_enabled["mitigation_enforced"] is True
        assert res_enabled["response"]["action"] == "DROP"
        assert res_enabled["response"]["result"] == "SOFTWARE_INTERCEPT"
        assert res_enabled["event"]["lifecycle_state"] == "FILTERED"

    # 2. Enforcement Disabled: already-isolated device bypasses short-circuit and reaches detector
    settings_disabled = Settings(
        database_path=tmp_path / "enforcement_disabled.sqlite3",
        in_process_enforcement=False,
    )
    runtime_disabled = GatewayRuntime(settings_disabled)
    runtime_disabled.response.isolate("ATK-01", "ISOLATE", "Threat isolation")
    assert "ATK-01" in runtime_disabled.response.enforcer.active_isolates

    with patch.object(runtime_disabled.detector, "analyze", wraps=runtime_disabled.detector.analyze) as spy_analyze:
        ev_disabled = generate_window("udp_flood", intensity=4, sequence=1)
        res_disabled = runtime_disabled.ingest(ev_disabled)

        spy_analyze.assert_called_once()
        assert res_disabled.get("mitigation_enforced") is not True
        assert res_disabled["event"]["lifecycle_state"] != "FILTERED"
        assert res_disabled["response"]["result"] != "SOFTWARE_INTERCEPT"
        assert res_disabled["decision"]["prediction"] == "ATTACK"


def test_feature_flag_env_var_controls_enforcement(tmp_path: Path, monkeypatch):
    """Proves AEGIS_IN_PROCESS_ENFORCEMENT environment variable changes runtime behavior."""
    # Test AEGIS_IN_PROCESS_ENFORCEMENT=false
    monkeypatch.setenv("AEGIS_IN_PROCESS_ENFORCEMENT", "false")
    st_off = Settings(database_path=tmp_path / "env_off.sqlite3")
    assert st_off.in_process_enforcement is False
    rt_off = GatewayRuntime(st_off)
    rt_off.response.isolate("ATK-01", "ISOLATE", "Active isolate")

    with patch.object(rt_off.detector, "analyze", wraps=rt_off.detector.analyze) as spy_det:
        res = rt_off.ingest(generate_window("udp_flood", intensity=4, sequence=1))
        spy_det.assert_called_once()
        assert res.get("mitigation_enforced") is not True
        assert res["event"]["lifecycle_state"] != "FILTERED"

    # Test AEGIS_IN_PROCESS_ENFORCEMENT=true
    monkeypatch.setenv("AEGIS_IN_PROCESS_ENFORCEMENT", "true")
    st_on = Settings(database_path=tmp_path / "env_on.sqlite3")
    assert st_on.in_process_enforcement is True
    rt_on = GatewayRuntime(st_on)
    rt_on.response.isolate("ATK-01", "ISOLATE", "Active isolate")

    with patch.object(rt_on.detector, "analyze", side_effect=AssertionError("Should be filtered")):
        res = rt_on.ingest(generate_window("udp_flood", intensity=4, sequence=1))
        assert res["mitigation_enforced"] is True
        assert res["event"]["lifecycle_state"] == "FILTERED"
        assert res["response"]["action"] == "DROP"


def test_policy_enforcer_authoritative_and_simulated_isolates_synchronized():
    """Proves InProcessPolicyEnforcer is authoritative and simulated_isolates is synchronized."""
    engine = ResponseEngine(mode="DRY_RUN", auto=True)
    assert len(engine.enforcer.active_isolates) == 0
    assert len(engine.simulated_isolates) == 0

    # 1. Isolate action synchronizes to both
    engine.isolate("DEV-01", "ISOLATE", "Threat isolate")
    assert "DEV-01" in engine.enforcer.active_isolates
    assert "DEV-01" in engine.simulated_isolates
    assert engine.enforcer.active_isolates["DEV-01"]["action"] == "ISOLATE"

    # 2. Block action is in enforcer, but not in simulated_isolates
    engine.isolate("DEV-02", "BLOCK", "Threat block")
    assert "DEV-02" in engine.enforcer.active_isolates
    assert "DEV-02" not in engine.simulated_isolates
    assert engine.enforcer.active_isolates["DEV-02"]["action"] == "BLOCK"

    # 3. Direct enforcer method maintains synchronization
    engine.enforcer.isolate("DEV-03", "ISOLATE", "Direct isolate")
    assert "DEV-03" in engine.simulated_isolates

    # 4. Release synchronizes to both
    engine.release("DEV-01")
    assert "DEV-01" not in engine.enforcer.active_isolates
    assert "DEV-01" not in engine.simulated_isolates

    # 5. Reset clears both
    engine.reset()
    assert len(engine.enforcer.active_isolates) == 0
    assert len(engine.simulated_isolates) == 0

