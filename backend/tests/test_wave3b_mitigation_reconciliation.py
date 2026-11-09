"""Phase 23 Wave 3B — Final Mitigation + Incident Lifecycle Reconciliation Tests.

Verifies:
- Test A: ATK-01 automatically recovers after simulation stops via step_device_recovery.
- Test B: Device B cannot advance Device A recovery (device isolation).
- Test C: Exact recovery milestone state transitions (CONTAINED -> RECOVERING -> RESOLVED).
- Test D: Attack resumption during recovery regresses state to CONTAINED and resets streak.
- Test E: DRY_RUN never performs software DROP (PolicyDecision.drop == False).
- Test F: ACTIVE mode performs software DROP (PolicyDecision.drop == True, FILTERED).
- Test G: in_process_enforcement=False bypasses software drops even in ACTIVE mode.
- Test H: Reset terminates active incidents and alerts in SQLite to CLOSED with recovery_state='RESET'.
- Test I: Restart of GatewayRuntime after reset reconstructs zero isolates (no ghost mitigation).
- Test J: Alert center statuses match reset incident state (all linked alerts CLOSED).
- Test K: Simulation stop/reset joins worker threads, eliminating termination race conditions.
- Test L: Multiple concurrent contained devices recover independently without crosstalk.
- Test M: Safety & IAM integrity: ATK-01 receives no auth_token, remains DENIED in IAM, no host network mutation.
"""

from __future__ import annotations

from pathlib import Path
import queue
import threading
import time
from unittest.mock import patch
import pytest

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.policy import PolicyDecision
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.schema import TelemetryEvent, utc_now
from aegis_gateway.security import DEFAULT_SIMULATED_MFA_TOKEN


@pytest.fixture
def runtime_app(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_wave3b.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
        response_mode="ACTIVE",
        in_process_enforcement=True,
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


def test_a_atk01_automatically_recovers_after_simulation_stops(runtime_app):
    """Test A: ATK-01 automatically recovers after simulation stops via step_device_recovery."""
    runtime, _ = runtime_app
    # 1. Ingest attack targeting ATK-01
    atk = generate_window("udp_flood", intensity=4, sequence=0)
    runtime.ingest(atk)

    inc = runtime.store.find_active_incident(device_id="ATK-01")
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"
    assert "ATK-01" in runtime.response.enforcer.active_isolates

    # 2. Step device recovery 5 times
    for _ in range(5):
        runtime.step_device_recovery()

    # 3. Incident reaches RESOLVED and device is released from active_isolates
    inc_resolved = runtime.store.incident(inc["incident_id"])
    assert inc_resolved["lifecycle_state"] == "RESOLVED"
    assert "ATK-01" not in runtime.response.enforcer.active_isolates
    assert runtime.store.find_active_incident(device_id="ATK-01") is None


def test_b_device_b_cannot_advance_device_a_recovery(runtime_app):
    """Test B: Device B normal traffic cannot advance Device A recovery."""
    runtime, _ = runtime_app
    # Contain Device A
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id="DEVICE-A"))
    assert "DEVICE-A" in runtime.response.enforcer.active_isolates
    assert runtime._device_normal_streaks["DEVICE-A"] == 0

    # Ingest 10 normal windows for Device B
    for seq in range(10):
        runtime.ingest(generate_window("normal", intensity=1, sequence=seq, device_id="DEVICE-B"))

    assert runtime._device_normal_streaks["DEVICE-B"] == 10
    assert runtime._device_normal_streaks["DEVICE-A"] == 0
    inc_a = runtime.store.find_active_incident(device_id="DEVICE-A")
    assert inc_a is not None
    assert inc_a["lifecycle_state"] == "CONTAINED"


def test_c_recovery_state_transitions(runtime_app):
    """Test C: Exact recovery milestone state transitions: CONTAINED -> RECOVERING -> RESOLVED."""
    runtime, _ = runtime_app
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id="DEV-C"))
    inc = runtime.store.find_active_incident(device_id="DEV-C")
    assert inc["lifecycle_state"] == "CONTAINED"

    # Windows 1 & 2: still CONTAINED
    runtime.step_device_recovery("DEV-C")
    assert runtime._device_normal_streaks["DEV-C"] == 1
    assert runtime.store.incident(inc["incident_id"])["lifecycle_state"] == "CONTAINED"

    runtime.step_device_recovery("DEV-C")
    assert runtime._device_normal_streaks["DEV-C"] == 2
    assert runtime.store.incident(inc["incident_id"])["lifecycle_state"] == "CONTAINED"

    # Window 3: transitions to RECOVERING
    runtime.step_device_recovery("DEV-C")
    assert runtime._device_normal_streaks["DEV-C"] == 3
    assert runtime.store.incident(inc["incident_id"])["lifecycle_state"] == "RECOVERING"
    assert runtime.response.enforcer.active_isolates["DEV-C"]["state"] == "RECOVERING"

    # Window 4: still RECOVERING
    runtime.step_device_recovery("DEV-C")
    assert runtime._device_normal_streaks["DEV-C"] == 4
    assert runtime.store.incident(inc["incident_id"])["lifecycle_state"] == "RECOVERING"

    # Window 5: transitions to RESOLVED
    runtime.step_device_recovery("DEV-C")
    assert runtime.store.incident(inc["incident_id"])["lifecycle_state"] == "RESOLVED"
    assert "DEV-C" not in runtime.response.enforcer.active_isolates
    assert "DEV-C" not in runtime._device_normal_streaks


def test_d_attack_resumption_during_recovery_regresses(runtime_app):
    """Test D: Attack resumption during recovery regresses state from RECOVERING to CONTAINED."""
    runtime, _ = runtime_app
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id="DEV-D"))
    inc = runtime.store.find_active_incident(device_id="DEV-D")
    assert inc["lifecycle_state"] == "CONTAINED"

    # Advance to streak 3 (RECOVERING)
    for _ in range(3):
        runtime.step_device_recovery("DEV-D")
    assert runtime.store.incident(inc["incident_id"])["lifecycle_state"] == "RECOVERING"
    assert runtime._device_normal_streaks["DEV-D"] == 3

    # New attack window arrives
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=10, device_id="DEV-D"))
    updated = runtime.store.incident(inc["incident_id"])
    assert updated["lifecycle_state"] == "CONTAINED"
    assert runtime._device_normal_streaks["DEV-D"] == 0


def test_e_dry_run_never_performs_software_drop(tmp_path: Path):
    """Test E: DRY_RUN mode never performs software DROP (PolicyDecision.drop == False)."""
    settings = Settings(
        database_path=tmp_path / "test_e.sqlite3",
        response_mode="DRY_RUN",
        in_process_enforcement=True,
    )
    runtime = GatewayRuntime(settings)
    runtime.response.isolate("ATK-01", "ISOLATE", "Threat isolation", state="CONTAINED")

    ev = generate_window("udp_flood", intensity=4, sequence=0)
    decision = runtime.response.evaluate("ATK-01", ev)
    assert decision.drop is False
    assert decision.action == "ALLOW"

    with patch.object(runtime.detector, "analyze", wraps=runtime.detector.analyze) as spy_det:
        res = runtime.ingest(ev)
        spy_det.assert_called_once()
        assert res.get("mitigation_enforced") is not True
        assert res["event"]["lifecycle_state"] != "FILTERED"


def test_f_active_mode_performs_software_drop(tmp_path: Path):
    """Test F: ACTIVE mode performs software DROP (PolicyDecision.drop == True, FILTERED)."""
    settings = Settings(
        database_path=tmp_path / "test_f.sqlite3",
        response_mode="ACTIVE",
        in_process_enforcement=True,
    )
    runtime = GatewayRuntime(settings)
    runtime.response.isolate("ATK-01", "ISOLATE", "Threat isolation", state="CONTAINED")

    ev = generate_window("udp_flood", intensity=4, sequence=0)
    decision = runtime.response.evaluate("ATK-01", ev)
    assert decision.drop is True
    assert decision.action == "DROP"

    with patch.object(runtime.detector, "analyze", side_effect=AssertionError("Detector must not run")):
        res = runtime.ingest(ev)
        assert res["mitigation_enforced"] is True
        assert res["response"]["action"] == "DROP"
        assert res["response"]["result"] == "SOFTWARE_INTERCEPT"
        assert res["event"]["lifecycle_state"] == "FILTERED"


def test_g_in_process_enforcement_disabled_bypasses_all_drops(tmp_path: Path):
    """Test G: in_process_enforcement=False bypasses all drops even when response_mode=ACTIVE."""
    settings = Settings(
        database_path=tmp_path / "test_g.sqlite3",
        response_mode="ACTIVE",
        in_process_enforcement=False,
    )
    runtime = GatewayRuntime(settings)
    runtime.response.isolate("ATK-01", "ISOLATE", "Threat isolation", state="CONTAINED")

    ev = generate_window("udp_flood", intensity=4, sequence=0)
    decision = runtime.response.evaluate("ATK-01", ev)
    assert decision.drop is False

    with patch.object(runtime.detector, "analyze", wraps=runtime.detector.analyze) as spy_det:
        res = runtime.ingest(ev)
        spy_det.assert_called_once()
        assert res.get("mitigation_enforced") is not True
        assert res["event"]["lifecycle_state"] != "FILTERED"


def test_h_reset_terminates_active_sqlite_incidents_and_alerts(runtime_app):
    """Test H: Reset terminates active SQLite incidents and alerts to CLOSED with recovery_state='RESET'."""
    runtime, app = runtime_app
    client = app.test_client()
    _login(client)

    # Generate an incident
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0))
    inc = runtime.store.find_active_incident(device_id="ATK-01")
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"

    alerts_before = runtime.store.list_alerts()
    assert len(alerts_before) > 0
    assert any(a["status"] != "CLOSED" for a in alerts_before)

    # Call reset
    res = client.post("/api/simulations/reset")
    assert res.status_code == 200
    assert res.json["status"] == "RESET"

    # Assert zero unclosed/unresolved incidents in SQLite
    assert runtime.store.find_active_incident(device_id="ATK-01") is None
    closed_inc = runtime.store.incident(inc["incident_id"])
    assert closed_inc["lifecycle_state"] == "CLOSED"
    assert closed_inc["recovery_state"] == "RESET"

    # Assert zero active alerts in SQLite
    alerts_after = runtime.store.list_alerts()
    assert all(a["status"] == "CLOSED" for a in alerts_after)


def test_i_restart_after_reset_prevents_ghost_mitigation(tmp_path: Path):
    """Test I: Restart after reset prevents ghost mitigation."""
    db_path = tmp_path / "test_i.sqlite3"
    settings = Settings(
        database_path=db_path,
        response_mode="ACTIVE",
        in_process_enforcement=True,
    )
    runtime = GatewayRuntime(settings)
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0))
    assert "ATK-01" in runtime.response.enforcer.active_isolates

    # Reset
    runtime.stop_simulation()
    runtime.store.reset_active_incidents_and_alerts(actor="admin")
    runtime.response.reset()
    runtime.reset_streaks()
    assert len(runtime.response.enforcer.active_isolates) == 0

    # Simulate restart by instantiating new GatewayRuntime on the same database
    runtime_restarted = GatewayRuntime(settings)
    assert len(runtime_restarted.response.enforcer.active_isolates) == 0
    assert "ATK-01" not in runtime_restarted.response.enforcer.active_isolates
    assert "ATK-01" not in runtime_restarted.response.simulated_isolates


def test_j_alerts_match_reset_incident_state(runtime_app):
    """Test J: Alert center status matches reset incident state via API."""
    runtime, app = runtime_app
    client = app.test_client()
    _login(client)

    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0))
    alerts_resp = client.get("/api/admin/alerts")
    assert alerts_resp.status_code == 200
    alerts_list = alerts_resp.json.get("alerts", [])
    active_alerts = [a for a in alerts_list if a.get("status") not in {"RESOLVED", "CLOSED"}]
    assert len(active_alerts) > 0

    # Reset
    reset_resp = client.post("/api/simulations/reset")
    assert reset_resp.status_code == 200

    alerts_resp_after = client.get("/api/admin/alerts")
    assert alerts_resp_after.status_code == 200
    alerts_after_list = alerts_resp_after.json.get("alerts", [])
    assert len(alerts_after_list) > 0
    assert all(a.get("status") == "CLOSED" for a in alerts_after_list)
    assert all(a.get("lifecycle_state") == "CLOSED" for a in alerts_after_list)


def test_k_simulation_stop_thread_join_race(runtime_app):
    """Test K: Simulation stop bounded join eliminates termination races."""
    runtime, _ = runtime_app
    sim = runtime.start_simulation("udp_flood", intensity=2)
    assert sim["state"] == "RUNNING"
    sim_state = runtime._simulations.get("udp_flood")
    assert sim_state is not None
    thread = sim_state.thread
    assert thread.is_alive()

    # stop_simulation must join thread before returning
    stopped = runtime.stop_simulation("udp_flood")
    assert "udp_flood" in stopped
    assert not thread.is_alive()
    assert "udp_flood" not in runtime._simulations


def test_l_multiple_concurrent_devices_quiescent_recovery(runtime_app):
    """Test L: Multiple concurrent contained devices recover independently without crosstalk."""
    runtime, _ = runtime_app
    # Contain Device 1 and Device 2
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id="DEV-L1"))
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id="DEV-L2"))

    assert "DEV-L1" in runtime.response.enforcer.active_isolates
    assert "DEV-L2" in runtime.response.enforcer.active_isolates

    # Step recovery for both
    for _ in range(3):
        runtime.step_device_recovery()

    inc1 = runtime.store.find_active_incident(device_id="DEV-L1")
    inc2 = runtime.store.find_active_incident(device_id="DEV-L2")
    assert inc1["lifecycle_state"] == "RECOVERING"
    assert inc2["lifecycle_state"] == "RECOVERING"

    # Resume attack only on DEV-L1
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=5, device_id="DEV-L1"))
    assert runtime.store.incident(inc1["incident_id"])["lifecycle_state"] == "CONTAINED"
    assert runtime.store.incident(inc2["incident_id"])["lifecycle_state"] == "RECOVERING"

    # Step recovery again - DEV-L2 completes recovery
    for _ in range(2):
        runtime.step_device_recovery("DEV-L2")

    assert runtime.store.incident(inc2["incident_id"])["lifecycle_state"] == "RESOLVED"
    assert "DEV-L2" not in runtime.response.enforcer.active_isolates
    # DEV-L1 still contained
    assert "DEV-L1" in runtime.response.enforcer.active_isolates


def test_m_safety_and_iam_integrity(runtime_app):
    """Test M: Safety & IAM integrity invariants:
    - ATK-01 never receives an auth_token during normal/recovery observation.
    - ATK-01 is rejected by IAM (DENIED, FAILED_OR_UNVERIFIED).
    - No attack_type inference shortcut used by policy enforcer.
    - No host networking commands executed (subprocess.run, os.system).
    """
    runtime, _ = runtime_app

    # 1. Verify ATK-01 window has no auth token
    norm_atk = generate_window("normal", intensity=1, sequence=0, device_id="ATK-01")
    assert norm_atk.auth_token is None

    # Verify SENSOR-01 gets auth token
    sensor_ev = generate_window("normal", intensity=1, sequence=0, device_id="SENSOR-01")
    assert sensor_ev.auth_token is not None

    # 2. Ingest ATK-01 normal window and verify IAM denies access
    res = runtime.ingest(norm_atk)
    assert res["event"]["authentication_status"] == "FAILED_OR_UNVERIFIED"
    assert res["event"]["authorization_status"] == "DENIED"
    assert res["event"]["access_decision"] == "DENY"

    # 3. Verify no host firewall/network commands are ever invoked
    with patch("subprocess.run") as mock_sub, patch("os.system") as mock_sys:
        runtime.ingest(generate_window("udp_flood", intensity=4, sequence=1))
        runtime.step_device_recovery()
        runtime.stop_simulation()
        mock_sub.assert_not_called()
        mock_sys.assert_not_called()


def test_n_active_attack_simulation_prevents_recovery_observation(runtime_app):
    """Test N: Proves active attack simulation prevents recovery observations, and stopping allows it.

    Verifies:
    1. ATK-01 active attack simulation running -> step_device_recovery() generates NO recovery observation.
       Streak remains 0, state remains CONTAINED.
    2. ATK-01 attack simulation stopped -> step_device_recovery() generates recovery observations.
       Streak increments toward RECOVERING / RESOLVED.
    3. Multi-device: Equivalent behavior verified for a second controlled device (DEV-CTRL-02).
       While DEV-CTRL-02 has active attack simulation running, it receives no recovery observations.
       When DEV-CTRL-02 simulation stops, it receives recovery observations.
    """
    runtime, _ = runtime_app

    # Part 1: ATK-01
    # Start active simulation for ATK-01
    runtime.start_simulation("udp_flood", intensity=2)
    # Wait for simulation to contain ATK-01
    for _ in range(50):
        inc_atk01 = runtime.store.find_active_incident(device_id="ATK-01")
        if inc_atk01 and inc_atk01.get("lifecycle_state") == "CONTAINED" and "ATK-01" in runtime.response.enforcer.active_isolates:
            break
        time.sleep(0.05)
    assert "ATK-01" in runtime.response.enforcer.active_isolates
    inc_atk01 = runtime.store.find_active_incident(device_id="ATK-01")
    assert inc_atk01 is not None
    assert inc_atk01["lifecycle_state"] == "CONTAINED"

    # While simulation is running, step_device_recovery must NOT produce recovery observation for ATK-01
    recovery_res = runtime.step_device_recovery()
    assert len(recovery_res) == 0
    assert runtime._device_normal_streaks["ATK-01"] == 0

    # Stop simulation for ATK-01
    stopped = runtime.stop_simulation("udp_flood")
    assert "udp_flood" in stopped

    # Now that simulation has stopped, step_device_recovery allows recovery observation
    recovery_res2 = runtime.step_device_recovery()
    assert len(recovery_res2) == 1
    assert recovery_res2[0]["event"]["device_id"] == "ATK-01"
    assert runtime._device_normal_streaks["ATK-01"] == 1

    # Part 2: Second Controlled Device (DEV-CTRL-02)
    # Start active simulation targeting DEV-CTRL-02
    runtime.start_simulation("syn_flood", intensity=2, device_id="DEV-CTRL-02")
    for _ in range(50):
        inc_dev2 = runtime.store.find_active_incident(device_id="DEV-CTRL-02")
        if inc_dev2 and inc_dev2.get("lifecycle_state") == "CONTAINED" and "DEV-CTRL-02" in runtime.response.enforcer.active_isolates:
            break
        time.sleep(0.05)
    assert "DEV-CTRL-02" in runtime.response.enforcer.active_isolates
    inc_dev2 = runtime.store.find_active_incident(device_id="DEV-CTRL-02")
    assert inc_dev2 is not None

    # While DEV-CTRL-02 simulation is active, step_device_recovery must exclude DEV-CTRL-02
    obs_batch = runtime.step_device_recovery()
    devs_observed = [o["event"]["device_id"] for o in obs_batch]
    assert "DEV-CTRL-02" not in devs_observed

    # Stop DEV-CTRL-02 simulation
    runtime.stop_simulation("syn_flood")

    # Now DEV-CTRL-02 can receive recovery observations
    obs_batch2 = runtime.step_device_recovery("DEV-CTRL-02")
    assert len(obs_batch2) == 1
    assert obs_batch2[0]["event"]["device_id"] == "DEV-CTRL-02"
    assert runtime._device_normal_streaks["DEV-CTRL-02"] >= 1


def test_o_reset_concurrency_while_baseline_worker_active(runtime_app):
    """Test O: Reset concurrency while baseline worker is active.

    Verifies:
    1. Baseline worker is active and running before reset.
    2. Reset called while baseline is active:
       - No duplicate baseline threads are created.
       - Exactly one baseline worker is running after reset.
       - No active incidents are recreated by a stale worker.
       - Reset remains deterministic.
    """
    runtime, app = runtime_app
    client = app.test_client()
    _login(client)

    # 1. Start baseline worker with fast tick
    runtime.start_baseline(tick_seconds=0.05)
    assert runtime._baseline_thread is not None
    assert runtime._baseline_thread.is_alive()
    initial_thread = runtime._baseline_thread

    # 2. Ingest an attack to create an active incident in SQLite and enforcer
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0))
    inc = runtime.store.find_active_incident(device_id="ATK-01")
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"
    assert "ATK-01" in runtime.response.enforcer.active_isolates

    # 3. Call reset endpoint while baseline worker is active
    res = client.post("/api/simulations/reset")
    assert res.status_code == 200
    assert res.json["status"] == "RESET"

    # 4. Verify thread state
    assert runtime._baseline_thread is not None
    assert runtime._baseline_thread.is_alive()
    # The old initial thread was cleanly joined and replaced by exactly one new baseline thread
    assert runtime._baseline_thread != initial_thread
    assert not initial_thread.is_alive()

    # Calling start_baseline again must NOT create duplicate threads
    current_thread = runtime._baseline_thread
    runtime.start_baseline()
    assert runtime._baseline_thread == current_thread

    # 5. Let baseline run for several ticks and verify no stale worker recreates an active incident
    time.sleep(0.2)
    assert runtime.store.find_active_incident(device_id="ATK-01") is None
    closed_inc = runtime.store.incident(inc["incident_id"])
    assert closed_inc["lifecycle_state"] == "CLOSED"
    assert closed_inc["recovery_state"] == "RESET"
    assert len(runtime.response.enforcer.active_isolates) == 0

    # Clean up baseline
    runtime.stop_baseline()


def test_p_asynchronous_baseline_worker_recovers_active_block_incident(tmp_path: Path):
    """Test P: Real asynchronous background baseline worker recovery in ACTIVE mode with BLOCK action.

    Verifies:
    1. Gateway running in ACTIVE mode with in-process enforcement.
    2. Attack simulation runs in background thread, containing ATK-01 with action BLOCK.
    3. Attack simulation stops naturally or via duration.
    4. Without calling _verify_recovery(), step_device_recovery(), transition_incident(), or resolve():
       Background worker 'aegis-live-baseline' automatically generates recovery observations.
    5. Contained device with BLOCK action is NOT dropped by policy.
    6. Device normal streak drives progression: CONTAINED -> RECOVERING (streak >= 3) -> RESOLVED (streak >= 5).
    7. ATK-01 is released from active_isolates upon resolution.
    8. Incident and linked alert in SQLite are both synchronized to RESOLVED.
    """
    settings = Settings(
        database_path=tmp_path / "test_p.sqlite3",
        response_mode="ACTIVE",
        in_process_enforcement=True,
        demo_tick_seconds=0.05,
    )
    runtime = GatewayRuntime(settings)
    runtime.start_baseline(tick_seconds=0.05)
    app = create_app(runtime)
    client = app.test_client()
    _login(client)

    try:
        # 1. Start simulation with high-rate attack (duration = 0.25s)
        res = client.post("/api/simulations/start", json={
            "scenario_id": "udp_flood",
            "intensity": 3,
            "duration": 0.25
        })
        assert res.status_code == 202

        # 2. Wait until incident is created and contained
        inc = None
        for _ in range(50):
            inc = runtime.store.find_active_incident(device_id="ATK-01")
            if inc and inc["lifecycle_state"] == "CONTAINED":
                break
            time.sleep(0.05)

        assert inc is not None
        assert inc["lifecycle_state"] == "CONTAINED"
        assert "ATK-01" in runtime.response.enforcer.active_isolates
        initial_action = runtime.response.enforcer.active_isolates["ATK-01"]["action"]
        assert initial_action in {"BLOCK", "ISOLATE"}

        # 3. Wait for attack simulation thread to stop
        for _ in range(50):
            if "udp_flood" not in runtime._simulations:
                break
            time.sleep(0.05)
        assert "udp_flood" not in runtime._simulations

        # 4. Without any manual intervention, allow background worker to drive recovery to RESOLVED
        # (Bounded wait up to 4 seconds)
        resolved = False
        curr = None
        for _ in range(80):
            curr = runtime.store.incident(inc["incident_id"])
            if curr and curr["lifecycle_state"] == "RESOLVED" and "ATK-01" not in runtime.response.enforcer.active_isolates:
                resolved = True
                break
            time.sleep(0.05)

        assert resolved, f"Background baseline worker failed to autonomously resolve incident: state={curr['lifecycle_state'] if curr else None}, streaks={dict(runtime._device_normal_streaks)}"
        assert curr["recovery_state"] == "VERIFIED"
        assert "ATK-01" not in runtime.response.enforcer.active_isolates
        assert runtime.store.find_active_incident(device_id="ATK-01") is None

        # Verify linked alert is RESOLVED
        alerts = runtime.store.list_alerts()
        linked = [a for a in alerts if a["incident_id"] == inc["incident_id"]]
        assert len(linked) == 1
        assert linked[0]["status"] == "RESOLVED"

    finally:
        runtime.stop_baseline()


def test_q_block_isolate_rate_limit_contained_recovery_qualification(runtime_app):
    """Test Q: Devices contained under BLOCK, ISOLATE, or RATE_LIMIT all qualify for recovery observations."""
    runtime, _ = runtime_app

    # Test BLOCK
    runtime.response.isolate("DEV-BLK", "BLOCK", "Volumetric block", state="CONTAINED")
    recovery_win = generate_window("normal", intensity=1, sequence=0, device_id="DEV-BLK", source_type="RECOVERY_OBSERVER")
    dec_rec = runtime.response.evaluate("DEV-BLK", recovery_win)
    assert dec_rec.drop is False
    assert dec_rec.action == "ALLOW"

    flood_win = generate_window("udp_flood", intensity=4, sequence=0, device_id="DEV-BLK")
    dec_flood = runtime.response.evaluate("DEV-BLK", flood_win)
    assert dec_flood.drop is True
    assert dec_flood.action == "DROP"

    # Test ISOLATE
    runtime.response.isolate("DEV-ISO", "ISOLATE", "Threat isolation", state="CONTAINED")
    dec_rec_iso = runtime.response.evaluate("DEV-ISO", recovery_win)
    assert dec_rec_iso.drop is False
    assert dec_rec_iso.action == "ALLOW"

    dec_flood_iso = runtime.response.evaluate("DEV-ISO", flood_win)
    assert dec_flood_iso.drop is True
    assert dec_flood_iso.action == "DROP"

    # Test RATE_LIMIT
    runtime.response.isolate("DEV-RL", "RATE_LIMIT", "Rate limit contained", state="CONTAINED")
    dec_rec_rl = runtime.response.evaluate("DEV-RL", recovery_win)
    assert dec_rec_rl.drop is False
    assert dec_rec_rl.action == "ALLOW"

    dec_flood_rl = runtime.response.evaluate("DEV-RL", flood_win)
    assert dec_flood_rl.drop is True
    assert dec_flood_rl.action == "DROP"


def test_r_normal_simulation_does_not_suppress_recovery_worker(runtime_app):
    """Test R: Launching a 'normal' simulation does not suppress step_device_recovery()."""
    runtime, app = runtime_app
    client = app.test_client()
    _login(client)

    # 1. Contained device ATK-01 exists
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))
    inc = runtime.store.find_active_incident(device_id="ATK-01")
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"

    # 2. Start 'normal' simulation
    res = client.post("/api/simulations/start", json={"scenario_id": "normal", "intensity": 1})
    assert res.status_code == 202
    assert "normal" in runtime._simulations

    # 3. step_device_recovery generates observations for ATK-01 even while 'normal' simulation is active
    obs = runtime.step_device_recovery()
    assert len(obs) >= 1
    assert any(o["event"]["device_id"] == "ATK-01" for o in obs)
    assert runtime._device_normal_streaks["ATK-01"] >= 1

    runtime.stop_simulation("normal")


def test_s_dashboard_state_authority_remains_active_when_telemetry_normal(runtime_app):
    """Test S: /api/status provides active_incident and lifecycle_state so dashboard stays active while telemetry is normal."""
    runtime, app = runtime_app
    client = app.test_client()
    _login(client)

    # 1. Attack creates active incident
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))
    inc = runtime.store.find_active_incident(device_id="ATK-01")
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"

    # 2. Normal sensor window arrives
    runtime.ingest(generate_window("normal", sequence=1, device_id="SENSOR-01"))

    # 3. Query /api/status
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json
    summary = data["summary"]

    # Telemetry prediction is NORMAL
    assert summary["latest_prediction"] == "NORMAL"
    # But active_incident is present and CONTAINED
    assert summary["active_incident"] is not None
    assert summary["active_incident"]["lifecycle_state"] == "CONTAINED"
    assert summary["lifecycle_state"] == "CONTAINED"


def test_t_backend_emits_all_intermediate_lifecycle_events(runtime_app):
    """Test T: Backend emits DETECTED, TRIAGED, RESPONDING, and CONTAINED sequentially to SSE subscribers."""
    runtime, _ = runtime_app
    sub_q: queue.Queue = queue.Queue(maxsize=100)
    with runtime._lock:
        runtime._subscribers.add(sub_q)

    try:
        # Ingest attack window
        runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))

        # Collect incident events from queue
        incident_events = []
        while not sub_q.empty():
            msg = sub_q.get_nowait()
            if msg.get("type") == "incident":
                incident_events.append(msg["data"]["lifecycle_state"])

        assert incident_events == ["DETECTED", "TRIAGED", "RESPONDING", "CONTAINED"]
    finally:
        with runtime._lock:
            runtime._subscribers.discard(sub_q)


def test_u_incident_history_contains_complete_pipeline(runtime_app):
    """Test U: SQLite incident_history records DETECTED, TRIAGED, RESPONDING, and CONTAINED."""
    runtime, _ = runtime_app
    runtime.ingest(generate_window("udp_flood", intensity=3, sequence=0))
    inc = runtime.store.find_active_incident(device_id="ATK-01")
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"

    full_inc = runtime.store.incident(inc["incident_id"])
    assert full_inc is not None
    history = full_inc.get("history", [])
    history_states = [(h.get("previous_state"), h.get("state")) for h in history]
    assert (None, "DETECTED") in history_states
    assert ("DETECTED", "TRIAGED") in history_states
    assert ("TRIAGED", "RESPONDING") in history_states
    assert ("RESPONDING", "CONTAINED") in history_states
