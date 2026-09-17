"""Phase 23 Wave 3A — Per-Device Incident Recovery & Concurrency Hardening Tests.

Verifies:
1. Test A: Device A contained, Device B normal traffic does NOT advance Device A.
2. Test B: Device B has recovery progress (streak 2), Device A attack does NOT reset Device B.
3. Test C: Device A independently completes recovery (streak 3 -> RECOVERING, streak 5 -> RESOLVED) and is released.
4. Test D: Two devices have independent active incidents; recovery of Device A does NOT release Device B.
5. Test E: Concurrent multi-threaded ingestion from multiple devices does not corrupt per-device recovery streaks.
6. Test F: Concurrent attack events for the same device do not create duplicate active incidents in SQLite.
7. Test G: Contained-device active attack cannot accidentally release an actively attacking device.
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
import threading
import pytest

from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window
from aegis_gateway.schema import TelemetryEvent, utc_now


@pytest.fixture
def runtime_app(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_wave3a_recovery.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


def test_a_device_a_contained_device_b_normal_traffic_does_not_advance_device_a(runtime_app):
    """Test A: Device A is contained; Device B normal traffic MUST NOT advance Device A recovery."""
    runtime, _ = runtime_app

    # 1. Device A attacks and is contained
    atk_ev = generate_window("udp_flood", intensity=4, sequence=0, device_id="DEVICE-A")
    runtime.ingest(atk_ev)

    inc_a = runtime.store.find_active_incident(device_id="DEVICE-A")
    assert inc_a is not None
    assert inc_a["lifecycle_state"] == "CONTAINED"
    assert "DEVICE-A" in runtime.response.enforcer.active_isolates
    assert runtime._device_normal_streaks["DEVICE-A"] == 0

    # 2. Ingest 5 normal windows from Device B
    for s in range(1, 6):
        norm_b = generate_window("normal", intensity=1, sequence=s, device_id="DEVICE-B")
        runtime.ingest(norm_b)

    # 3. Assertions: Device B has streak=5, but Device A is completely untouched
    assert runtime._device_normal_streaks["DEVICE-B"] == 5
    assert runtime._device_normal_streaks["DEVICE-A"] == 0

    # Incident for Device A MUST still be CONTAINED (never RECOVERING or RESOLVED)
    inc_a_after = runtime.store.find_active_incident(device_id="DEVICE-A")
    assert inc_a_after is not None
    assert inc_a_after["lifecycle_state"] == "CONTAINED"
    assert "DEVICE-A" in runtime.response.enforcer.active_isolates


def test_b_device_b_recovery_progress_not_reset_by_device_a_attack(runtime_app):
    """Test B: Device B has recovery progress (streak 2); Device A attack MUST NOT reset Device B."""
    runtime, _ = runtime_app

    # 1. Device B attacks and gets contained
    atk_b = generate_window("udp_flood", intensity=4, sequence=0, device_id="DEVICE-B")
    runtime.ingest(atk_b)
    inc_b = runtime.store.find_active_incident(device_id="DEVICE-B")
    assert inc_b["lifecycle_state"] == "CONTAINED"

    # 2. Device B sends 2 normal observation windows -> streak becomes 2
    for s in range(1, 3):
        norm_b = generate_window("normal", intensity=1, sequence=s, device_id="DEVICE-B")
        runtime.ingest(norm_b)
    assert runtime._device_normal_streaks["DEVICE-B"] == 2

    # 3. Device A launches an attack
    atk_a = generate_window("udp_flood", intensity=4, sequence=10, device_id="DEVICE-A")
    runtime.ingest(atk_a)
    assert runtime._device_normal_streaks["DEVICE-A"] == 0

    # 4. Assert Device B's streak was NOT reset and remains 2
    assert runtime._device_normal_streaks["DEVICE-B"] == 2
    inc_b_check = runtime.store.find_active_incident(device_id="DEVICE-B")
    assert inc_b_check["lifecycle_state"] == "CONTAINED"


def test_c_device_a_independently_completes_recovery_and_is_released(runtime_app):
    """Test C: Device A independently completes recovery (streak 3 -> RECOVERING, streak 5 -> RESOLVED) and is released."""
    runtime, _ = runtime_app

    # 1. Device A attacks and gets contained
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id="DEVICE-A"))
    assert "DEVICE-A" in runtime.response.enforcer.active_isolates
    assert runtime.store.find_active_incident(device_id="DEVICE-A")["lifecycle_state"] == "CONTAINED"

    # 2. Feed 3 normal windows for Device A (streak 3 -> RECOVERING)
    for s in range(1, 4):
        runtime.ingest(generate_window("normal", intensity=1, sequence=s, device_id="DEVICE-A"))

    inc_rec = runtime.store.find_active_incident(device_id="DEVICE-A")
    assert inc_rec["lifecycle_state"] == "RECOVERING"
    # In RECOVERING, policy enforcer marks it as under recovery trial
    assert "DEVICE-A" in runtime.response.enforcer.active_isolates
    assert runtime.response.enforcer.active_isolates["DEVICE-A"]["state"] == "RECOVERING"

    # 3. Feed 2 more normal windows for Device A (streak 5 -> RESOLVED)
    for s in range(4, 6):
        runtime.ingest(generate_window("normal", intensity=1, sequence=s, device_id="DEVICE-A"))

    # Active incident should now be None (resolved)
    assert runtime.store.find_active_incident(device_id="DEVICE-A") is None
    resolved_inc = [i for i in runtime.store.incidents(state="RESOLVED") if i["device_id"] == "DEVICE-A"]
    assert len(resolved_inc) == 1
    assert resolved_inc[0]["recovery_state"] == "VERIFIED"

    # In-process mitigation must be released
    assert "DEVICE-A" not in runtime.response.enforcer.active_isolates
    assert "DEVICE-A" not in runtime.response.simulated_isolates
    assert "DEVICE-A" not in runtime._device_normal_streaks


def test_d_two_devices_independent_recovery_isolation(runtime_app):
    """Test D: Two devices have independent active incidents; recovery of Device A does NOT release Device B."""
    runtime, _ = runtime_app

    # 1. Both Device A and Device B attack and get contained
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id="DEVICE-A"))
    runtime.ingest(generate_window("syn_flood", intensity=4, sequence=0, device_id="DEVICE-B"))

    assert "DEVICE-A" in runtime.response.enforcer.active_isolates
    assert "DEVICE-B" in runtime.response.enforcer.active_isolates

    # 2. Device A undergoes full 5-window recovery
    for s in range(1, 6):
        runtime.ingest(generate_window("normal", intensity=1, sequence=s, device_id="DEVICE-A"))

    # 3. Assertions: Device A is resolved and released
    assert runtime.store.find_active_incident(device_id="DEVICE-A") is None
    assert "DEVICE-A" not in runtime.response.enforcer.active_isolates

    # 4. Assertions: Device B is STILL CONTAINED and STILL ISOLATED!
    inc_b = runtime.store.find_active_incident(device_id="DEVICE-B")
    assert inc_b is not None
    assert inc_b["lifecycle_state"] == "CONTAINED"
    assert "DEVICE-B" in runtime.response.enforcer.active_isolates
    assert runtime._device_normal_streaks["DEVICE-B"] == 0


def test_e_concurrent_multi_device_ingestion_recovery_streaks(runtime_app):
    """Test E: Concurrent multi-threaded ingestion from multiple devices does not corrupt per-device streaks."""
    runtime, _ = runtime_app
    devices = [f"SENSOR-CONCURR-0{i}" for i in range(1, 5)]
    barrier = threading.Barrier(len(devices))
    errors: list[Exception] = []

    def ingest_device(dev_id: str):
        try:
            barrier.wait()
            for s in range(10):
                ev = generate_window("normal", intensity=1, sequence=s, device_id=dev_id)
                runtime.ingest(ev)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=ingest_device, args=(dev,)) for dev in devices]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(errors) == 0, f"Thread errors encountered: {errors}"
    for dev in devices:
        # Since these sensors had no active incidents, their streaks incremented cleanly to 10
        assert runtime._device_normal_streaks[dev] == 10


def test_f_concurrent_attack_events_same_device_no_duplicate_incidents(runtime_app):
    """Test F: Concurrent attack events for the same device do not create duplicate active incidents in SQLite."""
    runtime, _ = runtime_app
    dev_id = "ATK-CONCURR-SAME"
    num_threads = 10
    barrier = threading.Barrier(num_threads)
    errors: list[Exception] = []

    def ingest_attack(seq: int):
        try:
            barrier.wait()
            ev = generate_window("udp_flood", intensity=4, sequence=seq, device_id=dev_id)
            runtime.ingest(ev)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=ingest_attack, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(errors) == 0, f"Thread errors encountered: {errors}"

    # Query all incidents for this device
    all_incidents = [i for i in runtime.store.incidents(limit=50) if i["device_id"] == dev_id]
    # There MUST be exactly 1 incident created; the other 9 events must have been correlated or filtered
    active_inc = runtime.store.find_active_incident(device_id=dev_id)
    assert active_inc is not None
    assert len(all_incidents) == 1, f"Expected exactly 1 incident, found {len(all_incidents)}: {all_incidents}"


def test_g_contained_device_active_attack_cannot_accidentally_release(runtime_app):
    """Test G: Contained device active attack cannot qualify for recovery or accidentally release mitigation."""
    runtime, _ = runtime_app
    dev_id = "ATK-ACCIDENT-CHECK"

    # 1. Device attacks and gets contained
    runtime.ingest(generate_window("udp_flood", intensity=4, sequence=0, device_id=dev_id))
    assert dev_id in runtime.response.enforcer.active_isolates

    # 2. While contained, attacker attempts heavy flood (rate > 30 pps)
    flood_ev = generate_window("udp_flood", intensity=4, sequence=1, device_id=dev_id)
    res_flood = runtime.ingest(flood_ev)
    assert res_flood["mitigation_enforced"] is True
    assert res_flood["response"]["result"] == "SOFTWARE_INTERCEPT"
    assert runtime._device_normal_streaks[dev_id] == 0
    assert dev_id in runtime.response.enforcer.active_isolates

    # 3. Attacker attempts low-rate attack that still carries attack profile (e.g. SYN flood or slow rate)
    syn_ev = generate_window("syn_flood", intensity=1, sequence=2, device_id=dev_id)
    res_syn = runtime.ingest(syn_ev)
    # SYN flag is blocked at policy boundary or detected as attack
    assert runtime._device_normal_streaks[dev_id] == 0
    assert dev_id in runtime.response.enforcer.active_isolates

    # Active incident is still active and CONTAINED
    inc = runtime.store.find_active_incident(device_id=dev_id)
    assert inc is not None
    assert inc["lifecycle_state"] == "CONTAINED"


def test_h_recovery_observation_gate_independent_of_attack_type_metadata(runtime_app):
    """Test H: Presence of attack_type metadata alone cannot change the recovery observation policy decision.

    Compares equivalent events with attack_type=None and attack_type="udp_flood",
    with identical packet_rate <= 30 and no SYN flag, verifying that policy behavior is identical.
    """
    runtime, _ = runtime_app
    enforcer = runtime.response.enforcer
    dev_id = "DEV-OBSERVE-TEST"

    # Isolate device into CONTAINED
    enforcer.isolate(dev_id, action="ISOLATE", reason="Containment test", state="CONTAINED")

    ts = utc_now()
    # Event 1: attack_type is None
    ev_none = TelemetryEvent(
        device_id=dev_id,
        timestamp=ts,
        packet_count=15,
        packet_rate=15.0,
        protocol="UDP",
        attack_type=None,
    )

    # Event 2: identical observable wire properties, but attack_type is set to "udp_flood"
    ev_attack = TelemetryEvent(
        device_id=dev_id,
        timestamp=ts,
        packet_count=15,
        packet_rate=15.0,
        protocol="UDP",
        attack_type="udp_flood",
    )

    dec_none = enforcer.evaluate(dev_id, ev_none)
    dec_attack = enforcer.evaluate(dev_id, ev_attack)

    # Policy must evaluate observable properties identically regardless of attack_type metadata
    assert dec_none.action == dec_attack.action == "ALLOW"
    assert dec_none.drop == dec_attack.drop is False
    assert dec_none.metadata.get("recovery_observation") is True
    assert dec_attack.metadata.get("recovery_observation") is True

    # Also verify high-rate traffic (> 30 pps) is dropped identically regardless of attack_type
    ev_flood_none = TelemetryEvent(
        device_id=dev_id,
        timestamp=ts,
        packet_count=50,
        packet_rate=50.0,
        protocol="UDP",
        attack_type=None,
    )
    ev_flood_attack = TelemetryEvent(
        device_id=dev_id,
        timestamp=ts,
        packet_count=50,
        packet_rate=50.0,
        protocol="UDP",
        attack_type="udp_flood",
    )

    dec_flood_none = enforcer.evaluate(dev_id, ev_flood_none)
    dec_flood_attack = enforcer.evaluate(dev_id, ev_flood_attack)

    assert dec_flood_none.action == dec_flood_attack.action == "DROP"
    assert dec_flood_none.drop == dec_flood_attack.drop is True
