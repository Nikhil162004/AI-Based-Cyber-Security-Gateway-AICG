"""Tests for the upgraded six-attacker DDoS topology and dynamic simulation synchronization."""

from pathlib import Path
import pytest
from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window


@pytest.fixture
def runtime_app(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_topology.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


def _login(client, username="admin", password="Admin@AICG2026!", mfa="123456"):
    res = client.post("/api/auth/login", json={
        "username": username,
        "password": password,
        "mfa_code": mfa,
    })
    assert res.status_code == 200
    return res


def test_topology_six_attacker_data_structure(runtime_app):
    """Verify that /api/topology exposes 4 OT nodes, 6 DDoS attacker sources, and 9 converging links."""
    runtime, app = runtime_app
    with app.test_client() as client:
        _login(client)
        res = client.get("/api/topology")
        assert res.status_code == 200
        data = res.get_json()

        # 1. Counts validation
        counts = data.get("counts", {})
        assert counts.get("ot_nodes") == 4
        assert counts.get("ddos_sources") == 6
        assert counts.get("total_nodes") == 10
        assert counts.get("links") == 9

        # 2. Legitimate OT nodes (4)
        sensors = data.get("sensors", [])
        assert len(sensors) == 2
        sensor_ids = {s["id"] for s in sensors}
        assert sensor_ids == {"SENSOR-01", "SENSOR-02"}
        assert sensors[0]["ip"] == "10.42.0.11"
        assert sensors[1]["ip"] == "10.42.0.12"
        assert all(s["authorization"] == "AUTHORIZED" for s in sensors)

        gateway = data.get("gateway", {})
        assert gateway["id"] == "EDGE-GW-01"
        assert gateway["ip"] == "10.42.0.1"

        ot_servers = data.get("ot_servers", [])
        assert len(ot_servers) == 1
        assert ot_servers[0]["id"] == "PLC-SINK"
        assert ot_servers[0]["ip"] == "10.42.0.10"

        # 3. DDoS attacker sources (6)
        attack_nodes = data.get("attack_nodes", [])
        assert len(attack_nodes) == 6
        expected_attackers = [
            ("ATTACKER-01", "10.42.0.250", "udp_flood"),
            ("ATTACKER-02", "10.42.0.251", "syn_flood"),
            ("ATTACKER-03", "10.42.0.252", "icmp_flood"),
            ("ATTACKER-04", "10.42.0.253", "coap_anomaly"),
            ("ATTACKER-05", "10.42.0.254", "slow_rate"),
            ("ATTACKER-06", "10.42.0.249", "modbus_anomaly"),
        ]

        seen_ips = set()
        seen_ids = set()
        for idx, (exp_id, exp_ip, exp_vec) in enumerate(expected_attackers):
            node = attack_nodes[idx]
            assert node["id"] == exp_id
            assert node["ip"] == exp_ip
            assert node["vector"] == exp_vec
            assert node["authorization"] == "DENIED"
            assert node["simulation_only"] is True
            assert "role" in node and len(node["role"]) > 0
            assert "traffic_indicator" in node
            seen_ips.add(node["ip"])
            seen_ids.add(node["id"])

        # All 6 IPs and IDs must be strictly unique
        assert len(seen_ips) == 6
        assert len(seen_ids) == 6

        # 4. Network Connectivity: all 6 attack links converge on EDGE-GW-01
        links = data.get("links", [])
        assert len(links) == 9

        legit_links = [l for l in links if l.get("type") in {"legitimate", "ot"}]
        assert len(legit_links) == 3
        assert any(l["source"] == "SENSOR-01" and l["target"] == "EDGE-GW-01" for l in legit_links)
        assert any(l["source"] == "SENSOR-02" and l["target"] == "EDGE-GW-01" for l in legit_links)
        assert any(l["source"] == "EDGE-GW-01" and l["target"] == "PLC-SINK" for l in legit_links)

        attack_links = [l for l in links if l.get("type") == "attack"]
        assert len(attack_links) == 6
        for l in attack_links:
            assert l["target"] == "EDGE-GW-01"
            assert l["source"] in seen_ids

        # 5. Total visible nodes list
        nodes = data.get("nodes", [])
        assert len(nodes) == 10
        node_ids = {n["id"] for n in nodes}
        assert node_ids == {"SENSOR-01", "SENSOR-02", "EDGE-GW-01", "PLC-SINK"} | seen_ids


def test_topology_normal_baseline_state(runtime_app):
    """Verify that in State 1 (Normal Baseline), all 6 attacker nodes are IDLE and dimmed."""
    runtime, app = runtime_app
    with app.test_client() as client:
        _login(client)
        res = client.get("/api/topology")
        assert res.status_code == 200
        data = res.get_json()

        for a in data["attack_nodes"]:
            assert a["status"] == "IDLE"
            assert a["active"] is False
            assert a["mitigated"] is False
            assert a["packet_rate"] == 0.0
            assert "IDLE" in a["traffic_indicator"]

        assert data["gateway"]["status"] == "ONLINE"


def test_topology_ddos_attack_state(runtime_app):
    """Verify that in State 2 (DDoS Attack Active), attacker sources are marked active with traffic rates."""
    runtime, app = runtime_app
    with app.test_client() as client:
        _login(client)

        # Start multi-source DDoS attack at intensity 6 (all 6 nodes participate)
        sim = runtime.start_simulation("udp_flood", intensity=6)
        assert sim["state"] == "RUNNING"

        try:
            res = client.get("/api/topology")
            assert res.status_code == 200
            data = res.get_json()

            # Under intensity 6 simulation, all 6 sources represent active DDoS botnet
            active_attackers = [a for a in data["attack_nodes"] if a["active"]]
            assert len(active_attackers) == 6
            for a in active_attackers:
                assert a["status"] == "ATTACKING"
                assert a["packet_rate"] > 0
                assert "ACTIVE" in a["traffic_indicator"]

            # Gateway is on alert
            assert data["gateway"]["status"] == "ALERT"

        finally:
            runtime.stop_simulation("udp_flood")

        # After stop, traffic stops (active is False)
        res_after = client.get("/api/topology")
        data_after = res_after.get_json()
        assert all(a["active"] is False for a in data_after["attack_nodes"])

        # Reset simulation back to clean baseline
        res_reset = client.post("/api/simulations/reset")
        assert res_reset.status_code == 200

        # After baseline reset, all attackers return to IDLE
        res_clean = client.get("/api/topology")
        data_clean = res_clean.get_json()
        assert all(a["status"] == "IDLE" for a in data_clean["attack_nodes"])
        assert all(a["active"] is False for a in data_clean["attack_nodes"])
        assert all(a["mitigated"] is False for a in data_clean["attack_nodes"])
        assert data_clean["gateway"]["status"] == "ONLINE"


def test_topology_mitigation_active_state(runtime_app):
    """Verify that in State 3 (Mitigation Active), isolated attacker nodes indicate CONTAINED / BLOCKED."""
    runtime, app = runtime_app
    with app.test_client() as client:
        _login(client)

        # Ingest an attack from ATTACKER-01 / ATK-01
        ev = generate_window("udp_flood", intensity=4, sequence=0, device_id="ATK-01")
        runtime.ingest(ev)

        # Contain/isolate the attacker
        runtime.response.isolate("ATK-01", "ISOLATE", "Threat isolation", state="CONTAINED")

        res = client.get("/api/topology")
        assert res.status_code == 200
        data = res.get_json()

        # ATTACKER-01 (aliased to ATK-01) must reflect mitigation
        atk1 = next(a for a in data["attack_nodes"] if a["id"] == "ATTACKER-01")
        assert atk1["mitigated"] is True
        assert atk1["status"] == "CONTAINED"
        assert atk1["active"] is False
        assert "BLOCKED" in atk1["traffic_indicator"]

        # Gateway shows active defense shield
        assert data["gateway"]["status"] == "SHIELD_ACTIVE"


def test_attacker_ip_address_validity_and_broadcast(runtime_app):
    """Verify IP addresses are valid unicast hosts on 10.42.0.0/24 and 10.42.0.255 is NOT used."""
    import ipaddress
    runtime, app = runtime_app
    with app.test_client() as client:
        _login(client)
        res = client.get("/api/topology")
        assert res.status_code == 200
        data = res.get_json()

        subnet = ipaddress.IPv4Network("10.42.0.0/24")
        assert subnet.netmask == ipaddress.IPv4Address("255.255.255.0")
        assert subnet.broadcast_address == ipaddress.IPv4Address("10.42.0.255")

        attacker_nodes = data["attack_nodes"]
        assert len(attacker_nodes) == 6

        attacker_ips = [a["ip"] for a in attacker_nodes]

        # 1. Verify 10.42.0.255 is NOT assigned to any attacker (it's the subnet broadcast address)
        assert "10.42.0.255" not in attacker_ips, "10.42.0.255 is a broadcast address and cannot be assigned to an attacker host"

        # 2. Verify 10.42.0.0 is NOT assigned to any attacker (it's the network address)
        assert "10.42.0.0" not in attacker_ips

        # 3. Verify all 6 IPs are valid, usable unicast host IPs in 10.42.0.0/24
        for ip_str in attacker_ips:
            addr = ipaddress.IPv4Address(ip_str)
            assert addr in subnet.hosts(), f"{ip_str} is not a valid host IP in {subnet}"

        # 4. Verify all 6 IPs are unique
        assert len(set(attacker_ips)) == 6

        # 5. Verify no conflict with legitimate OT devices
        ot_ips = {s["ip"] for s in data["sensors"]} | {data["gateway"]["ip"]} | {s["ip"] for s in data["ot_servers"]}
        assert set(attacker_ips).isdisjoint(ot_ips)


def test_independent_attacker_source_telemetry():
    """Verify that six independent logical sources generate separately identifiable traffic records."""
    expected_mapping = [
        ("ATTACKER-01", "ATTACKER-01-SIM", "10.42.0.250"),
        ("ATTACKER-02", "ATTACKER-02-SIM", "10.42.0.251"),
        ("ATTACKER-03", "ATTACKER-03-SIM", "10.42.0.252"),
        ("ATTACKER-04", "ATTACKER-04-SIM", "10.42.0.253"),
        ("ATTACKER-05", "ATTACKER-05-SIM", "10.42.0.254"),
        ("ATTACKER-06", "ATTACKER-06-SIM", "10.42.0.249"),
    ]

    seen_dev_ids = set()
    seen_source_ids = set()
    seen_src_ips = set()

    for dev_id, exp_source_id, exp_src_ip in expected_mapping:
        event = generate_window("udp_flood", intensity=3, sequence=1, device_id=dev_id)
        assert event.device_id == dev_id
        assert event.source_id == exp_source_id
        assert event.src_ip == exp_src_ip
        assert event.packet_count > 0
        assert event.packet_rate > 0
        assert event.byte_count > 0
        assert event.byte_rate > 0

        seen_dev_ids.add(event.device_id)
        seen_source_ids.add(event.source_id)
        seen_src_ips.add(event.src_ip)

    assert len(seen_dev_ids) == 6
    assert len(seen_source_ids) == 6
    assert len(seen_src_ips) == 6


def test_simulation_intensity_scaling_levels_1_through_6(runtime_app):
    """Verify simulation intensity levels 1 through 6 scale the number of participating attacker sources 1:1."""
    runtime, app = runtime_app
    with app.test_client() as client:
        _login(client)

        for intensity in range(1, 7):
            sim = runtime.start_simulation("udp_flood", intensity=intensity)
            assert sim["state"] == "RUNNING"
            try:
                res = client.get("/api/topology")
                assert res.status_code == 200
                data = res.get_json()

                active_nodes = [a for a in data["attack_nodes"] if a["active"]]
                assert len(active_nodes) == intensity, (
                    f"Configured intensity {intensity} must have exactly {intensity} "
                    f"participating attacker sources, but got {len(active_nodes)}"
                )

                # Verify participating sources are the first 'intensity' nodes
                for k in range(intensity):
                    assert data["attack_nodes"][k]["active"] is True
                    assert data["attack_nodes"][k]["status"] == "ATTACKING"
                    assert data["attack_nodes"][k]["packet_rate"] > 0
                for k in range(intensity, 6):
                    assert data["attack_nodes"][k]["active"] is False
                    assert data["attack_nodes"][k]["status"] == "IDLE"
                    assert data["attack_nodes"][k]["packet_rate"] == 0.0

            finally:
                runtime.stop_simulation("udp_flood")
                # Reset simulation back to clean baseline between runs
                client.post("/api/simulations/reset")


def test_individual_attacker_mitigation_synchronization(runtime_app):
    """Verify that containment and mitigation indicators reflect actual backend enforcer isolation events."""
    runtime, app = runtime_app
    with app.test_client() as client:
        _login(client)

        # Baseline: none are mitigated
        res = client.get("/api/topology")
        assert all(a["mitigated"] is False for a in res.get_json()["attack_nodes"])

        # Isolate ATTACKER-03 specifically in the backend policy enforcer
        runtime.response.isolate("ATTACKER-03", "ISOLATE", "Specific Bot Containment", state="CONTAINED")

        res_iso = client.get("/api/topology")
        data_iso = res_iso.get_json()

        atk3 = next(a for a in data_iso["attack_nodes"] if a["id"] == "ATTACKER-03")
        assert atk3["mitigated"] is True
        assert atk3["status"] == "CONTAINED"
        assert atk3["traffic_indicator"] == "BLOCKED (0.0 pps)"

        # Other attackers are not isolated
        other_atks = [a for a in data_iso["attack_nodes"] if a["id"] != "ATTACKER-03"]
        assert all(a["mitigated"] is False for a in other_atks)

        # Release ATTACKER-03
        runtime.response.release("ATTACKER-03")
        res_rel = client.get("/api/topology")
        atk3_rel = next(a for a in res_rel.get_json()["attack_nodes"] if a["id"] == "ATTACKER-03")
        assert atk3_rel["mitigated"] is False
        assert atk3_rel["status"] == "IDLE"

