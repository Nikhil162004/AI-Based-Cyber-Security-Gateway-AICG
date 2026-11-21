"""Tests for NS-3, Cooja, and PCAP evidence adapters."""

import os
from pathlib import Path
import socket
import sys
import pytest

import dpkt

from aegis_gateway.adapters import cooja_csv_events, ns3_csv_events, pcap_events, pcap_window_events
from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.schema import utc_now
from aegis_gateway.security import ROLE_ADMIN


def test_ns3_window_csv_adapter():
    csv_file = Path("dataset/ns3_low_v1_features.csv")
    if not csv_file.exists():
        pytest.skip(f"Test file not found: {csv_file}")

    events = list(ns3_csv_events(csv_file))
    assert len(events) > 0
    first = events[0]
    assert first.source_type == "NS3"
    assert first.provenance == "SIMULATED"
    assert first.packet_count is not None
    assert first.packet_rate is not None
    assert first.packet_rate > 0
    assert first.label in ("NORMAL", "ATTACK")


def test_ns3_packet_trace_csv_adapter():
    csv_file = Path("dataset/ns3_normal_traffic.csv")
    if not csv_file.exists():
        pytest.skip(f"Test file not found: {csv_file}")

    events = list(ns3_csv_events(csv_file))
    assert len(events) > 0
    first = events[0]
    assert first.source_type == "NS3"
    assert first.provenance == "SIMULATED"
    assert first.packet_count > 0
    assert first.src_ip is not None
    assert first.dst_ip is not None
    assert first.protocol == "UDP"


def test_cooja_csv_adapter():
    default_csv = Path(__file__).resolve().parent.parent / "dataset" / "cooja_ml_ready_v1.csv"
    env_path = os.getenv("AEGIS_COOJA_CSV")
    csv_file = Path(env_path) if env_path else (default_csv if default_csv.exists() else Path("/home/kali/contiki-ng/examples/ai_edge_iiot/data/cooja_ml_ready_v1.csv"))
    if not csv_file.exists():
        pytest.skip(f"Contiki-NG file not found: {csv_file}")

    events = list(cooja_csv_events(csv_file))
    assert len(events) > 0
    first = events[0]
    assert first.source_type == "COOJA"
    assert first.provenance == "SIMULATED"
    assert first.protocol == "IEEE_802_15_4_6LOWPAN"
    assert first.device_id.startswith("COOJA-")
    assert first.packet_rate is not None


def test_pcap_replay_packet_adapter():
    pcap_file = Path("dataset/ns3_normal_sensor_1-0-0.pcap")
    if not pcap_file.exists():
        pytest.skip(f"PCAP file not found: {pcap_file}")

    events = list(pcap_events(pcap_file))
    assert len(events) > 0
    first = events[0]
    assert first.source_type == "PCAP_REPLAY"
    assert first.provenance == "REPLAYED"
    assert first.packet_count == 1
    assert first.byte_count > 0
    assert first.protocol == "UDP"


def test_pcap_replay_window_adapter():
    pcap_file = Path("dataset/ns3_normal_sensor_1-0-0.pcap")
    if not pcap_file.exists():
        pytest.skip(f"PCAP file not found: {pcap_file}")

    events = list(pcap_window_events(pcap_file, window_seconds=1.0))
    assert len(events) > 0
    first = events[0]
    assert first.source_type == "PCAP_REPLAY"
    assert first.provenance == "REPLAYED"
    assert first.packet_count >= 1
    assert first.packet_rate >= 1.0


def test_dpkt_tcp_udp_icmp_synthetic_parsing(tmp_path: Path):
    """Verify dpkt parser correctly decodes TCP (with flags), UDP, and ICMP frames."""
    pcap_path = tmp_path / "multi_protocol.pcap"
    with open(pcap_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)

        # 1. TCP frame with SYN flag
        tcp = dpkt.tcp.TCP(sport=4433, dport=8080, flags=dpkt.tcp.TH_SYN, data=b"tcp-payload")
        ip_tcp = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.50"),
            dst=socket.inet_aton("192.168.1.1"),
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp,
        )
        ip_tcp.len = len(ip_tcp)
        eth_tcp = dpkt.ethernet.Ethernet(
            src=b"\x00" * 6, dst=b"\x00" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_tcp
        )
        writer.writepkt(eth_tcp, ts=10.0)

        # 2. UDP frame
        udp = dpkt.udp.UDP(sport=5353, dport=53, data=b"udp-query")
        ip_udp = dpkt.ip.IP(
            src=socket.inet_aton("10.0.0.2"),
            dst=socket.inet_aton("10.0.0.1"),
            p=dpkt.ip.IP_PROTO_UDP,
            data=udp,
        )
        ip_udp.len = len(ip_udp)
        eth_udp = dpkt.ethernet.Ethernet(
            src=b"\x00" * 6, dst=b"\x00" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_udp
        )
        writer.writepkt(eth_udp, ts=10.5)

        # 3. ICMP frame (Echo Request)
        icmp = dpkt.icmp.ICMP(type=8, code=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
        ip_icmp = dpkt.ip.IP(
            src=socket.inet_aton("172.16.0.4"),
            dst=socket.inet_aton("172.16.0.1"),
            p=dpkt.ip.IP_PROTO_ICMP,
            data=icmp,
        )
        ip_icmp.len = len(ip_icmp)
        eth_icmp = dpkt.ethernet.Ethernet(
            src=b"\x00" * 6, dst=b"\x00" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_icmp
        )
        writer.writepkt(eth_icmp, ts=11.2)

    events = list(pcap_events(pcap_path))
    assert len(events) == 3

    # Packet 1: TCP
    assert events[0].protocol == "TCP"
    assert events[0].src_ip == "192.168.1.50"
    assert events[0].dst_ip == "192.168.1.1"
    assert events[0].src_port == 4433
    assert events[0].dst_port == 8080
    assert events[0].tcp_flags == "S"

    # Packet 2: UDP
    assert events[1].protocol == "UDP"
    assert events[1].src_ip == "10.0.0.2"
    assert events[1].dst_ip == "10.0.0.1"
    assert events[1].src_port == 5353
    assert events[1].dst_port == 53

    # Packet 3: ICMP
    assert events[2].protocol == "ICMP"
    assert events[2].src_ip == "172.16.0.4"
    assert events[2].dst_ip == "172.16.0.1"
    assert events[2].icmp_type == "8"


def test_dpkt_error_handling_empty_and_corrupted(tmp_path: Path):
    """Verify empty and invalid PCAP files raise ValueError."""
    # Empty file
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(b"")
    with pytest.raises(ValueError, match="Empty PCAP file"):
        list(pcap_events(empty_pcap))

    # Corrupted / invalid file
    corrupt_pcap = tmp_path / "corrupt.pcap"
    corrupt_pcap.write_bytes(b"NOT_A_VALID_PCAP_HEADER_DATA_1234567890")
    with pytest.raises(ValueError, match="Invalid or corrupted PCAP"):
        list(pcap_events(corrupt_pcap))

    # Non-existent file
    nonexistent = tmp_path / "does_not_exist.pcap"
    with pytest.raises(FileNotFoundError):
        list(pcap_events(nonexistent))


def test_dpkt_windowing_timestamp_grouping(tmp_path: Path):
    """Verify window aggregation correctly groups packets across sliding time buckets."""
    pcap_path = tmp_path / "window_test.pcap"
    with open(pcap_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        # Bucket 0: ts 1.0, 1.2, 1.8 (3 packets)
        for ts in [1.0, 1.2, 1.8]:
            udp = dpkt.udp.UDP(sport=1000, dport=2000, data=b"b0")
            ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("10.0.0.2"), p=17, data=udp)
            ip.len = len(ip)
            eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
            writer.writepkt(eth, ts=ts)
        # Bucket 1: ts 2.1, 2.5 (2 packets)
        for ts in [2.1, 2.5]:
            udp = dpkt.udp.UDP(sport=1000, dport=2000, data=b"b1")
            ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("10.0.0.2"), p=17, data=udp)
            ip.len = len(ip)
            eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
            writer.writepkt(eth, ts=ts)

    windows = list(pcap_window_events(pcap_path, window_seconds=1.0))
    assert len(windows) == 2
    assert windows[0].flow_id == "pcap-win-0"
    assert windows[0].packet_count == 3
    assert windows[0].packet_rate == 3.0
    assert windows[1].flow_id == "pcap-win-1"
    assert windows[1].packet_count == 2
    assert windows[1].packet_rate == 2.0


def test_scapy_not_imported_in_runtime():
    """Verify that scapy is never imported by the gateway runtime or adapters."""
    # Ensure scapy is not in sys.modules
    assert "scapy" not in sys.modules, "scapy should not be imported in sys.modules"


def test_pcap_replay_api_endpoint(tmp_path: Path):
    """Verify POST /api/pcap/replay successfully replays PCAP and returns expected schema."""
    pcap_file = Path("dataset/ns3_normal_sensor_1-0-0.pcap")
    if not pcap_file.exists():
        pytest.skip(f"PCAP fixture not found: {pcap_file}")

    settings = Settings(database_path=tmp_path / "replay_api_test.sqlite3")
    runtime = GatewayRuntime(settings=settings)
    app = create_app(runtime)
    app.config["TESTING"] = True

    with app.test_client() as client:
        # Simulate authenticated admin session
        with client.session_transaction() as sess:
            sess["user"] = {
                "user_id": "USR-ADMIN",
                "username": "admin",
                "role": ROLE_ADMIN,
                "authenticated": True,
                "mfa_verified": True,
                "login_time": utc_now(),
            }

        response = client.post(
            "/api/pcap/replay",
            json={"path": str(pcap_file), "windowed": True},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["provenance"] == "REPLAYED"
        assert data["transmitted"] is False
        assert data["replayed"] > 0
        assert "ns3_normal_sensor_1-0-0.pcap" in data["source"]
