"""Tests for NS-3, Cooja, and PCAP evidence adapters."""

import os
from pathlib import Path
import pytest
from aegis_gateway.adapters import cooja_csv_events, ns3_csv_events, pcap_events, pcap_window_events


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
