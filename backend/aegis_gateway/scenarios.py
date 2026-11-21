"""Safe, local traffic-window profiles.  They never transmit network packets."""

from __future__ import annotations

from dataclasses import dataclass
from random import Random
from typing import Any

from .schema import Provenance, TelemetryEvent, utc_now


@dataclass(frozen=True)
class AttackScenario:
    scenario_id: str
    name: str
    description: str
    severity: str
    protocol: str
    traffic_profile: str
    expected_indicators: tuple[str, ...]
    expected_resource_impact: str
    intensity_range: tuple[int, int]

    def public(self) -> dict[str, Any]:
        return {**self.__dict__, "expected_indicators": list(self.expected_indicators), "provenance": "SIMULATED", "safe": True}


_CATALOGUE = [
    AttackScenario("normal", "Normal IIoT rhythm", "Baseline sensor telemetry profile.", "INFO", "MQTT", "periodic", ("steady packet rate",), "normal CPU/radio", (1, 1)),
    AttackScenario("udp_flood", "UDP flood", "Controlled UDP-window exhaustion profile; no packets leave the process.", "HIGH", "UDP", "sustained", ("high packet rate", "UDP dominance", "source expansion"), "high RX/CPU", (3, 5)),
    AttackScenario("syn_flood", "SYN flood", "Controlled TCP SYN-heavy profile.", "HIGH", "TCP", "sustained", ("SYN ratio", "flow expansion"), "connection pressure", (3, 5)),
    AttackScenario("icmp_flood", "ICMP flood", "Controlled ICMP-heavy profile.", "HIGH", "ICMP", "sustained", ("ICMP dominance", "packet rate"), "RX/CPU increase", (3, 5)),
    AttackScenario("burst_exhaustion", "Burst traffic exhaustion", "Short high-intensity modeled burst.", "HIGH", "UDP", "burst", ("rate spike", "byte spike"), "radio/CPU spike", (4, 6)),
    AttackScenario("slow_rate", "Slow-rate resource exhaustion", "Low-rate persistent modeled connection pressure.", "MEDIUM", "TCP", "slow", ("long-lived flows", "SYN pressure"), "memory/connection pressure", (2, 3)),
    AttackScenario("coap_anomaly", "CoAP-style anomaly", "SIMULATED PROTOCOL PROFILE; no CoAP parser is asserted.", "MEDIUM", "UDP", "coap-style", ("UDP port 5683", "request-rate change"), "radio RX increase", (2, 4)),
    AttackScenario("mqtt_anomaly", "MQTT/MQTT-SN-style anomaly", "SIMULATED PROTOCOL PROFILE; no broker is required.", "MEDIUM", "TCP", "mqtt-style", ("port 1883", "publish-like burst"), "CPU/network increase", (2, 4)),
    AttackScenario("rpl_anomaly", "RPL/6LoWPAN-style anomaly", "SIMULATED CONTROL-PLANE PROFILE; no RPL decoder is asserted.", "HIGH", "ICMPV6", "rpl-style", ("control traffic ratio", "radio RX"), "radio/control overhead", (3, 5)),
    AttackScenario("modbus_anomaly", "Modbus-style anomaly", "SIMULATED PROTOCOL PROFILE; no Modbus payload parser is asserted.", "HIGH", "TCP", "modbus-style", ("port 502", "flow/rate change"), "PLC-facing connection pressure", (3, 5)),
    AttackScenario("mixed_vector", "Mixed multi-vector anomaly", "Combined safe profile across UDP, TCP, and ICMP.", "CRITICAL", "MIXED", "mixed", ("protocol mix shift", "packet and flow spike"), "CPU/radio/memory increase", (4, 6)),
]
CATALOGUE = {scenario.scenario_id: scenario for scenario in _CATALOGUE}


_ATTACKER_IPS: dict[str, str] = {
    "ATK-01": "10.42.0.250",
    "ATTACKER-01": "10.42.0.250",
    "ATTACKER-02": "10.42.0.251",
    "ATTACKER-03": "10.42.0.252",
    "ATTACKER-04": "10.42.0.253",
    "ATTACKER-05": "10.42.0.254",
    "ATTACKER-06": "10.42.0.249",
}


def catalogue() -> list[dict[str, Any]]:
    return [scenario.public() for scenario in _CATALOGUE]


def generate_window(scenario_id: str, intensity: int = 3, sequence: int = 0, seed: int = 7, provenance: str = Provenance.SIMULATED.value, source_type: str = "ATTACK_SIMULATOR", device_id: str | None = None) -> TelemetryEvent:
    """Generate one window of *modelled* attack/normal behavior, never traffic."""
    if scenario_id not in CATALOGUE:
        raise KeyError(f"Unknown scenario: {scenario_id}")
    scenario = CATALOGUE[scenario_id]
    rng = Random(f"{seed}:{scenario_id}:{sequence}")
    intensity = max(1, min(intensity, 6))
    normal = scenario_id == "normal"
    if normal:
        base = 14.0 + (intensity % 4) * 2.5
        rate = max(4.0, base + rng.uniform(-2.5, 2.5))
    elif scenario_id == "slow_rate":
        rate = 25 + intensity * 8 + rng.uniform(-3, 4)
    elif scenario_id == "burst_exhaustion":
        base_rate = 30 * intensity ** 2 + rng.uniform(-8, 20)
        rate = base_rate * 1.8 if sequence % 3 == 0 else base_rate * .65
    else:
        rate = 30 * intensity ** 2 + rng.uniform(-8, 20)
    packet_count = max(1, round(rate))
    if scenario_id in {"coap_anomaly", "udp_flood", "burst_exhaustion"}: packet_size = rng.uniform(70, 240)
    elif scenario_id == "modbus_anomaly": packet_size = rng.uniform(90, 280)
    else: packet_size = rng.uniform(120, 800)
    protocol = "UDP" if normal else scenario.protocol
    if protocol == "MIXED": protocol = ("UDP", "TCP", "ICMP")[sequence % 3]
    src_count = (1 + (sequence % 3)) if normal else max(1, min(20, intensity * 2 + rng.randint(0, 3)))
    dst_port = {"UDP": 5683, "TCP": 1883, "ICMP": None, "ICMPV6": None}.get(protocol, 9000)
    if scenario_id == "modbus_anomaly": dst_port = 502
    flags = "S" if scenario_id in {"syn_flood", "slow_rate"} else None
    sensor_idx = 1 + (sequence % 3)
    dev_id = device_id if device_id is not None else ("ATK-01" if not normal else f"SENSOR-0{sensor_idx}")
    flow_id = f"{scenario_id}-{sequence}"
    ts = utc_now()
    token = None
    if normal and (dev_id.startswith("SENSOR-") or dev_id == "operator"):
        from .iam import compute_device_token
        token = compute_device_token(dev_id, ts, flow_id)

    src_id = (
        ("ATK-SIM-01" if not normal else f"SENSOR-NODE-0{sensor_idx}")
        if device_id is None
        else (f"{dev_id}-SIM" if not normal else f"{dev_id}-NODE")
    )
    if not normal:
        src_ip = _ATTACKER_IPS.get(dev_id, "10.42.0.250")
    else:
        src_ip = _ATTACKER_IPS.get(dev_id) or (f"10.42.0.{10 + sensor_idx}" if dev_id.startswith("SENSOR-") else "10.42.0.10")

    return TelemetryEvent(
        source_type=source_type, source_id=src_id,
        device_id=dev_id,
        timestamp=ts,
        src_ip=src_ip,
        dst_ip="10.42.0.1", src_port=40000 + sequence % 1000, dst_port=dst_port, protocol=protocol,
        protocol_layer="TRANSPORT", packet_count=packet_count, byte_count=round(packet_count * packet_size),
        packet_rate=round(rate, 2), byte_rate=round(rate * packet_size, 2), packet_size=round(packet_size, 2),
        flow_id=flow_id, unique_sources=src_count, unique_destinations=1, tcp_flags=flags,
        icmp_type="RPL_CONTROL" if scenario_id == "rpl_anomaly" else None,
        attack_type=None if normal else scenario_id,
        traffic_type="NORMAL" if normal else "CONTROLLED_ATTACK_SIMULATION",
        label="NORMAL" if normal else "ATTACK", scenario_id=scenario_id, provenance=provenance,
        auth_token=token,
    ).normalize()
