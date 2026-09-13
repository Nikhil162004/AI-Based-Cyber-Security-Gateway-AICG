"""
Topology Context Adapter V1

Provides a read-only representation of the controlled NS-3
IIoT/OT topology for dashboard and gateway context layers.

This adapter does not modify or execute the NS-3 scenarios.
Topology facts are derived from the established controlled
NS-3 topology and IAM registry.

Environment:
    CONTROLLED_SIMULATION

Status:
    DECLARED

This is topology context, not live network discovery.
"""

from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

REGISTRY_PATH = (
    PROJECT_ROOT
    / "detection"
    / "device_identity_registry_v1.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "results"
    / "topology_context_v1.json"
)


TOPOLOGY_ID = "CONTROLLED_NS3_IIOT_OT_V1"


def _load_registry() -> dict:
    with REGISTRY_PATH.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def _find_device(
    devices: list[dict],
    device_id: str,
) -> dict:
    for device in devices:
        if device.get("device_id") == device_id:
            return device

    raise KeyError(
        f"Device not found in IAM registry: {device_id}"
    )


def build_topology_context() -> dict:
    """
    Build the declared controlled NS-3 topology context.

    The topology is represented independently from live traffic
    observation and existing ML/security outputs.
    """

    registry = _load_registry()
    devices = registry.get("devices", [])

    sensor_ids = [
        "iiot-sensor-01",
        "iiot-sensor-02",
        "iiot-sensor-03",
    ]

    gateway = _find_device(
        devices,
        "gateway-local",
    )

    sensors = [
        _find_device(devices, device_id)
        for device_id in sensor_ids
    ]

    attack_node = _find_device(
        devices,
        "ns3-attacker-01",
    )

    ot_server = _find_device(
        devices,
        "ot-server-01",
    )

    topology_devices = []

    for device in [
        gateway,
        *sensors,
        attack_node,
        ot_server,
    ]:
        topology_devices.append(
            {
                "device_id": device.get("device_id"),
                "ip_address": device.get("ip_address"),
                "device_role": device.get("device_role"),
                "identity_status": device.get("identity_status"),
                "authorization_decision": device.get(
                    "authorization_decision"
                ),
                "trust_score": device.get("trust_score"),
                "environment": device.get(
                    "environment",
                    "SIMULATED",
                ),
            }
        )

    links = []

    for sensor in sensors:
        links.append(
            {
                "source": sensor["device_id"],
                "destination": gateway["device_id"],
                "relationship": "SENSOR_TO_GATEWAY",
                "status": "DECLARED",
                "environment": "CONTROLLED_SIMULATION",
            }
        )

    links.append(
        {
            "source": attack_node["device_id"],
            "destination": gateway["device_id"],
            "relationship": "CONTROLLED_ATTACK_TO_GATEWAY",
            "status": "DECLARED",
            "environment": "CONTROLLED_SIMULATION",
        }
    )

    links.append(
        {
            "source": gateway["device_id"],
            "destination": ot_server["device_id"],
            "relationship": "GATEWAY_TO_OT_SERVER",
            "status": "DECLARED",
            "environment": "CONTROLLED_SIMULATION",
        }
    )

    return {
        "topology_id": TOPOLOGY_ID,
        "version": "1.0",
        "status": "DECLARED",
        "environment": "CONTROLLED_SIMULATION",
        "topology_type": "IIOT_OT_EDGE_GATEWAY",
        "gateway": {
            "device_id": gateway["device_id"],
            "ip_address": gateway["ip_address"],
            "device_role": gateway["device_role"],
        },
        "sensors": [
            {
                "device_id": sensor["device_id"],
                "ip_address": sensor["ip_address"],
                "device_role": sensor["device_role"],
            }
            for sensor in sensors
        ],
        "controlled_attack_nodes": [
            {
                "device_id": attack_node["device_id"],
                "ip_address": attack_node["ip_address"],
                "device_role": attack_node["device_role"],
                "authorization_decision": attack_node[
                    "authorization_decision"
                ],
                "simulation_only": True,
            }
        ],
        "ot_servers": [
            {
                "device_id": ot_server["device_id"],
                "ip_address": ot_server["ip_address"],
                "device_role": ot_server["device_role"],
            }
        ],
        "devices": topology_devices,
        "links": links,
        "provenance": {
            "source": "CONTROLLED_NS3_TOPOLOGY_AND_IAM_REGISTRY",
            "measurement_status": "DECLARED",
            "live_discovery": False,
            "hardware_measured": False,
            "attack_node_is_real": False,
        },
    }


def write_topology_context() -> dict:
    """
    Write the current declared topology context to JSON.
    """

    context = build_topology_context()

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            context,
            handle,
            indent=2,
        )
        handle.write("\n")

    return context


if __name__ == "__main__":
    context = write_topology_context()

    print("Topology ID:", context["topology_id"])
    print("Environment:", context["environment"])
    print("Status:", context["status"])
    print("Devices:", len(context["devices"]))
    print("Sensors:", len(context["sensors"]))
    print(
        "Controlled attack nodes:",
        len(context["controlled_attack_nodes"]),
    )
    print("OT servers:", len(context["ot_servers"]))
    print("Links:", len(context["links"]))
    print(
        "Live discovery:",
        context["provenance"]["live_discovery"],
    )
    print(
        "Hardware measured:",
        context["provenance"]["hardware_measured"],
    )
