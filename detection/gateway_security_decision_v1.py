"""
Integrated Gateway Security Decision Layer V1

Pipeline:
    Feature Vector
        ↓
    ML Bridge
        ↓
    Security Policy
        ↓
    Final Gateway Decision

This module is host-side only.
It does not directly block or isolate network traffic.
"""

from gateway_ml_bridge_v1 import classify_window

import sys
sys.path.insert(
    0,
    "/home/kali/contiki-ng/examples/ai_edge_iiot/detection"
)

from security_policy_v1 import apply_policy


def evaluate_gateway_window(features):
    """
    Run ML classification followed by the security policy.
    """

    ml_result = classify_window(features)

    policy_result = apply_policy(
        ml_result["prediction"],
        ml_result["normal_probability"],
        ml_result["ddos_probability"],
    )

    return {
        "prediction": policy_result["prediction"],
        "normal_probability": policy_result["normal_probability"],
        "ddos_probability": policy_result["ddos_probability"],
        "action": policy_result["action"],
        "severity": policy_result["severity"],
    }


if __name__ == "__main__":

    tests = {
        "NORMAL": {
            "packet_count": 30,
            "bytes_total": 6900,
            "unique_sources": 3,
            "average_packet_size": 230,
            "flow_count": 3,
        },

        "DDOS_LOW": {
            "packet_count": 230,
            "bytes_total": 115300,
            "unique_sources": 4,
            "average_packet_size": 501.304348,
            "flow_count": 4,
        },

        "DDOS_BASELINE": {
            "packet_count": 1030,
            "bytes_total": 548900,
            "unique_sources": 4,
            "average_packet_size": 532.9126,
            "flow_count": 4,
        },
    }

    print("TASK #134 — INTEGRATED GATEWAY SECURITY DECISION")
    print("=" * 70)

    for name, features in tests.items():

        result = evaluate_gateway_window(features)

        print()
        print(name)
        print("-" * 70)
        print("Prediction    :", result["prediction"])
        print("Normal prob   :", result["normal_probability"])
        print("DDoS prob     :", result["ddos_probability"])
        print("Action        :", result["action"])
        print("Severity      :", result["severity"])

    print()
    print("=" * 70)
    print("TASK #134 TEST COMPLETE")
