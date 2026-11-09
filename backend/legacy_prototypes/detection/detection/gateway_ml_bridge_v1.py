from ns3_ml_inference_v3 import predict

REQUIRED_FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count",
]


def classify_window(features):
    missing = [f for f in REQUIRED_FEATURES if f not in features]
    extra = [f for f in features if f not in REQUIRED_FEATURES]

    if missing:
        raise ValueError(f"Missing features: {missing}")

    if extra:
        raise ValueError(f"Unexpected features: {extra}")

    result = predict(features)

    if result["prediction"] == "DDOS_UDP":
        action = "ALERT"
        severity = "HIGH"
    else:
        action = "ALLOW"
        severity = "NORMAL"

    return {
        "prediction": result["prediction"],
        "normal_probability": result["normal_probability"],
        "ddos_probability": result["ddos_probability"],
        "action": action,
        "severity": severity,
    }


if __name__ == "__main__":
    test_windows = {
        "NORMAL": {
            "packet_count": 30,
            "bytes_total": 6900,
            "unique_sources": 3,
            "average_packet_size": 230,
            "flow_count": 3,
        },
        "LOW_DDOS": {
            "packet_count": 230,
            "bytes_total": 115300,
            "unique_sources": 4,
            "average_packet_size": 501.304348,
            "flow_count": 4,
        },
        "MIDLOW_DDOS": {
            "packet_count": 364,
            "bytes_total": 187928,
            "unique_sources": 4,
            "average_packet_size": 516.285714,
            "flow_count": 4,
        },
        "MID_DDOS": {
            "packet_count": 479,
            "bytes_total": 250258,
            "unique_sources": 4,
            "average_packet_size": 522.459290,
            "flow_count": 4,
        },
        "BASELINE_DDOS": {
            "packet_count": 1030,
            "bytes_total": 548900,
            "unique_sources": 4,
            "average_packet_size": 532.912621,
            "flow_count": 4,
        },
    }

    print("GATEWAY ML BRIDGE V1 TEST")
    print("=" * 60)

    for name, features in test_windows.items():
        result = classify_window(features)

        print()
        print(name)
        print("Prediction:", result["prediction"])
        print("NORMAL probability:", "%.6f" % result["normal_probability"])
        print("DDOS probability:", "%.6f" % result["ddos_probability"])
        print("Action:", result["action"])
        print("Severity:", result["severity"])

    print()
    print("=" * 60)
    print("GATEWAY ML BRIDGE V1 TEST COMPLETE")
    print("=" * 60)
