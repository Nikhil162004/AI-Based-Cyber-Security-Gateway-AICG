import sys
import joblib
import pandas as pd

MODEL_PATH = "detection/ns3_ddos_model_v3.pkl"

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count"
]


def load_model():
    return joblib.load(MODEL_PATH)


def predict(features):
    """
    Run V3 inference on one traffic window.

    Required input:
        dictionary containing exactly the five ML features.

    Returns:
        prediction
        NORMAL probability
        DDOS probability
    """

    missing = [f for f in FEATURES if f not in features]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    extra = [f for f in features if f not in FEATURES]

    if extra:
        raise ValueError(
            f"Unexpected features: {extra}"
        )

    row = pd.DataFrame(
        [[features[f] for f in FEATURES]],
        columns=FEATURES
    )

    model = load_model()

    prediction = model.predict(row)[0]
    probability = model.predict_proba(row)[0]

    probability_map = dict(
        zip(model.classes_, probability)
    )

    return {
        "prediction": prediction,
        "normal_probability": float(
            probability_map.get("NORMAL", 0.0)
        ),
        "ddos_probability": float(
            probability_map.get("DDOS_UDP", 0.0)
        )
    }


if __name__ == "__main__":

    tests = {
        "NORMAL": {
            "packet_count": 30,
            "bytes_total": 6900,
            "unique_sources": 3,
            "average_packet_size": 230.0,
            "flow_count": 3
        },

        "LOW_DDOS": {
            "packet_count": 230,
            "bytes_total": 115300,
            "unique_sources": 4,
            "average_packet_size": 501.304348,
            "flow_count": 4
        },

        "MIDLOW_DDOS": {
            "packet_count": 364,
            "bytes_total": 187928,
            "unique_sources": 4,
            "average_packet_size": 516.285714,
            "flow_count": 4
        },

        "MID_DDOS": {
            "packet_count": 479,
            "bytes_total": 250258,
            "unique_sources": 4,
            "average_packet_size": 522.459290,
            "flow_count": 4
        },

        "BASELINE_DDOS": {
            "packet_count": 1030,
            "bytes_total": 548900,
            "unique_sources": 4,
            "average_packet_size": 532.912621,
            "flow_count": 4
        }
    }

    print()
    print("V3 INFERENCE WRAPPER TEST")
    print("=" * 60)

    for name, sample in tests.items():

        result = predict(sample)

        print()
        print(name)
        print("Prediction:", result["prediction"])
        print(
            "NORMAL probability:",
            f"{result['normal_probability']:.6f}"
        )
        print(
            "DDOS probability:",
            f"{result['ddos_probability']:.6f}"
        )

    print()
    print("=" * 60)
    print("V3 INFERENCE WRAPPER TEST COMPLETE")
    print("=" * 60)
