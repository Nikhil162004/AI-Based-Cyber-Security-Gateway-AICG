import pickle
from pathlib import Path

import pandas as pd


MODEL_FILE = Path("detection/ns3_ddos_model_v1.pkl")

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count",
]


def load_model():
    """Load the frozen NS-3 baseline Random Forest model."""
    with open(MODEL_FILE, "rb") as f:
        return pickle.load(f)


def validate_features(feature_row):
    """Validate and normalize one feature row."""
    missing = [feature for feature in FEATURES if feature not in feature_row]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    values = {}

    for feature in FEATURES:
        try:
            values[feature] = float(feature_row[feature])
        except (TypeError, ValueError):
            raise ValueError(
                f"Feature '{feature}' must be numeric."
            )

    return pd.DataFrame([values], columns=FEATURES)


def predict(feature_row):
    """
    Run ML inference on one NS-3 feature window.

    Returns:
        dict containing prediction and class probabilities.
    """

    model = load_model()

    X = validate_features(feature_row)

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

    class_probabilities = dict(
        zip(model.classes_, probabilities)
    )

    return {
        "prediction": prediction,
        "probabilities": class_probabilities,
    }


if __name__ == "__main__":

    # Representative NORMAL window from the current NS-3 dataset.
    normal_sample = {
        "packet_count": 30,
        "bytes_total": 6900,
        "unique_sources": 3,
        "average_packet_size": 230.0,
        "flow_count": 3,
    }

    # Representative controlled DDoS window.
    ddos_sample = {
        "packet_count": 1030,
        "bytes_total": 548900,
        "unique_sources": 4,
        "average_packet_size": 532.9126,
        "flow_count": 4,
    }

    print("=" * 80)
    print("NS-3 ML INFERENCE COMPONENT V1")
    print("=" * 80)

    print("\nNORMAL sample:")
    result = predict(normal_sample)
    print("Prediction:", result["prediction"])

    for cls, probability in result["probabilities"].items():
        print(f"  {cls:8s}: {probability:.4f}")

    print("\nDDoS sample:")
    result = predict(ddos_sample)
    print("Prediction:", result["prediction"])

    for cls, probability in result["probabilities"].items():
        print(f"  {cls:8s}: {probability:.4f}")

    print("\n" + "=" * 80)
    print("INFERENCE COMPONENT TEST COMPLETE")
    print("=" * 80)
