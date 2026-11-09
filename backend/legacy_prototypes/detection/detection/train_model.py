import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split


# ============================================================
# 1. FILE PATH
# ============================================================

INPUT_FILE = "dataset/ml_training_data.csv"


# ============================================================
# 2. LOAD DATASET
# ============================================================

print("=" * 70)
print("AI-EDGE DDoS DETECTION - ML TRAINING")
print("=" * 70)

print("\nLoading dataset...")

data = pd.read_csv(INPUT_FILE)

print(f"Total windows: {len(data)}")


# ============================================================
# 3. SELECT FEATURES
# ============================================================

features = [
    "packet_count",
    "bytes_total",
    "packets_per_second",
    "bytes_per_second",
    "unique_sources",
    "unique_destinations",
    "udp_count",
    "tcp_count",
    "icmp_count",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "average_packet_size",
    "flow_count"
]

X = data[features]


# ============================================================
# 4. CREATE TARGET LABEL
# ============================================================

y = data["label"]


# ============================================================
# 5. DISPLAY DATASET INFORMATION
# ============================================================

print("\nClass distribution:")

print(y.value_counts())


# ============================================================
# 6. TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# ============================================================
# 7. CREATE RANDOM FOREST MODEL
# ============================================================

print("\nCreating Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)


# ============================================================
# 8. TRAIN MODEL
# ============================================================

print("Training model...")

model.fit(X_train, y_train)


# ============================================================
# 9. PREDICTION
# ============================================================

y_pred = model.predict(X_test)


# ============================================================
# 10. EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n" + "=" * 70)
print("MODEL RESULTS")
print("=" * 70)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


# ============================================================
# 11. FEATURE IMPORTANCE
# ============================================================

print("\nFeature Importance:")

importance = pd.DataFrame({
    "feature": features,
    "importance": model.feature_importances_
})

importance = importance.sort_values(
    by="importance",
    ascending=False
)

print(
    importance.to_string(
        index=False
    )
)


# ============================================================
# 12. SAVE MODEL
# ============================================================

import joblib

MODEL_FILE = "detection/ddos_model.pkl"

joblib.dump(
    model,
    MODEL_FILE
)

print("\n" + "=" * 70)
print("MODEL SAVED")
print("=" * 70)

print(f"Model file: {MODEL_FILE}")
