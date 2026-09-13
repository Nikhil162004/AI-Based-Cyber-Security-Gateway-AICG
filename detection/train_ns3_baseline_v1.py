import os
import pickle

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import LeaveOneOut


# ============================================================
# 1. FILE PATHS
# ============================================================

INPUT_FILE = "dataset/ns3_ml_ready_primary_v1.csv"
MODEL_FILE = "detection/ns3_ddos_model_v1.pkl"


# ============================================================
# 2. FEATURE DEFINITION
# ============================================================

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count",
]

LABEL_COLUMN = "label"


# ============================================================
# 3. LOAD DATASET
# ============================================================

print("=" * 80)
print("NS-3 AI-EDGE DDoS DETECTION — BASELINE TRAINING")
print("=" * 80)

print("\nLoading dataset...")
data = pd.read_csv(INPUT_FILE)

print("Dataset:", INPUT_FILE)
print("Samples:", len(data))
print("Features:", len(FEATURES))


# ============================================================
# 4. BASIC VALIDATION
# ============================================================

missing = int(data[FEATURES + [LABEL_COLUMN]].isna().sum().sum())

if missing != 0:
    raise ValueError(f"Dataset contains {missing} missing values.")

if not all(feature in data.columns for feature in FEATURES):
    raise ValueError("Dataset is missing one or more required features.")

if LABEL_COLUMN not in data.columns:
    raise ValueError("Dataset does not contain the label column.")

print("\nClass distribution:")
print(data[LABEL_COLUMN].value_counts().to_string())

print("\nExact duplicate rows:")
print(int(data.duplicated().sum()))


# ============================================================
# 5. PREPARE FEATURES AND LABEL
# ============================================================

X = data[FEATURES]
y = data[LABEL_COLUMN]


# ============================================================
# 6. LEAVE-ONE-OUT CROSS-VALIDATION
# ============================================================

print("\n" + "=" * 80)
print("LEAVE-ONE-OUT CROSS-VALIDATION")
print("=" * 80)

loo = LeaveOneOut()

predictions = []
actual = []

for train_index, test_index in loo.split(X):

    X_train = X.iloc[train_index]
    X_test = X.iloc[test_index]

    y_train = y.iloc[train_index]
    y_test = y.iloc[test_index]

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    prediction = model.predict(X_test)[0]

    predictions.append(prediction)
    actual.append(y_test.iloc[0])


# ============================================================
# 7. EVALUATION
# ============================================================

accuracy = accuracy_score(actual, predictions)

cm = confusion_matrix(
    actual,
    predictions,
    labels=["NORMAL", "DDOS_UDP"],
)

print("\nLOOCV Accuracy:")
print(f"  {accuracy:.4f}")

print("\nConfusion Matrix:")
print("                 Predicted")
print("                 NORMAL  DDOS_UDP")
print(f"Actual NORMAL    {cm[0,0]:7d}  {cm[0,1]:8d}")
print(f"Actual DDOS_UDP  {cm[1,0]:7d}  {cm[1,1]:8d}")

print("\nClassification Report:")
print(
    classification_report(
        actual,
        predictions,
        labels=["NORMAL", "DDOS_UDP"],
        zero_division=0,
    )
)


# ============================================================
# 8. TRAIN FINAL MODEL ON ALL DATA
# ============================================================

print("=" * 80)
print("TRAINING FINAL BASELINE MODEL")
print("=" * 80)

final_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
)

final_model.fit(X, y)


# ============================================================
# 9. FEATURE IMPORTANCE
# ============================================================

importance = pd.DataFrame({
    "feature": FEATURES,
    "importance": final_model.feature_importances_,
})

importance = importance.sort_values(
    by="importance",
    ascending=False,
)

print("\nFeature Importance:")
print(importance.to_string(index=False))


# ============================================================
# 10. SAVE MODEL
# ============================================================

with open(MODEL_FILE, "wb") as f:
    pickle.dump(final_model, f)

print("\nModel saved:")
print(" ", MODEL_FILE)

print("\nModel size:")
print(" ", os.path.getsize(MODEL_FILE), "bytes")


# ============================================================
# 11. MODEL METADATA
# ============================================================

print("\nModel feature count:")
print(" ", final_model.n_features_in_)

print("\nModel classes:")
print(" ", list(final_model.classes_))

print("\n" + "=" * 80)
print("NS-3 BASELINE TRAINING COMPLETE")
print("=" * 80)

print("\nIMPORTANT LIMITATION:")
print(
    "This model is trained on only 19 one-second windows from "
    "one controlled UDP-DDoS scenario."
)
print(
    "LOOCV performance must not be interpreted as proof of "
    "generalization to unseen attack types or networks."
)
