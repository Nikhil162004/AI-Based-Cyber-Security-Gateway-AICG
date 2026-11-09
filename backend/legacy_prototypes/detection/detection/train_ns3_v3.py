import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneOut, cross_val_predict
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)

DATASET = "dataset/ns3_ml_ready_combined_v4.csv"
MODEL_OUT = "detection/ns3_ddos_model_v3.pkl"

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count"
]

df = pd.read_csv(DATASET)

X = df[FEATURES]
y = df["label"]

print()
print("[1] Dataset")
print("Rows:", len(df))
print("Features:", FEATURES)

print()
print("[2] Label distribution")
print(y.value_counts().sort_index())

print()
print("[3] Scenario distribution")
print(df["scenario"].value_counts().sort_index())

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

print()
print("[4] Training Random Forest")
print("n_estimators: 100")
print("random_state: 42")
print("class_weight: balanced")

# Leave-One-Out cross-validation
loo = LeaveOneOut()

predictions = cross_val_predict(
    model,
    X,
    y,
    cv=loo
)

accuracy = accuracy_score(y, predictions)

cm = confusion_matrix(
    y,
    predictions,
    labels=["NORMAL", "DDOS_UDP"]
)

print()
print("[5] LOOCV result")
print(f"Accuracy: {accuracy:.4f}")

print()
print("Confusion matrix")
print("Rows = actual, Columns = predicted")
print("             NORMAL  DDOS")
print(
    f"NORMAL       {cm[0,0]:6d} {cm[0,1]:6d}"
)
print(
    f"DDOS         {cm[1,0]:6d} {cm[1,1]:6d}"
)

print()
print(classification_report(
    y,
    predictions,
    labels=["NORMAL", "DDOS_UDP"],
    zero_division=0
))

# Train final model on the complete frozen dataset
model.fit(X, y)

print()
print("[6] Final model feature importance")

importance = pd.DataFrame({
    "feature": FEATURES,
    "importance": model.feature_importances_
}).sort_values(
    "importance",
    ascending=False
)

print(importance.to_string(index=False))

# Save versioned model
joblib.dump(model, MODEL_OUT)

print()
print("[7] Saved model:", MODEL_OUT)

print()
print("============================================================")
print("TASK #79 COMPLETE")
print("============================================================")
