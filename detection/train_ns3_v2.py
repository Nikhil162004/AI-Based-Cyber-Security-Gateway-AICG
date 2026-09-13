import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneOut, cross_val_predict
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)

DATASET = "dataset/ns3_ml_ready_combined_v2.csv"
MODEL = "detection/ns3_ddos_model_v2.pkl"

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count",
]

df = pd.read_csv(DATASET)

X = df[FEATURES]
y = df["label"]

print("=" * 80)
print("NS-3 DDoS MODEL V2")
print("=" * 80)

print(f"\nDataset : {DATASET}")
print(f"Rows    : {len(df)}")
print(f"Features: {len(FEATURES)}")

print("\nLabel distribution:")
print(y.value_counts())

print("\nDuplicate rows:")
print(df.duplicated().sum())

# ---------------------------------------------------------------------
# LOOCV
# ---------------------------------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

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

print("\n" + "=" * 80)
print("LOOCV RESULT")
print("=" * 80)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nConfusion matrix")
print("Rows = actual, columns = predicted")
print("              NORMAL  DDOS_UDP")
print(f"NORMAL        {cm[0,0]:6d}  {cm[0,1]:8d}")
print(f"DDOS_UDP      {cm[1,0]:6d}  {cm[1,1]:8d}")

print("\nClassification report:")
print(
    classification_report(
        y,
        predictions,
        labels=["NORMAL", "DDOS_UDP"],
        zero_division=0
    )
)

# ---------------------------------------------------------------------
# Feature importance
# ---------------------------------------------------------------------

model.fit(X, y)

print("\n" + "=" * 80)
print("FEATURE IMPORTANCE")
print("=" * 80)

importance = pd.Series(
    model.feature_importances_,
    index=FEATURES
).sort_values(ascending=False)

for feature, value in importance.items():
    print(f"{feature:25s} {value:.6f}")

# ---------------------------------------------------------------------
# Save final V2 model
# ---------------------------------------------------------------------

joblib.dump(model, MODEL)

print("\n" + "=" * 80)
print("MODEL SAVED")
print("=" * 80)

print(f"Path: {MODEL}")

print("\nImportant:")
print("  V1 model remains unchanged.")
print("  V2 model is trained using both NS-3 scenarios.")
print("  This result does not establish real-world generalization.")
print("=" * 80)
