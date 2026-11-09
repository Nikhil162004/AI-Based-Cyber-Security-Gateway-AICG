import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneOut, cross_val_predict
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

DATASET = Path(
    "/home/kali/contiki-ng/examples/ai_edge_iiot/data/cooja_ml_ready_v1.csv"
)

MODEL_PATH = Path(
    "/home/kali/AI-Edge-DDoS-Gateway/detection/cooja_attack_model_v1.pkl"
)

FEATURES = [
    "packets_in_window",
    "packet_rate_mean",
    "byte_rate_mean",
    "radio_activity_ratio_mean",
]

LABEL = "label"

print("DATASET:", DATASET)
print("MODEL:", MODEL_PATH)

df = pd.read_csv(DATASET)

print("\nDATASET SHAPE:", df.shape)

print("\nLABEL COUNTS:")
print(df[LABEL].value_counts().to_string())

X = df[FEATURES].copy()
y = df[LABEL].copy()

print("\nFEATURES:")
for f in FEATURES:
    print(" ", f)

print("\nFEATURE MATRIX SHAPE:", X.shape)

print("\nMISSING VALUES:")
print(int(X.isna().sum().sum()))

print("\n============================================================")
print("TRAINING")
print("============================================================")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

loo = LeaveOneOut()

pred = cross_val_predict(
    model,
    X,
    y,
    cv=loo
)

accuracy = accuracy_score(y, pred)
cm = confusion_matrix(
    y,
    pred,
    labels=["NORMAL", "ATTACK"]
)

print("LOOCV ACCURACY:", f"{accuracy:.4f}")

print("\nCONFUSION MATRIX")
print("Rows = actual, Columns = predicted")
print("             NORMAL  ATTACK")
print("NORMAL      ", cm[0].tolist())
print("ATTACK      ", cm[1].tolist())

print("\nCLASSIFICATION REPORT:")
print(
    classification_report(
        y,
        pred,
        labels=["NORMAL", "ATTACK"],
        zero_division=0
    )
)

print("\n============================================================")
print("FINAL MODEL FIT")
print("============================================================")

model.fit(X, y)

print("\nFEATURE IMPORTANCE:")
for feature, importance in sorted(
    zip(FEATURES, model.feature_importances_),
    key=lambda x: x[1],
    reverse=True
):
    print(f"  {feature}: {importance:.6f}")

joblib.dump(model, MODEL_PATH)

print("\nMODEL SAVED:", MODEL_PATH)
print("MODEL SIZE:", MODEL_PATH.stat().st_size, "bytes")

print("\nMODEL CLASSES:")
print(model.classes_.tolist())

print("\nMODEL FEATURE COUNT:")
print(model.n_features_in_)

print("\n============================================================")
print("TASK #100 COMPLETE")
print("============================================================")
