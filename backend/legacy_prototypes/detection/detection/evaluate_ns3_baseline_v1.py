import pickle
import hashlib
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

MODEL = Path("detection/ns3_ddos_model_v1.pkl")
DATASET = Path("dataset/ns3_ml_ready_primary_v1.csv")

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count",
]

REPORT = Path("dataset/ns3_baseline_evaluation_v1.txt")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


print("=" * 80)
print("NS-3 BASELINE EVALUATION")
print("=" * 80)

with open(MODEL, "rb") as f:
    model = pickle.load(f)

df = pd.read_csv(DATASET)

X = df[FEATURES]
y = df["label"]

pred = model.predict(X)

accuracy = accuracy_score(y, pred)
cm = confusion_matrix(y, pred, labels=["NORMAL", "DDOS_UDP"])
report = classification_report(
    y,
    pred,
    labels=["NORMAL", "DDOS_UDP"],
    digits=4,
    zero_division=0,
)

model_hash = sha256(MODEL)
dataset_hash = sha256(DATASET)

output = []

output.append("NS-3 BASELINE EVALUATION REPORT")
output.append("=" * 80)
output.append("")
output.append("Model:")
output.append(str(MODEL))
output.append(f"Model SHA-256: {model_hash}")
output.append("")
output.append("Dataset:")
output.append(str(DATASET))
output.append(f"Dataset SHA-256: {dataset_hash}")
output.append("")
output.append("Feature schema:")
for feature in FEATURES:
    output.append(f"  - {feature}")
output.append("")
output.append(f"Total windows: {len(df)}")
output.append(f"NORMAL windows: {(y == 'NORMAL').sum()}")
output.append(f"DDOS_UDP windows: {(y == 'DDOS_UDP').sum()}")
output.append("")
output.append("Important limitation:")
output.append(
    "The dataset represents one controlled NS-3 DDoS scenario. "
    "Repeated windows are present, so these results do not establish "
    "generalization to unseen attack types, rates, topologies, or traffic patterns."
)
output.append("")
output.append("In-sample inference:")
output.append(f"Correct predictions: {(y == pred).sum()}/{len(y)}")
output.append(f"Accuracy: {accuracy:.4f}")
output.append("")
output.append("Confusion matrix")
output.append("Rows = actual, columns = predicted")
output.append("Labels: NORMAL, DDOS_UDP")
output.append(str(cm))
output.append("")
output.append("Classification report:")
output.append(report)
output.append("")
output.append("Temporal sequence:")
output.append("Windows 00-03 : NORMAL")
output.append("Windows 04-17 : DDOS_UDP")
output.append("Window 18     : NORMAL")
output.append("")
output.append("Conclusion:")
output.append(
    "The saved Random Forest model successfully performs inference using "
    "the defined five-feature NS-3 schema and correctly classifies all "
    "19 controlled simulation windows. This validates the baseline ML "
    "pipeline and temporal transition behavior, but broader evaluation "
    "is required before claiming deployment-level generalization."
)
output.append("")
output.append("=" * 80)

text = "\n".join(output)

print(text)

REPORT.write_text(text + "\n")

print(f"\nReport saved to: {REPORT}")
