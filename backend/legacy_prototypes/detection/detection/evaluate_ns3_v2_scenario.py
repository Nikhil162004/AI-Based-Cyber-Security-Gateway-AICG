import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

DATASET = "dataset/ns3_ml_ready_combined_v2.csv"

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count",
]

df = pd.read_csv(DATASET)

# The first 19 rows are the frozen baseline dataset.
# The remaining 18 rows are the low-intensity scenario.
baseline = df.iloc[:19].copy()
low = df.iloc[19:].copy()

X_baseline = baseline[FEATURES]
y_baseline = baseline["label"]

X_low = low[FEATURES]
y_low = low["label"]


def evaluate(train_X, train_y, test_X, test_y, title):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(train_X, train_y)

    predictions = model.predict(test_X)

    accuracy = accuracy_score(test_y, predictions)
    cm = confusion_matrix(
        test_y,
        predictions,
        labels=["NORMAL", "DDOS_UDP"]
    )

    print(f"\nTraining rows: {len(train_X)}")
    print(f"Testing rows : {len(test_X)}")
    print(f"Accuracy     : {accuracy:.4f}")

    print("\nConfusion matrix")
    print("Rows = actual, columns = predicted")
    print("              NORMAL  DDOS_UDP")
    print(f"NORMAL        {cm[0,0]:6d}  {cm[0,1]:8d}")
    print(f"DDOS_UDP      {cm[1,0]:6d}  {cm[1,1]:8d}")

    print("\nClassification report")
    print(
        classification_report(
            test_y,
            predictions,
            labels=["NORMAL", "DDOS_UDP"],
            zero_division=0
        )
    )

    return model


# ---------------------------------------------------------------------
# Test 1:
# Train on baseline, test on low-intensity.
# ---------------------------------------------------------------------
evaluate(
    X_baseline,
    y_baseline,
    X_low,
    y_low,
    "SCENARIO TEST 1: BASELINE -> LOW-INTENSITY"
)

# ---------------------------------------------------------------------
# Test 2:
# Train on low-intensity, test on baseline.
# ---------------------------------------------------------------------
evaluate(
    X_low,
    y_low,
    X_baseline,
    y_baseline,
    "SCENARIO TEST 2: LOW-INTENSITY -> BASELINE"
)

print("\n" + "=" * 80)
print("NS-3 V2 SCENARIO EVALUATION COMPLETE")
print("=" * 80)

print("\nFeatures used:")
for feature in FEATURES:
    print(f"  - {feature}")

print("\nDataset:")
print(f"  {DATASET}")

print("\nImportant:")
print("  The original baseline model was not modified.")
print("  This evaluation uses scenario-separated testing.")
print("=" * 80)
