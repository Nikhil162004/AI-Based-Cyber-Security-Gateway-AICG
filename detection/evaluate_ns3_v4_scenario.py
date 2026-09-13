import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)

DATASET = "dataset/ns3_ml_ready_combined_v4.csv"

FEATURES = [
    "packet_count",
    "bytes_total",
    "unique_sources",
    "average_packet_size",
    "flow_count"
]

SCENARIOS = [
    "LOW_V1",
    "MIDLOW_V1",
    "MID_V1_CLEAN",
    "BASELINE_V1"
]

df = pd.read_csv(DATASET)

print("Dataset:", DATASET)
print("Total rows:", len(df))
print()

for held_out in SCENARIOS:

    train = df[df["scenario"] != held_out].copy()
    test = df[df["scenario"] == held_out].copy()

    X_train = train[FEATURES]
    y_train = train["label"]

    X_test = test[FEATURES]
    y_test = test["label"]

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    cm = confusion_matrix(
        y_test,
        predictions,
        labels=["NORMAL", "DDOS_UDP"]
    )

    print("=" * 60)
    print("HELD-OUT SCENARIO:", held_out)
    print("=" * 60)

    print(
        "Training scenarios:",
        ", ".join(
            s for s in SCENARIOS
            if s != held_out
        )
    )

    print("Train rows:", len(train))
    print("Test rows:", len(test))
    print()

    print("Test labels:")
    print(y_test.value_counts().sort_index())
    print()

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

    report = classification_report(
        y_test,
        predictions,
        labels=["NORMAL", "DDOS_UDP"],
        zero_division=0
    )

    print(report)

print()
print("=" * 60)
print("TASK #76 COMPLETE")
print("=" * 60)
