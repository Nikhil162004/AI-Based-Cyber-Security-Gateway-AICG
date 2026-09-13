"""Reproducible synthetic laboratory dataset, grouped evaluation, and model bundle."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (average_precision_score, brier_score_loss, classification_report, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from .detection import FEATURES, FEATURE_VERSION, feature_mapping
from .scenarios import CATALOGUE, generate_window


DATASET_VERSION = "synthetic-lab-v2"


def generate_dataset(output: Path, metadata_output: Path | None = None, *, samples_per_campaign: int = 35, seed: int = 20260913) -> dict[str, Any]:
    """Generate varied windows; every row identifies its synthetic campaign.

    This does not duplicate existing captures and it deliberately never claims
    to be a field or industrial traffic dataset.
    """
    rows: list[dict[str, Any]] = []
    campaigns = 0
    for scenario_id, scenario in CATALOGUE.items():
        intensities = (1, 2) if scenario_id == "normal" else range(scenario.intensity_range[0], scenario.intensity_range[1] + 1)
        for intensity in intensities:
            campaign = f"{scenario_id}-i{intensity}"
            campaigns += 1
            for sequence in range(samples_per_campaign):
                event = generate_window(scenario_id, intensity, sequence, seed=seed + intensity, provenance="SYNTHETIC", source_type="DATASET_GENERATOR")
                # The variation is source-controlled but each value is generated, not copied.
                features = feature_mapping(event)
                rows.append({**features, "label": "NORMAL" if scenario_id == "normal" else "ATTACK", "attack_type": event.attack_type or "none",
                             "scenario_id": scenario_id, "campaign_id": campaign, "intensity": intensity, "provenance": "SYNTHETIC", "seed": seed + intensity})
    df = pd.DataFrame(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    metadata = {"dataset_id": output.stem, "dataset_version": DATASET_VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
                "provenance": "SYNTHETIC", "random_seed": seed, "feature_version": FEATURE_VERSION, "rows": len(df),
                "campaigns": campaigns, "samples_per_campaign": samples_per_campaign, "class_distribution": df["label"].value_counts().to_dict(),
                "features": FEATURES, "generation": "safe in-process traffic-window profiles; no packets transmitted"}
    metadata_output = metadata_output or output.with_suffix(".metadata.json")
    metadata_output.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return metadata


def _split_groups(data: pd.DataFrame, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Campaign-level 60/20/20 split avoids row-level campaign leakage."""
    groups = data["campaign_id"].to_numpy()
    splitter = GroupShuffleSplit(n_splits=1, test_size=.40, random_state=seed)
    train_idx, remainder_idx = next(splitter.split(data, data["label"], groups))
    remainder = data.iloc[remainder_idx]
    splitter = GroupShuffleSplit(n_splits=1, test_size=.50, random_state=seed + 1)
    val_local, test_local = next(splitter.split(remainder, remainder["label"], remainder["campaign_id"]))
    return train_idx, remainder_idx[val_local], remainder_idx[test_local]


def _metrics(y_true: pd.Series, predictions: np.ndarray, probability: np.ndarray) -> dict[str, Any]:
    labels = ["NORMAL", "ATTACK"]
    precision, recall, f1, support = precision_recall_fscore_support(y_true, predictions, labels=labels, zero_division=0)
    matrix = confusion_matrix(y_true, predictions, labels=labels)
    tn, fp, fn, tp = matrix.ravel()
    result: dict[str, Any] = {
        "samples": int(len(y_true)), "labels": labels, "confusion_matrix": matrix.tolist(),
        "precision": {label: float(value) for label, value in zip(labels, precision)},
        "recall": {label: float(value) for label, value in zip(labels, recall)},
        "f1": {label: float(value) for label, value in zip(labels, f1)},
        "support": {label: int(value) for label, value in zip(labels, support)},
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "false_positives": int(fp), "false_negatives": int(fn),
        "classification_report": classification_report(y_true, predictions, labels=labels, output_dict=True, zero_division=0),
    }
    target = (y_true == "ATTACK").astype(int)
    if len(set(target)) > 1:
        result.update({"roc_auc": float(roc_auc_score(target, probability)), "pr_auc": float(average_precision_score(target, probability)),
                       "brier_score": float(brier_score_loss(target, probability))})
    return result


def train_and_evaluate(dataset_path: Path, model_path: Path, report_path: Path, *, seed: int = 20260913, held_out_scenario: str = "mixed_vector") -> dict[str, Any]:
    data = pd.read_csv(dataset_path)
    needed = set(FEATURES + ["label", "scenario_id", "campaign_id"])
    missing = needed - set(data.columns)
    if missing: raise ValueError(f"Dataset lacks required columns: {sorted(missing)}")
    # Entire requested scenario is absent from fitting. This is a stricter second evaluation.
    held_out = data[data["scenario_id"] == held_out_scenario].copy()
    fit_data = data[data["scenario_id"] != held_out_scenario].copy()
    train_idx, validation_idx, test_idx = _split_groups(fit_data, seed)
    train, validation, test = fit_data.iloc[train_idx], fit_data.iloc[validation_idx], fit_data.iloc[test_idx]
    classifier = RandomForestClassifier(n_estimators=240, min_samples_leaf=2, class_weight="balanced", random_state=seed, n_jobs=-1)
    classifier.fit(train[FEATURES], train["label"])
    scaler = StandardScaler().fit(train[FEATURES])
    anomaly = IsolationForest(n_estimators=200, contamination=.08, random_state=seed)
    anomaly.fit(scaler.transform(train.loc[train["label"] == "NORMAL", FEATURES]))
    attack_index = list(classifier.classes_).index("ATTACK")
    def evaluate(frame: pd.DataFrame) -> dict[str, Any]:
        probability = classifier.predict_proba(frame[FEATURES])[:, attack_index]
        prediction = classifier.predict(frame[FEATURES])
        return _metrics(frame["label"], prediction, probability)
    report = {
        "experiment_id": f"EXP-{uuid4().hex[:12]}", "timestamp": datetime.now(timezone.utc).isoformat(), "dataset": str(dataset_path),
        "dataset_version": DATASET_VERSION, "feature_version": FEATURE_VERSION, "model_version": "hybrid-rf-if-v2", "random_seed": seed,
        "provenance": "SYNTHETIC", "evaluation_protocol": "campaign-grouped train/validation/test plus scenario-held-out evaluation",
        "class_distribution": data["label"].value_counts().to_dict(), "splits": {"train": len(train), "validation": len(validation), "test": len(test), "scenario_held_out": len(held_out)},
        "validation": evaluate(validation), "test": evaluate(test), "scenario_held_out": evaluate(held_out),
        "feature_importance": {feature: float(value) for feature, value in sorted(zip(FEATURES, classifier.feature_importances_), key=lambda pair: pair[1], reverse=True)},
        "calibration_note": "Brier score is reported for raw RF probabilities; probabilities are not calibrated by this pipeline.",
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"classifier": classifier, "anomaly": anomaly, "anomaly_scaler": scaler, "features": FEATURES,
                 "model_version": "hybrid-rf-if-v2", "feature_version": FEATURE_VERSION, "training_seed": seed}, model_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    # Useful review artefact without pretending that it is a chart or measurement.
    pd.DataFrame(report["test"]["confusion_matrix"], index=["actual_NORMAL", "actual_ATTACK"], columns=["pred_NORMAL", "pred_ATTACK"]).to_csv(report_path.with_name("confusion_matrix.csv"))
    return report
