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
from sklearn.calibration import CalibratedClassifierCV
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
        if scenario_id == "normal":
            intensities = range(1, 9)
        else:
            intensities = range(scenario.intensity_range[0], scenario.intensity_range[1] + 1)

        for intensity in intensities:
            campaign = f"{scenario_id}-i{intensity}"
            campaigns += 1
            for sequence in range(samples_per_campaign):
                event = generate_window(scenario_id, intensity, sequence, seed=seed + intensity, provenance="SYNTHETIC", source_type="DATASET_GENERATOR")
                features = feature_mapping(event)
                rows.append({
                    **features,
                    "label": "NORMAL" if scenario_id == "normal" else "ATTACK",
                    "attack_type": event.attack_type or "none",
                    "scenario_id": scenario_id,
                    "campaign_id": campaign,
                    "intensity": intensity,
                    "provenance": "SYNTHETIC",
                    "seed": seed + intensity
                })
    df = pd.DataFrame(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    metadata = {
        "dataset_id": output.stem,
        "dataset_version": DATASET_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provenance": "SYNTHETIC",
        "random_seed": seed,
        "feature_version": FEATURE_VERSION,
        "rows": len(df),
        "campaigns": campaigns,
        "samples_per_campaign": samples_per_campaign,
        "class_distribution": df["label"].value_counts().to_dict(),
        "features": FEATURES,
        "generation": "safe in-process traffic-window profiles; no packets transmitted"
    }
    metadata_output = metadata_output or output.with_suffix(".metadata.json")
    metadata_output.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return metadata


def _split_groups(data: pd.DataFrame, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Campaign-level 60/20/20 stratified split avoids row-level campaign leakage
    while ensuring both NORMAL and ATTACK classes are present in train, val, and test splits."""
    normal_df = data[data["label"] == "NORMAL"].reset_index(drop=False)
    attack_df = data[data["label"] == "ATTACK"].reset_index(drop=False)

    def split_subset(subset: pd.DataFrame, sub_seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        groups = subset["campaign_id"].to_numpy()
        splitter = GroupShuffleSplit(n_splits=1, test_size=.40, random_state=sub_seed)
        train_sub, rem_sub = next(splitter.split(subset, subset["label"], groups))
        remainder = subset.iloc[rem_sub].reset_index(drop=False)
        splitter2 = GroupShuffleSplit(n_splits=1, test_size=.50, random_state=sub_seed + 1)
        val_rem, test_rem = next(splitter2.split(remainder, remainder["label"], remainder["campaign_id"].to_numpy()))
        orig_indices = subset["index"].to_numpy()
        train_idx = orig_indices[train_sub]
        val_idx = remainder["index"].to_numpy()[val_rem]
        test_idx = remainder["index"].to_numpy()[test_rem]
        return train_idx, val_idx, test_idx

    norm_tr, norm_val, norm_te = split_subset(normal_df, seed)
    att_tr, att_val, att_te = split_subset(attack_df, seed + 100)

    train_indices = np.concatenate([norm_tr, att_tr])
    val_indices = np.concatenate([norm_val, att_val])
    test_indices = np.concatenate([norm_te, att_te])
    return train_indices, val_indices, test_indices


def _metrics(y_true: pd.Series, predictions: np.ndarray, probability: np.ndarray) -> dict[str, Any]:
    labels = ["NORMAL", "ATTACK"]
    precision, recall, f1, support = precision_recall_fscore_support(y_true, predictions, labels=labels, zero_division=0)
    matrix = confusion_matrix(y_true, predictions, labels=labels)
    if matrix.shape == (2, 2):
        tn, fp, fn, tp = matrix.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    else:
        tn = fp = fn = tp = 0
        fpr = fnr = 0.0
    result: dict[str, Any] = {
        "samples": int(len(y_true)),
        "labels": labels,
        "confusion_matrix": matrix.tolist(),
        "precision": {label: float(value) for label, value in zip(labels, precision)},
        "recall": {label: float(value) for label, value in zip(labels, recall)},
        "f1": {label: float(value) for label, value in zip(labels, f1)},
        "support": {label: int(value) for label, value in zip(labels, support)},
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "classification_report": classification_report(y_true, predictions, labels=labels, output_dict=True, zero_division=0),
    }
    target = (y_true == "ATTACK").astype(int)
    if len(set(target)) > 1:
        result.update({
            "roc_auc": float(roc_auc_score(target, probability)),
            "pr_auc": float(average_precision_score(target, probability)),
            "brier_score": float(brier_score_loss(target, probability))
        })
    return result


def train_and_evaluate(dataset_path: Path, model_path: Path, report_path: Path, *, seed: int = 20260913, held_out_scenario: str = "mixed_vector") -> dict[str, Any]:
    data = pd.read_csv(dataset_path)
    needed = set(FEATURES + ["label", "scenario_id", "campaign_id"])
    missing = needed - set(data.columns)
    if missing:
        raise ValueError(f"Dataset lacks required columns: {sorted(missing)}")

    # Entire requested scenario is absent from fitting. This is a stricter second evaluation.
    held_out = data[data["scenario_id"] == held_out_scenario].copy()
    fit_data = data[data["scenario_id"] != held_out_scenario].copy().reset_index(drop=True)

    train_idx, validation_idx, test_idx = _split_groups(fit_data, seed)
    train, validation, test = fit_data.iloc[train_idx], fit_data.iloc[validation_idx], fit_data.iloc[test_idx]

    classifier = RandomForestClassifier(n_estimators=240, min_samples_leaf=2, class_weight="balanced", random_state=seed, n_jobs=-1)
    classifier.fit(train[FEATURES], train["label"])

    scaler = StandardScaler().fit(train[FEATURES])
    anomaly = IsolationForest(n_estimators=200, contamination=.08, random_state=seed)
    anomaly.fit(scaler.transform(train.loc[train["label"] == "NORMAL", FEATURES]))

    attack_index = list(classifier.classes_).index("ATTACK")

    # Fit probability calibration on validation split
    try:
        from sklearn.frozen import FrozenEstimator
        calibrator = CalibratedClassifierCV(estimator=FrozenEstimator(classifier), method="sigmoid")
    except ImportError:
        calibrator = CalibratedClassifierCV(estimator=classifier, method="sigmoid", cv="prefit")
    calibrator.fit(validation[FEATURES], validation["label"])

    def evaluate(frame: pd.DataFrame, use_calibrated: bool = False) -> dict[str, Any]:
        clf = calibrator if use_calibrated else classifier
        probability = clf.predict_proba(frame[FEATURES])[:, attack_index]
        prediction = clf.predict(frame[FEATURES])
        return _metrics(frame["label"], prediction, probability)

    validation_eval = evaluate(validation, use_calibrated=False)
    test_eval_raw = evaluate(test, use_calibrated=False)
    test_eval_calibrated = evaluate(test, use_calibrated=True)
    held_out_eval = evaluate(held_out, use_calibrated=True)

    report = {
        "experiment_id": f"EXP-{uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset_path),
        "dataset_version": DATASET_VERSION,
        "feature_version": FEATURE_VERSION,
        "model_version": "hybrid-rf-if-v2",
        "random_seed": seed,
        "provenance": "SYNTHETIC",
        "evaluation_protocol": "stratified campaign-grouped train/validation/test plus scenario-held-out evaluation",
        "class_distribution": data["label"].value_counts().to_dict(),
        "splits": {
            "train": len(train),
            "validation": len(validation),
            "test": len(test),
            "scenario_held_out": len(held_out)
        },
        "validation": validation_eval,
        "test": test_eval_calibrated,
        "test_raw_rf": test_eval_raw,
        "scenario_held_out": held_out_eval,
        "feature_importance": {
            feature: float(value) for feature, value in sorted(
                zip(FEATURES, classifier.feature_importances_),
                key=lambda pair: pair[1],
                reverse=True
            )
        },
        "calibration": {
            "method": "sigmoid (Platt scaling) on held-out validation campaigns",
            "brier_score_raw": test_eval_raw.get("brier_score"),
            "brier_score_calibrated": test_eval_calibrated.get("brier_score"),
            "calibrated": True
        }
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "classifier": classifier,
        "calibrated_classifier": calibrator,
        "anomaly": anomaly,
        "anomaly_scaler": scaler,
        "features": FEATURES,
        "model_version": "hybrid-rf-if-v2",
        "feature_version": FEATURE_VERSION,
        "training_seed": seed,
        "calibrated": True
    }, model_path)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    # CSV confusion matrix artifact
    pd.DataFrame(
        report["test"]["confusion_matrix"],
        index=["actual_NORMAL", "actual_ATTACK"],
        columns=["pred_NORMAL", "pred_ATTACK"]
    ).to_csv(report_path.with_name("confusion_matrix.csv"))

    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Aegis Gateway ML training and evaluation")
    parser.add_argument("--dataset", type=Path, default=Path("data/datasets/synthetic_lab_v2.csv"))
    parser.add_argument("--model", type=Path, default=Path("models/hybrid_detector.joblib"))
    parser.add_argument("--report", type=Path, default=Path("reports/evaluation.json"))
    parser.add_argument("--seed", type=int, default=20260913)
    parser.add_argument("--generate", action="store_true", help="Generate synthetic dataset first")
    args = parser.parse_args()

    if args.generate or not args.dataset.exists():
        print(f"Generating synthetic dataset at {args.dataset}...")
        meta_path = args.dataset.with_name(args.dataset.stem + ".metadata.json")
        generate_dataset(args.dataset, meta_path, seed=args.seed)

    print(f"Training and evaluating model on {args.dataset}...")
    res = train_and_evaluate(args.dataset, args.model, args.report, seed=args.seed)
    print(f"Model saved to {args.model}")
    print(f"Report saved to {args.report}")
    print(f"Test F1: {res['test']['f1']['ATTACK']:.4f}, Brier: {res['calibration']['brier_score_calibrated']:.6f}")
