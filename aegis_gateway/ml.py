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
from .energy import EnergyModel
from .scenarios import CATALOGUE, generate_window


DATASET_VERSION = "synthetic-lab-v2"


def generate_dataset(output: Path, metadata_output: Path | None = None, *, samples_per_campaign: int = 40, seed: int = 20260913) -> dict[str, Any]:
    """Generate varied windows; every row identifies its synthetic campaign.

    This does not duplicate existing captures and it deliberately never claims
    to be a field or industrial traffic dataset.
    """
    energy_model = EnergyModel()
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
                energy_model.correlate(event)
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
            "roc_auc": min(1.0, float(roc_auc_score(target, probability))),
            "pr_auc": min(1.0, float(average_precision_score(target, probability))),
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


REALISTIC_BENCHMARK_VERSION = "realistic-benchmark-v1"


def _generate_realistic_sample(scenario_id: str, intensity: int, sequence: int, seed: int, energy_model: EnergyModel) -> dict[str, Any]:
    from random import Random
    from .schema import TelemetryEvent, utc_now
    rng = Random(f"{seed}:{scenario_id}:{intensity}:{sequence}")
    is_normal = scenario_id.startswith("normal")

    if scenario_id == "normal_periodic":
        rate = 10.0 + intensity * 3.5 + rng.uniform(-2.5, 3.0)
        sources = int(max(1, 2 + intensity + rng.randint(0, 2)))
        size = rng.uniform(90, 260)
        proto = "UDP" if rng.random() < 0.6 else "TCP"
        flags = None
    elif scenario_id == "normal_aggregation":
        rate = 26.0 + intensity * 8.0 + rng.uniform(-4.0, 5.0)
        sources = int(max(5, 7 + intensity * 3 + rng.randint(0, 3)))
        size = rng.uniform(120, 380)
        proto = "UDP" if rng.random() < 0.5 else "TCP"
        flags = "A" if proto == "TCP" and rng.random() < 0.4 else None
    elif scenario_id == "normal_burst":
        base = 50.0 + intensity * 20.0 + rng.uniform(-8.0, 12.0)
        rate = base * 1.3 if (sequence % 4 == 0) else base * 0.8
        sources = int(max(3, 4 + intensity * 2 + rng.randint(0, 3)))
        size = rng.uniform(320, 950)
        proto = "TCP" if rng.random() < 0.8 else "UDP"
        flags = "PA" if proto == "TCP" else None
    elif scenario_id == "normal_noisy":
        rate = max(8.0, 14.0 + intensity * 6.0 + rng.uniform(-7.0, 9.0))
        sources = int(max(2, 2 + intensity * 2 + rng.randint(0, 2)))
        size = rng.uniform(80, 450)
        proto = "UDP" if rng.random() < 0.5 else "TCP"
        flags = None
    elif scenario_id == "slow_stealth":
        rate = 18.0 + intensity * 6.5 + rng.uniform(-3.5, 4.0)
        sources = int(max(2, 3 + intensity + rng.randint(0, 2)))
        size = rng.uniform(60, 140)
        proto = "TCP" if rng.random() < 0.7 else "UDP"
        flags = "S" if proto == "TCP" else None
    elif scenario_id == "gradual_ramp":
        ramp = (sequence / 40.0) * 80.0
        rate = 25.0 + intensity * 15.0 + ramp + rng.uniform(-5.0, 6.0)
        sources = int(max(2, 2 + intensity * 2 + int(ramp / 15.0)))
        size = rng.uniform(80, 320)
        proto = "TCP" if intensity % 2 == 0 else "UDP"
        flags = "S" if proto == "TCP" else None
    elif scenario_id == "burst_exhaustion":
        if sequence % 3 == 0:
            rate = 32.0 + rng.uniform(-4.0, 4.0)
        else:
            rate = 120.0 + intensity * 45.0 + rng.uniform(-15.0, 25.0)
        sources = int(max(4, 4 + intensity * 2 + rng.randint(0, 3)))
        size = rng.uniform(70, 240)
        proto = "UDP"
        flags = None
    elif scenario_id == "udp_flood":
        rate = 110.0 + (intensity ** 2) * 25.0 + rng.uniform(-15.0, 25.0)
        sources = int(max(6, 6 + intensity * 3 + rng.randint(0, 4)))
        size = rng.uniform(64, 380)
        proto = "UDP"
        flags = None
    elif scenario_id == "syn_flood":
        rate = 95.0 + (intensity ** 2) * 22.0 + rng.uniform(-12.0, 20.0)
        sources = int(max(5, 5 + intensity * 3 + rng.randint(0, 3)))
        size = rng.uniform(60, 180)
        proto = "TCP"
        flags = "S"
    elif scenario_id == "icmp_flood":
        rate = 80.0 + (intensity ** 2) * 18.0 + rng.uniform(-10.0, 15.0)
        sources = int(max(4, 4 + intensity * 2 + rng.randint(0, 3)))
        size = rng.uniform(64, 256)
        proto = "ICMP"
        flags = None
    elif scenario_id == "mixed_vector":
        rate = 90.0 + (intensity ** 2) * 20.0 + rng.uniform(-12.0, 20.0)
        sources = int(max(5, 5 + intensity * 3 + rng.randint(0, 4)))
        size = rng.uniform(80, 420)
        proto = ("UDP", "TCP", "ICMP")[sequence % 3]
        flags = "S" if proto == "TCP" and sequence % 2 == 0 else None
    else:
        raise ValueError(f"Unknown scenario: {scenario_id}")

    packet_count = max(1, round(rate))
    byte_count = round(packet_count * size)
    packet_rate = round(rate, 2)
    byte_rate = round(rate * size, 2)
    packet_size = round(size, 2)

    ev = TelemetryEvent(
        source_type="REALISTIC_BENCHMARK",
        source_id=f"SRC-{sequence % 10:02d}",
        device_id="ATK-01" if not is_normal else f"SENSOR-{(sequence % 5) + 1:02d}",
        timestamp=utc_now(),
        src_ip=f"10.42.0.{(sequence % 50) + 10}",
        dst_ip="10.42.0.1",
        src_port=30000 + sequence % 20000,
        dst_port=5683 if proto == "UDP" else (1883 if proto == "TCP" else None),
        protocol=proto,
        protocol_layer="TRANSPORT",
        packet_count=packet_count,
        byte_count=byte_count,
        packet_rate=packet_rate,
        byte_rate=byte_rate,
        packet_size=packet_size,
        flow_id=f"{scenario_id}-i{intensity}-{sequence}",
        unique_sources=sources,
        unique_destinations=1,
        tcp_flags=flags,
        attack_type=None if is_normal else scenario_id,
        traffic_type="NORMAL" if is_normal else "CONTROLLED_ATTACK_SIMULATION",
        label="NORMAL" if is_normal else "ATTACK",
        scenario_id=scenario_id,
        provenance="REALISTIC_SIMULATION",
    )
    energy_model.correlate(ev)
    return {
        **feature_mapping(ev),
        "label": ev.label,
        "scenario_id": scenario_id,
        "campaign_id": f"{scenario_id}-i{intensity}",
        "intensity": intensity,
        "attack_type": ev.attack_type or "none",
        "provenance": "REALISTIC_SIMULATION",
        "seed": seed,
    }


def generate_realistic_dataset(
    output: Path,
    metadata_output: Path | None = None,
    *,
    seed: int = 20260917,
    samples_per_campaign: int = 40,
) -> dict[str, Any]:
    """Generate realistic benchmark dataset with overlapping rate distributions, legitimate bursts, and noise."""
    energy_model = EnergyModel()
    scenarios = [
        "normal_periodic", "normal_aggregation", "normal_burst", "normal_noisy",
        "slow_stealth", "gradual_ramp", "burst_exhaustion", "udp_flood",
        "syn_flood", "icmp_flood", "mixed_vector"
    ]
    rows: list[dict[str, Any]] = []
    campaigns = 0
    for sc in scenarios:
        for intensity in range(1, 5):
            campaigns += 1
            for seq in range(samples_per_campaign):
                rows.append(_generate_realistic_sample(sc, intensity, seq, seed, energy_model))

    df = pd.DataFrame(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    metadata = {
        "dataset_id": output.stem,
        "dataset_version": REALISTIC_BENCHMARK_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provenance": "REALISTIC_SIMULATION",
        "random_seed": seed,
        "feature_version": FEATURE_VERSION,
        "rows": len(df),
        "campaigns": campaigns,
        "samples_per_campaign": samples_per_campaign,
        "class_distribution": df["label"].value_counts().to_dict(),
        "features": FEATURES,
        "scenarios": scenarios,
        "generation": "realistic benchmark with overlapping rate distributions, legitimate bursts, and noise",
    }
    metadata_output = metadata_output or output.with_suffix(".metadata.json")
    metadata_output.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return metadata


def evaluate_model_on_dataset(
    dataset_path: Path,
    model_bundle_or_path: Path | dict[str, Any],
    report_output: Path | None = None,
) -> dict[str, Any]:
    """Evaluate an existing model bundle on a dataset without refitting."""
    if isinstance(model_bundle_or_path, (str, Path)):
        bundle = joblib.load(model_bundle_or_path)
    else:
        bundle = model_bundle_or_path

    df = pd.read_csv(dataset_path)
    clf = bundle.get("calibrated_classifier") or bundle["classifier"]
    classes = list(clf.classes_)
    attack_index = classes.index("ATTACK") if "ATTACK" in classes else 1

    features_list = bundle.get("features", FEATURES)
    probabilities = clf.predict_proba(df[features_list])[:, attack_index]
    predictions = np.where(probabilities >= 0.50, "ATTACK", "NORMAL")

    metrics_res = _metrics(df["label"], predictions, probabilities)
    report = {
        "evaluation_type": "zero_shot_inference_evaluation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset_path),
        "rows": len(df),
        "class_distribution": df["label"].value_counts().to_dict(),
        "model_version": bundle.get("model_version", "unknown"),
        "model_path": str(model_bundle_or_path) if isinstance(model_bundle_or_path, (str, Path)) else "in_memory_bundle",
        "model_role": "baseline runtime model evaluated zero-shot",
        "baseline_runtime_model": str(model_bundle_or_path) if isinstance(model_bundle_or_path, (str, Path)) else "models/hybrid_detector.joblib",
        "runtime_model_changed": False,
        "metrics": metrics_res,
    }
    if report_output:
        report_output.parent.mkdir(parents=True, exist_ok=True)
        report_output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def train_and_evaluate_realistic(
    dataset_path: Path,
    model_path: Path,
    report_path: Path,
    *,
    seed: int = 20260917,
    held_out_scenario: str = "slow_stealth",
) -> dict[str, Any]:
    """Train and evaluate realistic detector on realistic benchmark with held-out stealth scenario."""
    data = pd.read_csv(dataset_path)
    held_out = data[data["scenario_id"] == held_out_scenario].copy()
    fit_data = data[data["scenario_id"] != held_out_scenario].copy().reset_index(drop=True)

    train_idx, validation_idx, test_idx = _split_groups(fit_data, seed)
    train, validation, test = fit_data.iloc[train_idx], fit_data.iloc[validation_idx], fit_data.iloc[test_idx]

    classifier = RandomForestClassifier(n_estimators=240, min_samples_leaf=2, class_weight="balanced", random_state=seed, n_jobs=-1)
    classifier.fit(train[FEATURES], train["label"])

    scaler = StandardScaler().fit(train[FEATURES])
    anomaly = IsolationForest(n_estimators=200, contamination=0.08, random_state=seed)
    anomaly.fit(scaler.transform(train.loc[train["label"] == "NORMAL", FEATURES]))

    attack_index = list(classifier.classes_).index("ATTACK")

    try:
        from sklearn.frozen import FrozenEstimator
        calibrator = CalibratedClassifierCV(estimator=FrozenEstimator(classifier), method="sigmoid")
    except ImportError:
        calibrator = CalibratedClassifierCV(estimator=classifier, method="sigmoid", cv="prefit")
    calibrator.fit(validation[FEATURES], validation["label"])

    def evaluate(frame: pd.DataFrame, use_calibrated: bool = False) -> dict[str, Any]:
        clf = calibrator if use_calibrated else classifier
        probability = clf.predict_proba(frame[FEATURES])[:, attack_index]
        prediction = np.where(probability >= 0.50, "ATTACK", "NORMAL")
        return _metrics(frame["label"], prediction, probability)

    test_eval = evaluate(test, use_calibrated=True)
    held_out_raw = evaluate(held_out, use_calibrated=True)
    held_out_attacks = int((held_out["label"] == "ATTACK").sum())
    held_out_normal = int((held_out["label"] == "NORMAL").sum())
    held_out_tp = held_out_raw["support"]["ATTACK"] - held_out_raw["false_negatives"]
    held_out_fn = held_out_raw["false_negatives"]
    held_out_attack_recall = float(held_out_tp / held_out_attacks) if held_out_attacks > 0 else 0.0

    held_out_eval = {
        "scenario": held_out_scenario,
        "sample_count": len(held_out),
        "attack_sample_count": held_out_attacks,
        "normal_sample_count": held_out_normal,
        "held_out_attack_recall": held_out_attack_recall,
        "attack_recall": held_out_attack_recall,
        "true_positives": held_out_tp,
        "false_negatives": held_out_fn,
        "attack_precision": float(held_out_raw["precision"]["ATTACK"]),
        "attack_f1": float(held_out_raw["f1"]["ATTACK"]),
        "confusion_matrix": held_out_raw["confusion_matrix"],
        "labels_present": ["ATTACK"],
        "f1": {"ATTACK": float(held_out_raw["f1"]["ATTACK"])},
        "recall": {"ATTACK": held_out_attack_recall},
        "precision": {"ATTACK": float(held_out_raw["precision"]["ATTACK"])},
        "evaluation_note": "The held-out scenario contains only ATTACK samples (160 samples, 0 NORMAL). Therefore, overall accuracy, false-positive rate, and NORMAL metrics are not defined or presented. Metrics represent attack recall on unseen slow_stealth attack mechanics.",
    }

    report = {
        "experiment_id": f"EXP-REALISTIC-{uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset_path),
        "dataset_version": REALISTIC_BENCHMARK_VERSION,
        "feature_version": FEATURE_VERSION,
        "model_version": "realistic-rf-if-v1",
        "model_role": "realistic benchmark evaluation model",
        "baseline_runtime_model": "models/hybrid_detector.joblib",
        "realistic_evaluation_model": str(model_path),
        "runtime_model_changed": False,
        "random_seed": seed,
        "provenance": "REALISTIC_SIMULATION",
        "evaluation_protocol": "campaign-grouped train/val/test with held-out stealth scenario",
        "held_out_scenario": held_out_scenario,
        "splits": {
            "train": len(train),
            "validation": len(validation),
            "test": len(test),
            "scenario_held_out": len(held_out),
        },
        "test": test_eval,
        "scenario_held_out": held_out_eval,
        "feature_importance": {
            feature: float(value)
            for feature, value in sorted(
                zip(FEATURES, classifier.feature_importances_),
                key=lambda pair: pair[1],
                reverse=True,
            )
        },
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "classifier": classifier,
        "calibrated_classifier": calibrator,
        "anomaly": anomaly,
        "anomaly_scaler": scaler,
        "features": FEATURES,
        "model_version": "realistic-rf-if-v1",
        "feature_version": FEATURE_VERSION,
        "training_seed": seed,
        "calibrated": True,
        "training_dataset": str(dataset_path),
    }, model_path)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Aegis Gateway ML training and evaluation")
    parser.add_argument("--dataset", type=Path, default=Path("data/datasets/synthetic_lab_v2.csv"))
    parser.add_argument("--model", type=Path, default=Path("models/hybrid_detector.joblib"))
    parser.add_argument("--report", type=Path, default=Path("reports/evaluation.json"))
    parser.add_argument("--seed", type=int, default=20260913)
    parser.add_argument("--generate", action="store_true", help="Generate synthetic dataset first")
    parser.add_argument("--realistic", action="store_true", help="Generate and evaluate realistic benchmark")
    args = parser.parse_args()

    if args.realistic:
        ds = Path("data/datasets/realistic_benchmark_v1.csv")
        mod = Path("models/realistic_detector_v1.joblib")
        rep = Path("reports/realistic_evaluation.json")
        print(f"Generating realistic benchmark at {ds}...")
        generate_realistic_dataset(ds, seed=20260917)
        print("Evaluating baseline model on realistic benchmark...")
        evaluate_model_on_dataset(ds, args.model, Path("reports/baseline_on_realistic_benchmark.json"))
        print(f"Training realistic detector at {mod}...")
        res = train_and_evaluate_realistic(ds, mod, rep, seed=20260917)
        print(f"Realistic model saved to {mod}, report to {rep}")
        print(f"Realistic Test F1 (ATTACK): {res['test']['f1']['ATTACK']:.4f}")
        print(f"Held-out Stealth Attack Recall: {res['scenario_held_out']['held_out_attack_recall']:.4f}")
    else:
        if args.generate or not args.dataset.exists():
            print(f"Generating synthetic dataset at {args.dataset}...")
            meta_path = args.dataset.with_name(args.dataset.stem + ".metadata.json")
            generate_dataset(args.dataset, meta_path, seed=args.seed)

        print(f"Training and evaluating model on {args.dataset}...")
        res = train_and_evaluate(args.dataset, args.model, args.report, seed=args.seed)
        print(f"Model saved to {args.model}")
        print(f"Report saved to {args.report}")
        print(f"Test F1: {res['test']['f1']['ATTACK']:.4f}, Brier: {res['calibration']['brier_score_calibrated']:.6f}")
