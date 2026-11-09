"""Tests for detection engine, feature extraction, ML training, evaluation, and calibration."""

import copy
from pathlib import Path
import pytest
from aegis_gateway.config import Settings
from aegis_gateway.detection import FEATURES, HybridDetector, feature_mapping
from aegis_gateway.energy import EnergyModel
from aegis_gateway.ml import generate_dataset, train_and_evaluate
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import CATALOGUE, generate_window


def test_feature_mapping_completeness():
    event = generate_window("syn_flood", intensity=3, sequence=0)
    mapping = feature_mapping(event)
    for feat in FEATURES:
        assert feat in mapping
        assert isinstance(mapping[feat], (int, float))
    assert mapping["syn_ratio"] == 1.0
    assert mapping["tcp_ratio"] == 1.0


def test_rule_based_detection_untrained():
    # Detector without model bundle falls back on rules
    detector = HybridDetector(model_path=None)
    assert detector.model_version == "rules-v2-untrained"

    normal_event = generate_window("normal", intensity=1, sequence=0)
    decision = detector.analyze(normal_event)
    assert decision.prediction == "NORMAL"
    assert decision.severity == "INFO"

    attack_event = generate_window("udp_flood", intensity=4, sequence=0)
    decision = detector.analyze(attack_event)
    assert decision.prediction == "ATTACK"
    assert decision.severity in ("HIGH", "CRITICAL")
    assert len(decision.evidence) > 0


def test_dataset_generation_and_evaluation(tmp_path: Path):
    ds_path = tmp_path / "test_dataset.csv"
    meta_path = tmp_path / "test_dataset.metadata.json"
    model_path = tmp_path / "test_model.joblib"
    report_path = tmp_path / "test_report.json"

    meta = generate_dataset(ds_path, meta_path, samples_per_campaign=10, seed=12345)
    assert ds_path.exists()
    assert meta_path.exists()
    assert meta["rows"] > 0
    assert "NORMAL" in meta["class_distribution"]
    assert "ATTACK" in meta["class_distribution"]

    report = train_and_evaluate(ds_path, model_path, report_path, seed=12345, held_out_scenario="mixed_vector")
    assert model_path.exists()
    assert report_path.exists()
    assert "test" in report
    assert "validation" in report
    assert "scenario_held_out" in report

    # Test set metrics
    test_metrics = report["test"]
    assert test_metrics["samples"] > 0
    assert test_metrics["confusion_matrix"] is not None
    assert test_metrics["f1"]["ATTACK"] > 0.8
    assert test_metrics["false_positive_rate"] is not None
    assert test_metrics["false_negative_rate"] is not None
    assert "roc_auc" in test_metrics

    # Calibration
    assert "calibration" in report
    assert report["calibration"]["calibrated"] is True


def test_hybrid_detector_with_trained_bundle():
    settings = Settings()
    if not settings.model_path.exists():
        pytest.skip("Model bundle not yet generated at default path")

    detector = HybridDetector(settings.model_path)
    assert detector.bundle is not None
    assert detector.model_version == "hybrid-rf-if-v2"
    energy_model = EnergyModel()

    norm_ev = energy_model.correlate(generate_window("normal", intensity=1, sequence=0))
    dec_norm = detector.analyze(norm_ev)
    assert dec_norm.prediction == "NORMAL"
    assert dec_norm.calibrated_probability is not None
    assert dec_norm.calibrated_probability < 0.20

    atk_ev = energy_model.correlate(generate_window("udp_flood", intensity=3, sequence=0))
    dec_atk = detector.analyze(atk_ev)
    assert dec_atk.prediction == "ATTACK"
    assert dec_atk.calibrated_probability is not None
    assert dec_atk.calibrated_probability > 0.80


def test_attack_metadata_cannot_force_detection():
    """Requirement A: event.attack_type must not influence inference decisions."""
    settings = Settings()
    trained_detector = HybridDetector(settings.model_path if settings.model_path.exists() else None)
    untrained_detector = HybridDetector(model_path=None)
    energy_model = EnergyModel()

    # 1. Benign observable telemetry with injected attack metadata MUST NOT trigger ATTACK
    normal_ev = energy_model.correlate(generate_window("normal", intensity=1, sequence=0))
    spoofed_ev = copy.deepcopy(normal_ev)
    spoofed_ev.attack_type = "udp_flood"

    for det in [trained_detector, untrained_detector]:
        dec_normal = det.analyze(normal_ev)
        dec_spoofed = det.analyze(spoofed_ev)
        assert dec_normal.prediction == "NORMAL"
        assert dec_spoofed.prediction == "NORMAL"
        assert dec_spoofed.score == dec_normal.score
        assert dec_spoofed.severity == dec_normal.severity

    # 2. Attack telemetry with attack_type vs attack_type=None must yield identical decision scores
    atk_ev = energy_model.correlate(generate_window("udp_flood", intensity=4, sequence=0))
    unlabeled_atk = copy.deepcopy(atk_ev)
    unlabeled_atk.attack_type = None

    for det in [trained_detector, untrained_detector]:
        dec_labeled = det.analyze(atk_ev)
        dec_unlabeled = det.analyze(unlabeled_atk)
        assert dec_labeled.prediction == "ATTACK"
        assert dec_unlabeled.prediction == "ATTACK"
        assert dec_labeled.score == dec_unlabeled.score
        assert dec_labeled.severity == dec_unlabeled.severity


def test_unlabeled_attack_scenarios_remain_detectable():
    """Requirement B: All attack scenarios remain detectable when attack_type=None."""
    settings = Settings()
    if not settings.model_path.exists():
        pytest.skip("Model bundle not yet generated at default path")

    detector = HybridDetector(settings.model_path)
    energy_model = EnergyModel()
    for sc_id, sc in CATALOGUE.items():
        if sc_id == "normal":
            continue
        ev = energy_model.correlate(generate_window(sc_id, intensity=sc.intensity_range[0], sequence=0))
        ev.attack_type = None  # Strip ground truth simulation metadata
        dec = detector.analyze(ev)
        assert dec.prediction == "ATTACK", f"Scenario {sc_id} not detected when unlabeled"
        assert dec.score >= 0.50, f"Scenario {sc_id} score {dec.score} < 0.50 when unlabeled"


def test_normal_telemetry_remains_normal():
    """Requirement C: Normal telemetry remains NORMAL across sequences."""
    settings = Settings()
    detector = HybridDetector(settings.model_path if settings.model_path.exists() else None)
    energy_model = EnergyModel()
    for seq in range(10):
        ev = energy_model.correlate(generate_window("normal", intensity=1, sequence=seq))
        dec = detector.analyze(ev)
        assert dec.prediction == "NORMAL"
        assert dec.score < 0.50


def test_ml_feature_schema_strictly_15_features():
    """Requirement D: Feature schema remains exactly 15 features without attack_type."""
    assert len(FEATURES) == 15
    assert "attack_type" not in FEATURES
    assert "label" not in FEATURES
    assert "scenario_id" not in FEATURES

    settings = Settings()
    if settings.model_path.exists():
        detector = HybridDetector(settings.model_path)
        assert detector.bundle is not None
        assert len(detector.bundle["features"]) == 15
        assert list(detector.bundle["features"]) == FEATURES


def test_downstream_campaign_and_incident_attack_type_preservation(tmp_path: Path):
    """Requirement E: Downstream incident storage and campaign grouping retain attack_type."""
    settings = Settings(database_path=tmp_path / "test_downstream.sqlite3")
    runtime = GatewayRuntime(settings=settings)

    atk_ev = generate_window("slow_rate", intensity=2, sequence=0)
    assert atk_ev.attack_type == "slow_rate"

    res = runtime.ingest(atk_ev)
    assert res["decision"]["prediction"] == "ATTACK"
    assert res["incident"] is not None
    assert res["incident"]["attack_type"] == "slow_rate"
    # Policy dispatches RATE_LIMIT based on event.attack_type for non-critical attacks
    assert res["response"]["action"] == "RATE_LIMIT"

    # Campaign correlation by device_id and attack_type
    active = runtime.store.find_active_incident(device_id=atk_ev.device_id, attack_type="slow_rate")
    assert active is not None
    assert active["incident_id"] == res["incident"]["incident_id"]


def test_dataset_energy_variation(tmp_path: Path):
    """Wave 2 Requirement A: Synthetic dataset generation produces non-zero variance for energy fields."""
    import pandas as pd
    ds_path = tmp_path / "energy_test_ds.csv"
    meta = generate_dataset(ds_path, samples_per_campaign=5, seed=42)
    assert ds_path.exists()
    df = pd.read_csv(ds_path)
    for col in ["cpu_activity", "memory_activity", "energy_deviation"]:
        assert col in df.columns
        assert float(df[col].std()) > 0.0, f"Column {col} has zero standard deviation"
        assert float(df[col].max()) > float(df[col].min()), f"Column {col} has no range"


def test_training_events_energy_correlation():
    """Wave 2 Requirement B: EnergyModel correlation populates energy features prior to mapping."""
    em = EnergyModel()
    ev = generate_window("normal", intensity=1, sequence=0)
    assert ev.cpu_activity is None
    assert ev.energy_deviation is None
    em.correlate(ev)
    assert ev.cpu_activity is not None and ev.cpu_activity > 0
    assert ev.memory_activity is not None and ev.memory_activity > 0
    assert ev.energy_deviation is not None
    mapping = feature_mapping(ev)
    assert mapping["cpu_activity"] == ev.cpu_activity
    assert mapping["memory_activity"] == ev.memory_activity
    assert mapping["energy_deviation"] == ev.energy_deviation


def test_energy_feature_importance_non_zero():
    """Wave 2 Requirement E: Model bundle has non-zero feature importance for energy-related features."""
    settings = Settings()
    if not settings.model_path.exists():
        pytest.skip("Model bundle not yet generated at default path")
    detector = HybridDetector(settings.model_path)
    assert detector.bundle is not None
    classifier = detector.bundle["classifier"]
    importances = dict(zip(detector.bundle["features"], classifier.feature_importances_))
    for col in ["cpu_activity", "memory_activity", "energy_deviation"]:
        assert importances[col] > 0.05, f"Energy feature {col} importance is too low: {importances[col]}"
