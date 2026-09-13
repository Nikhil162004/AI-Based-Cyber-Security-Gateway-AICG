"""Tests for detection engine, feature extraction, ML training, evaluation, and calibration."""

from pathlib import Path
import pytest
from aegis_gateway.config import Settings
from aegis_gateway.detection import FEATURES, HybridDetector, feature_mapping
from aegis_gateway.ml import generate_dataset, train_and_evaluate
from aegis_gateway.scenarios import generate_window


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

    norm_ev = generate_window("normal", intensity=1, sequence=0)
    dec_norm = detector.analyze(norm_ev)
    assert dec_norm.prediction == "NORMAL"
    assert dec_norm.calibrated_probability is not None
    assert dec_norm.calibrated_probability < 0.20

    atk_ev = generate_window("udp_flood", intensity=3, sequence=0)
    dec_atk = detector.analyze(atk_ev)
    assert dec_atk.prediction == "ATTACK"
    assert dec_atk.calibrated_probability is not None
    assert dec_atk.calibrated_probability > 0.80
