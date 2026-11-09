"""Phase A1 — Focused Tests for Runtime ML Model Configurability (AEGIS_MODEL_PATH).

Verifies:
1. Default behavior remains models/hybrid_detector.joblib when AEGIS_MODEL_PATH is unset.
2. AEGIS_MODEL_PATH selects a valid alternate model (e.g. realistic_detector_v1.joblib)
   via relative and absolute paths.
3. Empty/whitespace AEGIS_MODEL_PATH safely falls back to hybrid_detector.joblib.
4. Nonexistent model path fails safely: runtime initializes without crashing,
   falls back to rules-v2-untrained, and continues processing traffic safely.
5. Corrupted model file fails clearly: deserialization raises an explicit exception.
6. Non-classifier joblib payload fails safely: rejected and falls back to rules.
7. Explicit model_path keyword argument overrides environment variable.
"""

from pathlib import Path
import joblib
import pytest

from aegis_gateway.config import Settings
from aegis_gateway.detection import HybridDetector
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window


def test_default_model_path_is_hybrid_detector(monkeypatch):
    """Default runtime model must remain models/hybrid_detector.joblib."""
    monkeypatch.delenv("AEGIS_MODEL_PATH", raising=False)
    settings = Settings()
    expected_default = settings.root / "models" / "hybrid_detector.joblib"
    assert settings.model_path == expected_default
    assert settings.model_path.exists(), "Default model bundle must exist on disk"

    runtime = GatewayRuntime(settings)
    assert runtime.detector.bundle is not None
    assert runtime.detector.model_version == "hybrid-rf-if-v2"
    assert runtime.status()["model_version"] == "hybrid-rf-if-v2"


def test_aegis_model_path_override_relative_path(monkeypatch):
    """AEGIS_MODEL_PATH selects alternate model using a relative path."""
    monkeypatch.setenv("AEGIS_MODEL_PATH", "models/realistic_detector_v1.joblib")
    settings = Settings()
    expected_path = settings.root / "models" / "realistic_detector_v1.joblib"
    assert settings.model_path == expected_path
    assert settings.model_path.exists(), "Realistic detector model must exist on disk"

    runtime = GatewayRuntime(settings)
    assert runtime.detector.bundle is not None
    assert runtime.detector.model_version == "realistic-rf-if-v1"
    assert runtime.status()["model_version"] == "realistic-rf-if-v1"

    # Verify inference executes properly with the loaded alternate model
    norm_ev = generate_window("normal", intensity=1, sequence=0)
    dec_norm = runtime.detector.analyze(norm_ev)
    assert dec_norm.prediction == "NORMAL"
    assert dec_norm.severity == "INFO"

    atk_ev = generate_window("udp_flood", intensity=4, sequence=0)
    dec_atk = runtime.detector.analyze(atk_ev)
    assert dec_atk.prediction == "ATTACK"
    assert dec_atk.severity in ("HIGH", "CRITICAL")


def test_aegis_model_path_override_absolute_path(monkeypatch):
    """AEGIS_MODEL_PATH selects alternate model using an absolute path."""
    target = (Settings().root / "models" / "realistic_detector_v1.joblib").resolve()
    assert target.exists()
    monkeypatch.setenv("AEGIS_MODEL_PATH", str(target))

    settings = Settings()
    assert settings.model_path == target
    assert settings.model_path.is_absolute()

    runtime = GatewayRuntime(settings)
    assert runtime.detector.bundle is not None
    assert runtime.detector.model_version == "realistic-rf-if-v1"
    assert runtime.status()["model_version"] == "realistic-rf-if-v1"


def test_aegis_model_path_empty_or_whitespace_uses_default(monkeypatch):
    """Empty or whitespace AEGIS_MODEL_PATH safely preserves default model."""
    for empty_val in ("", "   ", "\t\n"):
        monkeypatch.setenv("AEGIS_MODEL_PATH", empty_val)
        settings = Settings()
        assert settings.model_path == settings.root / "models" / "hybrid_detector.joblib"
        runtime = GatewayRuntime(settings)
        assert runtime.detector.model_version == "hybrid-rf-if-v2"


def test_invalid_model_path_nonexistent_fails_safely(monkeypatch):
    """Nonexistent model path fails safely: falls back to rule engine without crashing."""
    monkeypatch.setenv("AEGIS_MODEL_PATH", "/nonexistent/path/to/missing_detector.joblib")
    settings = Settings()
    assert settings.model_path == Path("/nonexistent/path/to/missing_detector.joblib")
    assert not settings.model_path.exists()

    runtime = GatewayRuntime(settings)
    assert runtime.detector.bundle is None
    assert runtime.detector.model_version == "rules-v2-untrained"
    assert runtime.status()["model_version"] == "rules-v2-untrained"

    # Gateway remains fully functional using explainable rules
    norm_ev = generate_window("normal", intensity=1, sequence=0)
    dec_norm = runtime.detector.analyze(norm_ev)
    assert dec_norm.prediction == "NORMAL"

    atk_ev = generate_window("udp_flood", intensity=4, sequence=0)
    dec_atk = runtime.detector.analyze(atk_ev)
    assert dec_atk.prediction == "ATTACK"


def test_invalid_model_path_corrupt_fails_clearly(tmp_path: Path, monkeypatch):
    """Corrupted model file fails clearly: raises explicit deserialization exception."""
    corrupt_file = tmp_path / "corrupt_detector.joblib"
    corrupt_file.write_bytes(b"INVALID_HEADER_NOT_A_PICKLE_OR_JOBLIB_STREAM\x00\xff")
    monkeypatch.setenv("AEGIS_MODEL_PATH", str(corrupt_file))

    settings = Settings()
    assert settings.model_path == corrupt_file
    assert settings.model_path.exists()

    with pytest.raises(Exception):
        HybridDetector(settings.model_path)


def test_invalid_model_bundle_missing_classifier_fails_safely(tmp_path: Path, monkeypatch):
    """Joblib file missing classifier structure is rejected and falls back safely to rules."""
    dummy_file = tmp_path / "not_a_model.joblib"
    joblib.dump({"version": "1.0", "data": [1, 2, 3]}, dummy_file)
    monkeypatch.setenv("AEGIS_MODEL_PATH", str(dummy_file))

    settings = Settings()
    detector = HybridDetector(settings.model_path)
    assert detector.bundle is None
    assert detector.model_version == "rules-v2-untrained"


def test_explicit_model_path_kwarg_overrides_env(monkeypatch):
    """Explicit model_path argument passed to Settings overrides AEGIS_MODEL_PATH."""
    monkeypatch.setenv("AEGIS_MODEL_PATH", "models/realistic_detector_v1.joblib")
    forced_default = Settings().root / "models" / "hybrid_detector.joblib"

    settings = Settings(model_path=forced_default)
    assert settings.model_path == forced_default

    runtime = GatewayRuntime(settings)
    assert runtime.detector.model_version == "hybrid-rf-if-v2"
