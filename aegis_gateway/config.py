"""Repository-relative configuration with safe demonstration defaults."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Settings intentionally exclude host-enforcement configuration."""

    root: Path = ROOT
    database_path: Path = Path(os.getenv("AEGIS_DATABASE_PATH", str(ROOT / "data" / "aegis_gateway.sqlite3")))
    model_path: Path = ROOT / "models" / "hybrid_detector.joblib"
    report_dir: Path = ROOT / "reports"
    dataset_dir: Path = ROOT / "data" / "datasets"
    event_retention_days: int = int(os.getenv("AEGIS_RETENTION_DAYS", "30"))
    demo_tick_seconds: float = float(os.getenv("AEGIS_DEMO_TICK_SECONDS", "1.0"))
    response_mode: str = os.getenv("AEGIS_RESPONSE_MODE", "DRY_RUN").upper()
    auto_response: bool = _bool("AEGIS_AUTO_RESPONSE", True)
    host: str = os.getenv("AEGIS_HOST", "127.0.0.1")
    port: int = int(os.getenv("AEGIS_PORT", "8000"))
    secret_key: str = os.getenv("AEGIS_SECRET_KEY", "aicg-edge-gateway-lab-secret-key-2026")
    session_cookie_secure: bool = _bool("AEGIS_SESSION_COOKIE_SECURE", False)
    auth_rate_limit_max: int = int(os.getenv("AEGIS_AUTH_RATE_LIMIT_MAX", "10"))
    auth_rate_limit_window_seconds: int = int(os.getenv("AEGIS_AUTH_RATE_LIMIT_WINDOW", "60"))

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

