"""Backward-compatibility shim redirecting to backend/app.py."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

# Ensure backend directory and repository root are on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(1, str(PROJECT_ROOT))

backend_app = BACKEND_DIR / "app.py"

if __name__ == "__main__":
    runpy.run_path(str(backend_app), run_name="__main__")
else:
    _exported = runpy.run_path(str(backend_app), run_name=__name__)
    app = _exported.get("app")
    runtime = _exported.get("runtime")
    create_app = _exported.get("create_app")
    GatewayRuntime = _exported.get("GatewayRuntime")
    __all__ = ["app", "runtime", "create_app", "GatewayRuntime"]
