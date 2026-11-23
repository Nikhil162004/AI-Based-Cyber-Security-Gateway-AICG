"""Compatibility launcher for the unified AEGIS-OT gateway API/HMI."""

import os
import sys
from pathlib import Path

# Ensure backend directory and repository root are on sys.path for direct launcher execution
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(1, str(PROJECT_ROOT))

# Enable dev auto auth by default so operations console runs seamlessly out of the box
os.environ.setdefault("AEGIS_DEV_AUTO_AUTH", "1")

from aegis_gateway.api import create_app
from aegis_gateway.runtime import GatewayRuntime

runtime = GatewayRuntime()
runtime.start_baseline()
app = create_app(runtime)

if __name__ == "__main__":
    host = os.environ.get("AEGIS_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT") or os.environ.get("AEGIS_PORT", 8000))
    app.run(host=host, port=port, debug=False, threaded=True)
