"""Compatibility launcher for the unified AEGIS-OT gateway API/HMI."""

import sys
from pathlib import Path

# Ensure repository root is on sys.path for direct launcher execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis_gateway.api import create_app
from aegis_gateway.runtime import GatewayRuntime

runtime = GatewayRuntime()
runtime.start_baseline()
app = create_app(runtime)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False, threaded=True)
