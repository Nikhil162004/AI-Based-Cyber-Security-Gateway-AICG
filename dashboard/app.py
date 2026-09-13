"""Compatibility launcher for the unified AEGIS-OT gateway API/HMI."""

from aegis_gateway.api import create_app
from aegis_gateway.runtime import GatewayRuntime

app = create_app(GatewayRuntime())

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False, threaded=True)
