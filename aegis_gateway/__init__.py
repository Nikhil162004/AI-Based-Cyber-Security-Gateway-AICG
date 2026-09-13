"""AEGIS-OT laboratory gateway package.

This package deliberately separates observed packet data from simulation and
model output.  It is a demonstration gateway, not a host firewall.
"""

from .config import Settings
from .runtime import GatewayRuntime

__all__ = ["GatewayRuntime", "Settings"]
