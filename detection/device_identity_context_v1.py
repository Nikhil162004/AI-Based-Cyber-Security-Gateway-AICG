#!/usr/bin/env python3

"""
AI-Edge Security Gateway
Device Identity Context V1

Purpose:
    Resolve lightweight device identity/security context for the
    gateway/dashboard aggregation layer.

Important:
    This module is a LOCAL CONTEXT RESOLVER.

It is NOT:
    - an enterprise IAM platform
    - an authentication server
    - an LDAP/Active Directory replacement
    - a cryptographic identity verifier
    - a packet enforcement mechanism
    - a firewall controller
    - a device isolation mechanism

The module must remain outside the frozen ML feature contracts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_FILE = (
    PROJECT_ROOT
    / "detection"
    / "device_identity_registry_v1.json"
)


DEFAULT_CONTEXT = {
    "device_id": "unknown-device",
    "device_role": "UNKNOWN",
    "ip_address": "",
    "identity_status": "UNKNOWN",
    "authentication_status": "NOT_VERIFIED",
    "authorization_decision": "UNKNOWN",
    "trust_score": 0.0,
    "failed_attempts": 0,
    "suspicious": False,
    "session_state": "UNKNOWN",
}


def load_registry(path: Path = REGISTRY_FILE) -> dict[str, Any]:
    """Load and validate the local device registry."""

    if not path.exists():
        raise FileNotFoundError(
            f"Device identity registry not found: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        registry = json.load(handle)

    if not isinstance(registry, dict):
        raise ValueError("Device identity registry must be a JSON object")

    devices = registry.get("devices")

    if not isinstance(devices, list):
        raise ValueError("Registry 'devices' must be a list")

    return registry


def _normalize_device(device: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized device context."""

    context = DEFAULT_CONTEXT.copy()

    for key in context:
        if key in device:
            context[key] = device[key]

    context["trust_score"] = float(context["trust_score"])
    context["failed_attempts"] = int(context["failed_attempts"])
    context["suspicious"] = bool(context["suspicious"])

    return context


def resolve_device_context(
    ip_address: str | None,
    registry_path: Path = REGISTRY_FILE,
) -> dict[str, Any]:
    """
    Resolve a device context using an observed IP address.

    Unknown addresses receive an explicit UNKNOWN context rather
    than being assigned a fabricated identity.
    """

    normalized_ip = str(ip_address or "").strip()

    registry = load_registry(registry_path)

    for device in registry["devices"]:
        if not isinstance(device, dict):
            continue

        if str(device.get("ip_address", "")).strip() == normalized_ip:
            context = _normalize_device(device)
            context["ip_address"] = normalized_ip
            return context

    context = DEFAULT_CONTEXT.copy()
    context["ip_address"] = normalized_ip

    return context


def resolve_many(
    ip_addresses: list[str],
    registry_path: Path = REGISTRY_FILE,
) -> list[dict[str, Any]]:
    """Resolve multiple observed IP addresses."""

    return [
        resolve_device_context(
            ip_address,
            registry_path=registry_path,
        )
        for ip_address in ip_addresses
    ]


def main() -> None:
    """Run a deterministic standalone module test."""

    print("=" * 70)
    print("DEVICE IDENTITY CONTEXT V1")
    print("=" * 70)

    known = resolve_device_context("127.0.0.1")
    unknown = resolve_device_context("192.0.2.10")

    print("\nKnown device:")
    print(json.dumps(known, indent=2))

    print("\nUnknown device:")
    print(json.dumps(unknown, indent=2))

    print("\nModule test complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
