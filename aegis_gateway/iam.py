"""Lightweight deterministic IAM and trust context for a laboratory gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Identity:
    identity: str
    role: str
    authenticated: bool = True
    trust_score: float = 100.0
    failures: int = 0


@dataclass
class IAMService:
    identities: dict[str, Identity] = field(default_factory=lambda: {
        "SENSOR-01": Identity("SENSOR-01", "sensor"), "SENSOR-GROUP-A": Identity("SENSOR-GROUP-A", "sensor"),
        "ATK-01": Identity("ATK-01", "untrusted", False, 35.0), "operator": Identity("operator", "operator"),
    })

    def get(self, identity: str | None) -> Identity:
        name = identity or "UNKNOWN"
        if name not in self.identities:
            self.identities[name] = Identity(name, "unknown", False, 45.0)
        return self.identities[name]

    def access(self, identity: str | None, resource: str = "gateway:telemetry") -> dict[str, Any]:
        item = self.get(identity)
        allowed = item.authenticated and item.role != "untrusted" and item.trust_score >= 40
        return {"identity": item.identity, "role": item.role, "authentication_status": "AUTHENTICATED" if item.authenticated else "FAILED_OR_UNVERIFIED",
                "authorization_status": "AUTHORIZED" if allowed else "DENIED", "access_request": resource,
                "decision": "ALLOW" if allowed else "DENY", "reason": "role/trust policy"}

    def adjust_trust(self, identity: str | None, *, attack: bool, auth_failure: bool = False, recovered: bool = False) -> tuple[Identity, float, str]:
        item = self.get(identity)
        delta, reason = (0.0, "No trust change")
        if auth_failure:
            item.failures += 1; delta, reason = -15.0, "authentication failure"
        elif attack:
            delta, reason = -20.0, "suspicious traffic detection"
        elif recovered and item.trust_score < 100:
            delta, reason = 3.0, "observed recovery toward baseline"
        item.trust_score = max(0.0, min(100.0, round(item.trust_score + delta, 2)))
        return item, delta, reason
