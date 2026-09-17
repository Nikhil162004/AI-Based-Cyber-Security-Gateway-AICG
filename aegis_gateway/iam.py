"""Lightweight deterministic IAM and trust governance context for an edge gateway."""

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
    mfa_status: str = "NOT_REQUIRED"  # Simulated MFA: NOT_REQUIRED, REQUIRED, VERIFIED, FAILED


@dataclass
class IAMService:
    """Zero-trust IAM, simulated MFA, and dynamic reputation engine.

    Enforces distinct authentication (who the entity is), simulated MFA verification,
    authorization (access control), and dynamic trust reputation (bounded 0..100).
    """

    identities: dict[str, Identity] = field(default_factory=lambda: {
        "SENSOR-01": Identity("SENSOR-01", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED"),
        "SENSOR-02": Identity("SENSOR-02", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED"),
        "SENSOR-03": Identity("SENSOR-03", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED"),
        "SENSOR-GROUP-A": Identity("SENSOR-GROUP-A", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED"),
        "ATK-01": Identity("ATK-01", "untrusted", authenticated=False, trust_score=35.0, mfa_status="FAILED"),
        "operator": Identity("operator", "operator", authenticated=True, trust_score=100.0, mfa_status="VERIFIED"),
    })

    def get(self, identity: str | None) -> Identity:
        name = identity or "UNKNOWN"
        if name not in self.identities:
            if name.startswith("SENSOR-"):
                self.identities[name] = Identity(name, "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED")
            else:
                mfa = "FAILED" if name.startswith("ATK") else ("REQUIRED" if "operator" in name.lower() else "NOT_REQUIRED")
                self.identities[name] = Identity(name, "unknown", authenticated=False, trust_score=45.0, mfa_status=mfa)
        return self.identities[name]

    def reset_identities(self) -> None:
        """Reset identity reputation to clean baseline state."""
        for name, ident in self.identities.items():
            if name.startswith("SENSOR-") or name == "operator":
                ident.trust_score = 100.0
                ident.failures = 0
            elif name.startswith("ATK"):
                ident.trust_score = 35.0
                ident.failures = 0

    def access(self, identity: str | None, resource: str = "gateway:telemetry") -> dict[str, Any]:
        item = self.get(identity)
        if not item.authenticated:
            allowed = False
            reason = "Authentication unverified or failed"
        elif item.role == "untrusted":
            allowed = False
            reason = "Untrusted role policy boundary"
        elif item.trust_score < 40.0:
            allowed = False
            reason = f"Trust score ({item.trust_score:.1f}) below minimum policy threshold (40.0)"
        else:
            allowed = True
            reason = f"Authenticated role '{item.role}' with valid trust score ({item.trust_score:.1f})"

        return {
            "identity": item.identity,
            "role": item.role,
            "authentication_status": "AUTHENTICATED" if item.authenticated else "FAILED_OR_UNVERIFIED",
            "mfa_status": item.mfa_status,
            "authorization_status": "AUTHORIZED" if allowed else "DENIED",
            "access_request": resource,
            "decision": "ALLOW" if allowed else "DENY",
            "reason": reason,
        }

    def adjust_trust(self, identity: str | None, *, attack: bool, auth_failure: bool = False, recovered: bool = False) -> tuple[Identity, float, str]:
        item = self.get(identity)
        prev_score = item.trust_score

        if auth_failure:
            item.failures += 1
            delta, reason = -15.0, "authentication failure"
        elif attack:
            delta, reason = -20.0, "suspicious traffic detection"
        elif recovered and item.trust_score < 100.0:
            delta, reason = 3.0, "observed recovery toward baseline"
        else:
            delta, reason = 0.0, "normal operational baseline maintained"

        new_score = max(0.0, min(100.0, round(prev_score + delta, 2)))
        effective_delta = round(new_score - prev_score, 2)
        item.trust_score = new_score
        return item, effective_delta, reason
