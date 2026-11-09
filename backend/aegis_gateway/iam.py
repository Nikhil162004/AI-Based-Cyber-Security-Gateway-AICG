"""Lightweight deterministic IAM and trust governance context for an edge gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import os
import threading
import time
from typing import Any

from .config import LAB_MASTER_KEY_FALLBACK
from .schema import utc_now

DEFAULT_MASTER_KEY = os.getenv("AEGIS_MASTER_KEY") or os.getenv("AEGIS_DEVICE_MASTER_KEY") or LAB_MASTER_KEY_FALLBACK
TOKEN_EXPIRATION_SECONDS = 300.0  # 5-minute replay window


class TokenReplayCache:
    """Thread-safe, bounded, in-memory process-local replay protection cache.

    Stores cryptographic SHA-256 digests of valid authentication tokens along with their
    expiration horizons. Never persists or exposes plaintext tokens. Upon process restart,
    this cache resets; freshness drift windows prevent replay of tokens older than the
    expiration window.
    """

    def __init__(self, max_size: int = 10000, default_retention_seconds: float = TOKEN_EXPIRATION_SECONDS):
        self._lock = threading.Lock()
        self._entries: dict[str, float] = {}  # token_hash -> expiry_monotonic
        self._max_size = max(10, int(max_size))
        self._retention_seconds = float(default_retention_seconds)

    def check_and_record(
        self,
        device_id: str,
        token: str,
        token_timestamp: str | None = None,
        retention_seconds: float | None = None,
    ) -> tuple[bool, str]:
        """Check whether the token has already been seen. If not, record its SHA-256 fingerprint.

        Returns (True, 'Token accepted') if fresh, or (False, 'Authentication token replayed; duplicate token rejected')
        if replayed.
        """
        if not token:
            return False, "Missing token"

        retention = float(retention_seconds or self._retention_seconds)
        # Store strictly a SHA-256 digest binding device_id and token - never plaintext token
        digest = hashlib.sha256(f"{device_id}:{token}".encode("utf-8")).hexdigest()
        now_mono = time.monotonic()
        expires_at = now_mono + retention

        with self._lock:
            # 1. Check if token fingerprint already in cache and unexpired
            prev_expiry = self._entries.get(digest)
            if prev_expiry is not None and prev_expiry > now_mono:
                return False, "Authentication token replayed; duplicate token rejected"

            # 2. Prune expired entries if table is growing
            if len(self._entries) >= self._max_size:
                self._prune_expired(now_mono)
                # If still at max capacity, evict oldest 10%
                if len(self._entries) >= self._max_size:
                    sorted_items = sorted(self._entries.items(), key=lambda item: item[1])
                    evict_count = max(1, len(sorted_items) // 10)
                    for key, _ in sorted_items[:evict_count]:
                        self._entries.pop(key, None)

            # 3. Record new fingerprint
            self._entries[digest] = expires_at
            return True, "Token accepted"

    def _prune_expired(self, now_mono: float) -> None:
        expired_keys = [k for k, exp in self._entries.items() if exp <= now_mono]
        for k in expired_keys:
            self._entries.pop(k, None)

    def clear(self) -> None:
        """Clear all cached fingerprints."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __repr__(self) -> str:
        return f"<TokenReplayCache size={len(self)} max_size={self._max_size}>"

    def __str__(self) -> str:
        return self.__repr__()


DEFAULT_REPLAY_CACHE = TokenReplayCache()


def derive_device_key(device_id: str, master_key: str | None = None) -> str:
    """Derive a deterministic per-device preshared key using HMAC-SHA256."""
    eff_key = master_key if master_key is not None else DEFAULT_MASTER_KEY
    return hmac.new(
        eff_key.encode("utf-8"),
        f"device-psk:{device_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_device_key(psk: str) -> str:
    """Cryptographic hash of the PSK for storage in SQLite (never store plaintext PSK)."""
    return hashlib.sha256(psk.encode("utf-8")).hexdigest()


def compute_device_token(
    device_id: str,
    timestamp: str,
    flow_id: str | None = None,
    master_key: str | None = None,
    psk: str | None = None,
) -> str:
    """Compute HMAC-SHA256 token binding device_id, timestamp, and flow_id."""
    eff_key = master_key if master_key is not None else DEFAULT_MASTER_KEY
    key = psk if psk is not None else derive_device_key(device_id, eff_key)
    canonical_msg = f"{device_id}:{timestamp}:{flow_id or 'none'}"
    return hmac.new(
        key.encode("utf-8"),
        canonical_msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_device_token(
    device_id: str,
    token: str | None,
    timestamp: str | None,
    flow_id: str | None = None,
    master_key: str | None = None,
    psk: str | None = None,
    max_drift_seconds: float = TOKEN_EXPIRATION_SECONDS,
    replay_cache: TokenReplayCache | None = None,
) -> tuple[bool, str]:
    """Verify device authentication token with replay protection and constant-time check."""
    if not token or not timestamp:
        return False, "Missing authentication token or timestamp"

    # Replay protection: check timestamp drift
    try:
        clean_ts = timestamp.replace("Z", "+00:00")
        ts = datetime.fromisoformat(clean_ts)
        now = datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        drift = (now - ts).total_seconds()
        if drift < -5.0:
            return False, f"Authentication token rejected: future timestamp drift {-drift:.1f}s > 5.0s"
        if drift > max_drift_seconds:
            return False, f"Authentication token expired (timestamp drift {drift:.1f}s > {max_drift_seconds:.0f}s)"
    except Exception:
        return False, "Invalid timestamp format in authentication request"

    eff_key = master_key if master_key is not None else DEFAULT_MASTER_KEY
    expected_token = compute_device_token(device_id, timestamp, flow_id, eff_key, psk)
    if not hmac.compare_digest(token, expected_token):
        return False, "Cryptographic token verification failed"

    # Replay check: only verified tokens enter the replay cache
    cache = replay_cache if replay_cache is not None else DEFAULT_REPLAY_CACHE
    fresh, reason = cache.check_and_record(
        device_id=device_id,
        token=token,
        token_timestamp=timestamp,
        retention_seconds=max_drift_seconds,
    )
    if not fresh:
        return False, reason

    return True, "Token verified"


@dataclass
class Identity:
    identity: str
    role: str
    authenticated: bool = True
    trust_score: float = 100.0
    failures: int = 0
    mfa_status: str = "NOT_REQUIRED"  # Simulated MFA: NOT_REQUIRED, REQUIRED, VERIFIED, FAILED
    status: str = "ENROLLED"


class IAMService:
    """Zero-trust IAM, simulated MFA, and dynamic reputation engine.

    Enforces distinct authentication (who the entity is), simulated MFA verification,
    authorization (access control), and dynamic trust reputation (bounded 0..100).
    Backs identity and trust states to persistent storage when available.
    """

    def __init__(
        self,
        storage: Any | None = None,
        master_key: str | None = None,
        replay_cache: TokenReplayCache | None = None,
    ):
        self.storage = storage
        self.master_key = master_key if master_key is not None else DEFAULT_MASTER_KEY
        self.replay_cache = replay_cache if replay_cache is not None else DEFAULT_REPLAY_CACHE
        self.identities: dict[str, Identity] = {}
        self._load_identities()

    def _canonical_defaults(self) -> dict[str, Identity]:
        return {
            "SENSOR-01": Identity("SENSOR-01", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED", status="ENROLLED"),
            "SENSOR-02": Identity("SENSOR-02", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED", status="ENROLLED"),
            "SENSOR-03": Identity("SENSOR-03", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED", status="ENROLLED"),
            "SENSOR-GROUP-A": Identity("SENSOR-GROUP-A", "sensor", authenticated=True, trust_score=100.0, mfa_status="NOT_REQUIRED", status="ENROLLED"),
            "ATK-01": Identity("ATK-01", "untrusted", authenticated=False, trust_score=35.0, mfa_status="FAILED", status="REVOKED"),
            "operator": Identity("operator", "operator", authenticated=True, trust_score=100.0, mfa_status="VERIFIED", status="ENROLLED"),
        }

    def _load_identities(self) -> None:
        defaults = self._canonical_defaults()
        if self.storage is not None:
            try:
                rows = self.storage.list_device_identities()
                if rows:
                    for row in rows:
                        dev_id = row["device_id"]
                        role = row["role"]
                        status = row.get("status", "ENROLLED")
                        mfa = row.get("mfa_status", "NOT_REQUIRED")
                        is_auth = (status == "ENROLLED" and role != "untrusted")
                        self.identities[dev_id] = Identity(
                            identity=dev_id,
                            role=role,
                            authenticated=is_auth,
                            trust_score=float(row["trust_score"]),
                            failures=int(row["failures"]),
                            mfa_status=mfa,
                            status=status,
                        )
            except Exception:
                pass

        # Ensure canonical identities exist if not loaded from storage
        for name, ident in defaults.items():
            if name not in self.identities:
                self.identities[name] = ident

    def get(self, identity: str | None) -> Identity:
        name = identity or "UNKNOWN"
        if name not in self.identities:
            if self.storage is not None:
                try:
                    row = self.storage.get_device_identity(name)
                    if row:
                        status = row.get("status", "ENROLLED")
                        role = row["role"]
                        is_auth = (status == "ENROLLED" and role != "untrusted")
                        ident = Identity(
                            identity=name,
                            role=role,
                            authenticated=is_auth,
                            trust_score=float(row["trust_score"]),
                            failures=int(row["failures"]),
                            mfa_status=row.get("mfa_status", "NOT_REQUIRED"),
                            status=status,
                        )
                        self.identities[name] = ident
                        return ident
                except Exception:
                    pass

            # Zero-trust: unknown devices are UNREGISTERED, UNAUTHENTICATED, and UNTRUSTED
            mfa = "FAILED" if name.startswith("ATK") else ("REQUIRED" if "operator" in name.lower() else "NOT_REQUIRED")
            self.identities[name] = Identity(
                identity=name,
                role="unknown",
                authenticated=False,
                trust_score=45.0,
                mfa_status=mfa,
                status="UNREGISTERED",
            )
        return self.identities[name]

    def is_enrolled_sensor(self, device_id: str | None) -> bool:
        if not device_id:
            return False
        ident = self.get(device_id)
        return ident.role == "sensor" and ident.status == "ENROLLED"

    def authenticate_device(
        self,
        device_id: str | None,
        token: str | None,
        timestamp: str | None,
        flow_id: str | None = None,
    ) -> tuple[bool, str]:
        if not device_id:
            return False, "Missing device_id"

        ident = self.get(device_id)

        if ident.status == "REVOKED":
            return False, f"Device '{device_id}' is revoked"
        if ident.status == "UNREGISTERED" or ident.role in ("unknown", "untrusted"):
            return False, f"Device '{device_id}' is not an enrolled sensor"
        if ident.role == "operator":
            return True, "Operator identity verified"

        if not token:
            return False, f"Missing authentication token for enrolled sensor '{device_id}'"

        valid, reason = verify_device_token(
            device_id=device_id,
            token=token,
            timestamp=timestamp,
            flow_id=flow_id,
            master_key=self.master_key,
            replay_cache=self.replay_cache,
        )
        if valid and self.storage:
            try:
                self.storage.update_device_last_seen(device_id, timestamp)
            except Exception:
                pass
        return valid, reason

    def enroll_device(self, device_id: str, role: str = "sensor", psk: str | None = None) -> dict[str, Any]:
        derived_psk = psk or derive_device_key(device_id, self.master_key)
        key_hash = hash_device_key(derived_psk)
        now = utc_now()

        ident = Identity(
            identity=device_id,
            role=role.lower(),
            authenticated=True,
            trust_score=100.0,
            failures=0,
            mfa_status="NOT_REQUIRED",
            status="ENROLLED",
        )
        self.identities[device_id] = ident

        if self.storage:
            self.storage.upsert_device_identity(
                device_id=device_id,
                role=role.lower(),
                auth_key_hash=key_hash,
                status="ENROLLED",
                trust_score=100.0,
                failures=0,
                mfa_status="NOT_REQUIRED",
            )

        return {
            "device_id": device_id,
            "role": role.lower(),
            "status": "ENROLLED",
            "trust_score": 100.0,
            "auth_key_hash": key_hash,
            "provisioning_psk": derived_psk,
            "enrolled_at": now,
        }

    def revoke_device(self, device_id: str) -> dict[str, Any]:
        ident = self.get(device_id)
        ident.status = "REVOKED"
        ident.authenticated = False
        ident.trust_score = min(ident.trust_score, 35.0)

        if self.storage:
            self.storage.set_device_status(device_id, "REVOKED")
            self.storage.update_device_trust(device_id, ident.trust_score)

        return {
            "device_id": device_id,
            "status": "REVOKED",
            "trust_score": ident.trust_score,
            "authenticated": False,
        }

    def reset_identities(self) -> None:
        """Reset identity reputation to clean baseline state."""
        for name, ident in self.identities.items():
            if name.startswith("SENSOR-") or name == "operator":
                ident.trust_score = 100.0
                ident.failures = 0
            elif name.startswith("ATK"):
                ident.trust_score = 35.0
                ident.failures = 0
        if self.replay_cache:
            self.replay_cache.clear()
        if self.storage:
            for name, ident in self.identities.items():
                try:
                    self.storage.update_device_trust(name, ident.trust_score, ident.failures)
                except Exception:
                    pass

    def access(self, identity: str | None, resource: str = "gateway:telemetry") -> dict[str, Any]:
        item = self.get(identity)
        if not item.authenticated:
            allowed = False
            reason = "Authentication unverified or failed"
        elif item.role == "untrusted" or item.status == "REVOKED":
            allowed = False
            reason = "Untrusted or revoked role policy boundary"
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
        if self.storage:
            try:
                self.storage.update_device_trust(item.identity, item.trust_score, item.failures if auth_failure else None)
            except Exception:
                pass
        return item, effective_delta, reason
