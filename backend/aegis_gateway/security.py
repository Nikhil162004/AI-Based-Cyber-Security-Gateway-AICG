"""AICG Administrative Security Layer: RBAC, password security, session handling, and simulated MFA."""

from __future__ import annotations

from collections import defaultdict
from functools import wraps
import hmac
import os
import time
from typing import Any, Callable
from flask import jsonify, redirect, request, session
from werkzeug.security import check_password_hash, generate_password_hash

# =====================================================================
# ROLES AND PERMISSIONS (RBAC)
# =====================================================================

ROLE_ADMIN = "ADMIN"
ROLE_OPERATOR = "OPERATOR"

ALL_ROLES = (ROLE_ADMIN, ROLE_OPERATOR)

# Granular permissions defined in AICG Master Prompt
PERM_VIEW_DASHBOARD = "VIEW_DASHBOARD"
PERM_VIEW_INCIDENTS = "VIEW_INCIDENTS"
PERM_ACK_ALERT = "ACK_ALERT"
PERM_MANAGE_INCIDENT = "MANAGE_INCIDENT"
PERM_CLOSE_INCIDENT = "CLOSE_INCIDENT"
PERM_VIEW_AUDIT = "VIEW_AUDIT"
PERM_MANAGE_USERS = "MANAGE_USERS"
PERM_VIEW_SECURITY_POSTURE = "VIEW_SECURITY_POSTURE"
PERM_VIEW_SYSTEM_STATUS = "VIEW_SYSTEM_STATUS"
PERM_ADMIN_CONTROLS = "ADMIN_CONTROLS"

ROLE_PERMISSIONS: dict[str, set[str]] = {
    ROLE_ADMIN: {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INCIDENTS,
        PERM_ACK_ALERT,
        PERM_MANAGE_INCIDENT,
        PERM_CLOSE_INCIDENT,
        PERM_VIEW_AUDIT,
        PERM_MANAGE_USERS,
        PERM_VIEW_SECURITY_POSTURE,
        PERM_VIEW_SYSTEM_STATUS,
        PERM_ADMIN_CONTROLS,
    },
    ROLE_OPERATOR: {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INCIDENTS,
        PERM_ACK_ALERT,
        PERM_MANAGE_INCIDENT,
        PERM_VIEW_SECURITY_POSTURE,
        PERM_VIEW_SYSTEM_STATUS,
    },
}

# Explicitly forbidden for OPERATOR per specifications
OPERATOR_DENIED_PERMISSIONS = {
    PERM_MANAGE_USERS,
    PERM_ADMIN_CONTROLS,
    PERM_CLOSE_INCIDENT,
    PERM_VIEW_AUDIT,
}

# Standard Demonstration Lab Token
DEFAULT_SIMULATED_MFA_TOKEN = "123456"


def has_permission(role: str | None, permission: str) -> bool:
    """Check if the specified role possesses the permission."""
    if not role:
        return False
    perms = ROLE_PERMISSIONS.get(role.upper(), set())
    return permission in perms


def hash_password(plaintext: str) -> str:
    """Hash password using Werkzeug's secure PBKDF2/scrypt algorithm."""
    return generate_password_hash(plaintext)


def verify_password(plaintext: str, password_hash: str) -> bool:
    """Constant-time verification of plaintext against password hash."""
    if not plaintext or not password_hash:
        return False
    return check_password_hash(password_hash, plaintext)


def verify_simulated_mfa(token: str) -> bool:
    """Constant-time validation of simulated MFA token."""
    if not token:
        return False
    clean = token.strip()
    return hmac.compare_digest(clean, DEFAULT_SIMULATED_MFA_TOKEN)


# =====================================================================
# SESSION HARDENING & PRE-MFA STATE MANAGEMENT
# =====================================================================

class AuthRateLimiter:
    """In-memory rate limiter tracking failed authentication attempts per (ip, identifier)."""

    def __init__(self, max_attempts: int = 10, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = defaultdict(list)

    def _key(self, ip: str | None, username: str | None) -> str:
        return f"{ip or 'unknown'}:{username or 'unknown'}"

    def is_rate_limited(self, ip: str | None, username: str | None) -> bool:
        key = self._key(ip, username)
        now = time.time()
        self._failures[key] = [t for t in self._failures[key] if now - t < self.window_seconds]
        return len(self._failures[key]) >= self.max_attempts

    def record_failure(self, ip: str | None, username: str | None) -> None:
        key = self._key(ip, username)
        self._failures[key].append(time.time())

    def reset(self, ip: str | None, username: str | None) -> None:
        key = self._key(ip, username)
        self._failures.pop(key, None)


auth_limiter = AuthRateLimiter(max_attempts=10, window_seconds=60)


def rotate_session() -> None:
    """Rotate session data to prevent session fixation attacks."""
    session.clear()


def set_pre_mfa_user(user: dict[str, Any] | str, role: str = ROLE_OPERATOR) -> None:
    """Store pre-MFA state in session after successful password verification."""
    session.clear()
    if isinstance(user, str):
        session["pre_mfa"] = {
            "user_id": f"USR-{user.upper()}",
            "username": user,
            "role": role,
            "timestamp": time.time(),
        }
    else:
        session["pre_mfa"] = {
            "user_id": user.get("user_id", f"USR-{user.get('username', 'UNKNOWN').upper()}"),
            "username": user["username"],
            "role": user.get("role", role),
            "timestamp": time.time(),
        }


def get_pre_mfa_user() -> dict[str, Any] | None:
    """Retrieve pre-MFA candidate from session. Valid for 10 minutes."""
    pre = session.get("pre_mfa")
    if not pre or not isinstance(pre, dict):
        return None
    if time.time() - float(pre.get("timestamp", 0)) > 600:
        session.pop("pre_mfa", None)
        return None
    return pre


def clear_pre_mfa() -> None:
    """Clear pre-MFA session state."""
    session.pop("pre_mfa", None)


def generate_user_token(user_session: dict[str, Any], secret_key: str | None = None) -> str:
    """Generate a signed URL-safe authorization token for cross-origin / iframe sessions."""
    from itsdangerous import URLSafeSerializer
    from flask import current_app
    secret = secret_key or (current_app.secret_key if current_app else "aegis-fallback-secret-2026")
    s = URLSafeSerializer(secret, salt="aegis-auth-v1")
    return s.dumps(user_session)


def verify_user_token(token: str, secret_key: str | None = None) -> dict[str, Any] | None:
    """Verify and decode a signed URL-safe authorization token."""
    from itsdangerous import URLSafeSerializer
    from flask import current_app
    try:
        secret = secret_key or (current_app.secret_key if current_app else "aegis-fallback-secret-2026")
        s = URLSafeSerializer(secret, salt="aegis-auth-v1")
        data = s.loads(token)
        if isinstance(data, dict) and data.get("authenticated"):
            return data
    except Exception:
        pass
    return None


def get_current_user() -> dict[str, Any] | None:
    """Retrieve authenticated user context from Flask session, header, or query token."""
    user = session.get("user")
    if user and isinstance(user, dict) and user.get("authenticated"):
        return user

    from flask import current_app, request
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.args.get("token") or request.args.get("auth_token")

    if token:
        valid_user = verify_user_token(token, current_app.secret_key if current_app else None)
        if valid_user:
            try:
                session["user"] = valid_user
            except Exception:
                pass
            return valid_user

    # Dev/Demonstration fallback for sandboxed browser iframes where third-party cookies & localStorage are blocked
    if current_app:
        rt = current_app.config.get("runtime")
        is_prod = bool(rt.settings.production) if (rt and hasattr(rt, "settings")) else False
        if not is_prod and os.getenv("AEGIS_DEV_AUTO_AUTH", "0") == "1":
            from datetime import datetime, timezone
            now_str = datetime.now(timezone.utc).isoformat()
            return {
                "user_id": "USR-ADMIN-01",
                "username": "admin",
                "role": ROLE_ADMIN,
                "authenticated": True,
                "mfa_verified": True,
                "mfa_status": "SIMULATED_VERIFIED",
                "login_time": now_str,
            }

    return None


def _log_security_audit(username: str, role: str, action: str, details: str) -> None:
    """Helper to record security audit logs during access control enforcement."""
    try:
        from flask import current_app
        rt = current_app.config.get("runtime")
        if rt and hasattr(rt, "store"):
            rt.store.record_audit(
                username=username,
                role=role,
                action=action,
                resource=request.path,
                resource_id=None,
                result="DENIED",
                details=details,
                source_ip=request.remote_addr,
            )
    except Exception:
        pass


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator requiring an authenticated session."""
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        user = get_current_user()
        if not user:
            if request.method in ("POST", "PUT", "PATCH", "DELETE") or request.path.startswith("/api/") or request.path == "/events":
                _log_security_audit(
                    "anonymous",
                    "ANONYMOUS",
                    "ACCESS_DENIED",
                    f"Unauthenticated attempt to access {request.method} {request.path}",
                )
            if request.path.startswith("/api/") or request.path == "/events":
                return jsonify({
                    "error": "Unauthorized: Authentication required",
                    "code": "AUTH_REQUIRED",
                    "authenticated": False,
                }), 401
            return redirect(f"/login?next={request.path}")
        return f(*args, **kwargs)
    return decorated


def roles_required(*roles: str) -> Callable[..., Any]:
    """Decorator requiring the authenticated user to hold one of the given roles."""
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user:
                _log_security_audit(
                    "anonymous",
                    "ANONYMOUS",
                    "ACCESS_DENIED",
                    f"Unauthenticated attempt to access {request.method} {request.path}",
                )
                if request.path.startswith("/api/") or request.path == "/events":
                    return jsonify({
                        "error": "Unauthorized: Authentication required",
                        "code": "AUTH_REQUIRED",
                        "authenticated": False,
                    }), 401
                return redirect(f"/login?next={request.path}")
            user_role = str(user.get("role", "")).upper()
            allowed = [r.upper() for r in roles]
            if user_role not in allowed:
                _log_security_audit(
                    user.get("username", "unknown"),
                    user_role,
                    "ACCESS_DENIED",
                    f"Denied role '{user_role}' for endpoint {request.method} {request.path}. Allowed: {allowed}",
                )
                return jsonify({
                    "error": f"Forbidden: Role '{user_role}' lacks authorization. Required: {allowed}",
                    "code": "FORBIDDEN_ROLE",
                    "role": user_role,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def permission_required(permission: str) -> Callable[..., Any]:
    """Decorator requiring a specific RBAC permission."""
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user:
                _log_security_audit(
                    "anonymous",
                    "ANONYMOUS",
                    "ACCESS_DENIED",
                    f"Unauthenticated attempt to access {request.method} {request.path}",
                )
                if request.path.startswith("/api/") or request.path == "/events":
                    return jsonify({
                        "error": "Unauthorized: Authentication required",
                        "code": "AUTH_REQUIRED",
                        "authenticated": False,
                    }), 401
                return redirect(f"/login?next={request.path}")
            user_role = str(user.get("role", "")).upper()
            if not has_permission(user_role, permission):
                _log_security_audit(
                    user.get("username", "unknown"),
                    user_role,
                    "ACCESS_DENIED",
                    f"Denied role '{user_role}' for endpoint {request.method} {request.path}. Required permission: {permission}",
                )
                return jsonify({
                    "error": f"Forbidden: Role '{user_role}' lacks required permission '{permission}'",
                    "code": "FORBIDDEN_PERMISSION",
                    "role": user_role,
                    "required_permission": permission,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
