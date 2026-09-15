"""AICG Administrative Security Layer: RBAC, password security, session handling, and simulated MFA."""

from __future__ import annotations

from functools import wraps
import hmac
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


def get_current_user() -> dict[str, Any] | None:
    """Retrieve authenticated user context from Flask session."""
    user = session.get("user")
    if not user or not isinstance(user, dict):
        return None
    if not user.get("authenticated"):
        return None
    return user


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator requiring an authenticated session."""
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/"):
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
                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Unauthorized: Authentication required",
                        "code": "AUTH_REQUIRED",
                        "authenticated": False,
                    }), 401
                return redirect(f"/login?next={request.path}")
            user_role = str(user.get("role", "")).upper()
            allowed = [r.upper() for r in roles]
            if user_role not in allowed:
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
                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Unauthorized: Authentication required",
                        "code": "AUTH_REQUIRED",
                        "authenticated": False,
                    }), 401
                return redirect(f"/login?next={request.path}")
            user_role = str(user.get("role", "")).upper()
            if not has_permission(user_role, permission):
                return jsonify({
                    "error": f"Forbidden: Role '{user_role}' lacks required permission '{permission}'",
                    "code": "FORBIDDEN_PERMISSION",
                    "role": user_role,
                    "required_permission": permission,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
