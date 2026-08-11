"""Role-based access control for the dashboard.

Identity comes from two places:
  • Firebase (Google / email-password) — see auth.py
  • Local accounts stored in this project's DB — see database.py
*Authorization* lives here, and is the same regardless of how the user signed
in: every user carries a single role on their profile, and the decorators below
gate routes against a simple three-tier hierarchy.

Roles (lowest → highest privilege):

    viewer          "Dashboard Viewer"  — read-only. Sees the dashboard, news,
                                          reports and analytics. No actions.
    analyst_admin   "Analyst + Admin"   — everything a viewer can do, plus all
                                          operational work (scraping, curation,
                                          sending, deliveries) AND the /admin
                                          settings panel. Cannot manage users.
    admin           "Admin"             — everything analyst_admin can do, plus
                                          managing users and assigning roles.

A bootstrap allowlist (config.BOOTSTRAP_SUPER_ADMINS) is always treated as
`admin` so the platform owner can never be locked out.
"""

import logging
from functools import wraps

from flask import session, request, jsonify, redirect, url_for

import config

logger = logging.getLogger(__name__)

# ─── The canonical roles ────────────────────────────────────────────────
ROLE_VIEWER = "viewer"
ROLE_ANALYST_ADMIN = "analyst_admin"
ROLE_ADMIN = "admin"

# Human-facing labels (used by the login/onboarding/admin UIs).
ROLE_LABELS = {
    ROLE_VIEWER: "Dashboard Viewer",
    ROLE_ANALYST_ADMIN: "Analyst + Admin",
    ROLE_ADMIN: "Admin",
}

# Three-or-four-word gist of each role, for tight spots like the cell under a
# role dropdown where the full sentence below would wrap to four lines.
ROLE_SUMMARIES = {
    ROLE_VIEWER: "Read-only access",
    ROLE_ANALYST_ADMIN: "Runs operations + settings",
    ROLE_ADMIN: "Everything, including users",
}

# One-line summary of each role, shown next to the role picker so whoever is
# granting access can see what they are handing over.
ROLE_DESCRIPTIONS = {
    ROLE_VIEWER: "Read-only. Sees the dashboard, news, reports and analytics.",
    ROLE_ANALYST_ADMIN: "Everything a viewer can do, plus scraping, curation, "
                        "sending, deliveries and the admin settings panel.",
    ROLE_ADMIN: "Full control, including managing users and granting roles.",
}

# What each role can actually do, as the Users & Access page renders it. Each row
# corresponds to a real decorator on the routes in web_dashboard.py — when you
# gate a new capability, add its row here so the page stays truthful.
#   "View dashboard & reports"   every authenticated user (the login gate)
#   "Run scraping, send email"   @require_operator
#   "Admin settings panel"       @require_operator
#   "Manage users & roles"       @require_admin
#   "Reset the whole project"    @require_admin (wipes articles + workflow state)
ROLE_CAPABILITIES = {
    ROLE_VIEWER: [
        ("View dashboard & reports", True),
        ("Run scraping, send email", False),
        ("Admin settings panel", False),
        ("Manage users & roles", False),
        ("Reset the whole project", False),
    ],
    ROLE_ANALYST_ADMIN: [
        ("View dashboard & reports", True),
        ("Run scraping, send email", True),
        ("Admin settings panel", True),
        ("Manage users & roles", False),
        ("Reset the whole project", False),
    ],
    ROLE_ADMIN: [
        ("View dashboard & reports", True),
        ("Run scraping, send email", True),
        ("Admin settings panel", True),
        ("Manage users & roles", True),
        ("Reset the whole project", True),
    ],
}

# Privilege ordering. Higher number == more access.
_ROLE_LEVEL = {
    ROLE_VIEWER: 1,
    ROLE_ANALYST_ADMIN: 2,
    ROLE_ADMIN: 3,
}

# Roles an existing admin may assign through the Users & Roles panel.
ASSIGNABLE_ROLES = [ROLE_VIEWER, ROLE_ANALYST_ADMIN, ROLE_ADMIN]

# Roles a brand-new user may end up with by self-onboarding. Privileged roles
# are never self-granted — an admin elevates them afterwards.
SELF_SIGNUP_ROLES = [ROLE_VIEWER]

# Legacy role strings that predate the three-tier model, mapped onto it so old
# profiles keep working after the migration.
_LEGACY_ROLE_MAP = {
    "super_admin": ROLE_ADMIN,
    "administrator": ROLE_ADMIN,
    "manager": ROLE_ANALYST_ADMIN,
    "sender": ROLE_ANALYST_ADMIN,
    "analyst": ROLE_ANALYST_ADMIN,
    "operator": ROLE_ANALYST_ADMIN,
}

# Roles permitted to reach the admin *settings* panel and operational/config
# endpoints. (User management is stricter — admin only — see require_admin.)
ADMIN_ROLES = {ROLE_ANALYST_ADMIN, ROLE_ADMIN}


def normalize_role(role) -> str:
    """Map any stored/legacy role string onto one of the three canonical roles.

    Unknown or missing roles fail *safe* to viewer (read-only), never to a
    privileged role."""
    r = (role or "").strip().lower()
    if r in _ROLE_LEVEL:
        return r
    if r in _LEGACY_ROLE_MAP:
        return _LEGACY_ROLE_MAP[r]
    return ROLE_VIEWER


def role_level(role) -> int:
    return _ROLE_LEVEL.get(normalize_role(role), _ROLE_LEVEL[ROLE_VIEWER])


def _bootstrap_admins():
    return {e.strip().lower() for e in getattr(config, "BOOTSTRAP_SUPER_ADMINS", []) if e}


def is_email_allowed(email: str) -> bool:
    """True if this address may sign in *via Firebase*: an allow-listed domain
    or a bootstrap admin. Fails closed when no domains are configured.

    Local accounts do NOT go through this gate — they are created explicitly by
    an admin and are authorized by their very existence."""
    email = (email or "").strip().lower()
    if not email:
        return False
    if email in _bootstrap_admins():
        return True
    allowed = {d.strip().lower() for d in getattr(config, "ALLOWED_EMAIL_DOMAINS", []) if d}
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    return bool(domain) and domain in allowed


def effective_role(user) -> str:
    """The canonical role we authorize against. Bootstrap accounts are always
    admin; everyone else gets the (normalized) role from their profile."""
    if not user:
        return None
    email = (user.get("email") or "").lower()
    if email in _bootstrap_admins():
        return ROLE_ADMIN
    return normalize_role((user.get("profile") or {}).get("role"))


def _wants_json() -> bool:
    return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"


def _deny(user, role, min_role):
    logger.warning(
        f"🚫 RBAC deny: {(user or {}).get('email')} (role={role}) "
        f"needs≥{min_role} → {request.method} {request.path}"
    )
    if _wants_json():
        return jsonify({
            "error": "forbidden",
            "message": "You do not have permission to perform this action.",
        }), 403
    return redirect(url_for("dashboard"))


def require_min_role(min_role):
    """Decorator: allow the request only if the user's role ranks at or above
    `min_role` in the hierarchy."""
    threshold = _ROLE_LEVEL[normalize_role(min_role)]

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get("user")
            if not user:
                # The global auth gate normally handles this; be defensive anyway.
                if _wants_json():
                    return jsonify({"error": "authentication_required"}), 401
                return redirect(url_for("login_page"))
            role = effective_role(user)
            if role_level(role) < threshold:
                return _deny(user, role, min_role)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_role(*allowed):
    """Decorator: allow the request only if the user's effective role is exactly
    one of `allowed` (after normalization). Kept for callers that want an
    explicit set rather than a hierarchy threshold."""
    allowed_set = {normalize_role(r) for r in allowed}

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get("user")
            if not user:
                if _wants_json():
                    return jsonify({"error": "authentication_required"}), 401
                return redirect(url_for("login_page"))
            role = effective_role(user)
            if role not in allowed_set:
                return _deny(user, role, "/".join(sorted(allowed_set)))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ─── Convenience decorators used across the routes ──────────────────────
def require_viewer(fn):
    """Any authenticated user with a valid role (i.e. everyone). Marks a route
    as read-only-and-above."""
    return require_min_role(ROLE_VIEWER)(fn)


def require_analyst_admin(fn):
    """Operational work + the settings panel: Analyst+Admin and Admin."""
    return require_min_role(ROLE_ANALYST_ADMIN)(fn)


# `require_operator` reads well on action endpoints; same gate as analyst_admin.
require_operator = require_analyst_admin


def require_admin(fn):
    """User management and anything reserved for full admins."""
    return require_min_role(ROLE_ADMIN)(fn)


# ─── Verified identity (a second axis, independent of role) ─────────────
def is_verified_identity(user) -> bool:
    """True when an external identity provider vouched for this person, rather
    than a password row in our own database vouching for itself.

    This is deliberately *not* a role. The access audit log records who granted
    which privileges to whom, so reading it should require a provably real
    identity — an admin account created locally with a shipped default password
    must not qualify on the strength of its role alone.

    Bootstrap super-admins always pass (they are the platform owners).
    Firebase identities pass unless the ID token said the address was
    explicitly unverified. Local email+password accounts never pass.
    """
    if not user:
        return False
    if (user.get("email") or "").lower() in _bootstrap_admins():
        return True
    provider = ((user.get("profile") or {}).get("auth_provider") or "").strip().lower()
    if provider != "firebase":
        return False
    # Sessions minted before email_verified was recorded have no such key. Treat
    # a Firebase-backed identity as verified rather than locking someone out
    # mid-session; only an explicit False disqualifies.
    return user.get("email_verified") is not False


def require_verified_admin(fn):
    """Admin role AND a verified identity — the gate on the access audit log."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user:
            if _wants_json():
                return jsonify({"error": "authentication_required"}), 401
            return redirect(url_for("login_page"))
        role = effective_role(user)
        if role_level(role) < _ROLE_LEVEL[ROLE_ADMIN]:
            return _deny(user, role, ROLE_ADMIN)
        if not is_verified_identity(user):
            logger.warning(
                f"🚫 Audit log denied — unverified identity: {user.get('email')} "
                f"(provider={(user.get('profile') or {}).get('auth_provider')})"
            )
            if _wants_json():
                return jsonify({
                    "error": "identity_not_verified",
                    "message": "The audit log is restricted to accounts with a "
                               "verified identity. Sign in with your organization "
                               "Google account to view it.",
                }), 403
            return redirect(url_for("admin_users_page"))
        return fn(*args, **kwargs)

    return wrapper
