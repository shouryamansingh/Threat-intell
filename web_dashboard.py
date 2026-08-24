#!/usr/bin/env python3
"""
Threat Intelligence Web Dashboard
Modern web interface for managing the threat intelligence system
"""

import os
import sys

# Windows consoles often use cp1252; emoji in print() would raise UnicodeEncodeError.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError, TypeError):
        pass

# Configure logging before importing project modules, so anything they log at
# import time lands in the log file too.
from log_setup import setup_logging
logger = setup_logging("dashboard")

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import sqlite3
import threading
import time
import secrets
from datetime import datetime, timedelta
import json
import logging
import pytz

# Import existing system components
from database import db
from web_scraper import scraper
from email_system import email_system
from scheduler import threat_scheduler
from soc_report_formatter_enhanced import enhanced_soc_formatter as soc_formatter
import config
from auth import verify_id_token, user_from_claims
from link_tokens import INTERNAL_HEADER, verify_internal_token
from rbac import (
    require_admin, require_analyst_admin, require_operator, require_viewer,
    require_verified_admin, is_verified_identity,
    is_email_allowed, effective_role, normalize_role,
    ASSIGNABLE_ROLES, SELF_SIGNUP_ROLES, ROLE_LABELS, ROLE_ADMIN, ROLE_VIEWER,
    ROLE_DESCRIPTIONS, ROLE_SUMMARIES, ROLE_CAPABILITIES,
)

# Refuse to start in production with configuration that would silently break
# email links or leave the app wide open.
_config_problems = config.validate_deployment()
if _config_problems:
    for _p in _config_problems:
        logger.error(f"CONFIG: {_p}")
    if config.IS_PRODUCTION:
        logger.warning(
            "Continuing despite the above — review these before trusting the "
            "approval workflow. Set the missing TI_* variables in the service "
            "EnvironmentFile."
        )

# Flask app setup
app = Flask(__name__)

# Behind a reverse proxy, the peer address is always the proxy (127.0.0.1) and
# the scheme is always http. ProxyFix rewrites request.remote_addr, .scheme and
# .host from the X-Forwarded-* headers so client-IP checks and url_for() stay
# truthful. Applied only when TI_TRUSTED_PROXY_HOPS says a proxy exists —
# trusting those headers with no proxy in front lets any client forge its own IP.
if config.TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=config.TRUSTED_PROXY_HOPS,
        x_proto=config.TRUSTED_PROXY_HOPS,
        x_host=config.TRUSTED_PROXY_HOPS,
        x_prefix=config.TRUSTED_PROXY_HOPS,
    )
    logger.info(f"ProxyFix enabled for {config.TRUSTED_PROXY_HOPS} proxy hop(s)")
# Persist the SECRET_KEY across restarts so sessions survive a reboot.
_SECRET_KEY_FILE = config.SECRET_KEY_FILE
if os.path.exists(_SECRET_KEY_FILE):
    with open(_SECRET_KEY_FILE, "rb") as _f:
        app.config['SECRET_KEY'] = _f.read()
else:
    _generated = secrets.token_bytes(32)
    with open(_SECRET_KEY_FILE, "wb") as _f:
        _f.write(_generated)
    os.chmod(_SECRET_KEY_FILE, 0o600)
    app.config['SECRET_KEY'] = _generated
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Only send the session cookie over HTTPS in production. Without this the
# cookie travels in cleartext on every request and anyone on the network path
# can lift a logged-in session. Left off locally because dev runs on http://.
app.config['SESSION_COOKIE_SECURE'] = config.IS_PRODUCTION
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
# The dashboard runs with debug off, so Jinja would otherwise cache each
# template for the life of the process and an edited .html would keep serving
# the old markup until a full restart. One stat() per render is a fine price for
# not chasing phantom "my change didn't apply" bugs.
app.config['TEMPLATES_AUTO_RELOAD'] = True
# cors_allowed_origins was "*", which lets any site a signed-in user visits open
# an authenticated Socket.IO connection to the dashboard. In production this is
# pinned to the dashboard's own origin (see config.CORS_ALLOWED_ORIGINS).
socketio = SocketIO(app, cors_allowed_origins=config.CORS_ALLOWED_ORIGINS, async_mode='threading')


# ─── Real-time delivery push ────────────────────────────────────────────
# enhanced_scheduler (the background poller) and scheduler._finalize_delivery
# run OUTSIDE any Flask request. Register a notifier so that the moment a SOC
# delivery is actually sent, every connected dashboard is pushed the new state
# and flips the row to "Published" immediately — no wait for the next poll.
def _push_delivery_to_clients(payload):
    try:
        socketio.emit('delivery_notification', payload)
    except Exception as _e:
        logger.warning(f"Could not emit delivery_notification: {_e}")

try:
    import enhanced_scheduler as _enhanced_scheduler
    _enhanced_scheduler.delivery_notifier = _push_delivery_to_clients
except Exception as _e:  # pragma: no cover - defensive
    logging.getLogger(__name__).warning(f"Could not register delivery notifier: {_e}")


# ─── Authentication gate ────────────────────────────────────────────────
# Paths that must remain reachable without a session — the login page itself,
# the token-exchange endpoint, static assets, and the callback-from-email
# notification endpoints (those are POSTed by the callback_server, not a user).
_AUTH_PUBLIC_PREFIXES = (
    '/login',
    '/api/auth/',
    '/static/',
    '/favicon',
    '/socket.io/',
    '/api/notify_approval',
    '/api/notify_validation',
    '/api/notify_delivery',
    '/healthz',   # liveness probe for uptime monitors — returns no sensitive data
    # Branding and the Firebase *browser* config, for the React front end
    # (frontend_bridge.py). Public for the same reason the login page is: a
    # sign-in screen needs the Firebase config before anyone has a session.
    # This exposes nothing new — every value in it is already rendered into the
    # HTML of login.html, which is served to anonymous visitors today.
    '/api/public-config',
)

# Once signed in, a brand-new user is held at /setup-profile until they
# fill out the onboarding form. Only these endpoints work while in that
# half-authenticated state.
_PROFILE_GATE_ALLOWED = (
    '/setup-profile',
    '/api/profile/setup',
    '/api/auth/me',
    '/api/auth/logout',
    '/static/',
    '/favicon',
)


# DEMO_MODE (set env DEMO_MODE=1) bypasses Firebase sign-in and injects a
# neutral demo identity so screen recordings never expose a real account,
# email, or login flow. Has NO effect unless the env var is set.
_DEMO_USER = {
    'uid': 'demo-admin',
    'email': 'analyst@sentinel-demo.io',
    'name': 'Alex Morgan',
    'provider': 'demo',
    'profile_complete': True,
    'profile': {
        'display_name': 'Alex Morgan',
        # 'admin' so the recording can showcase the /admin panel (sources,
        # schedule, email settings) end-to-end.
        'role': 'admin',
        'department': 'IT Internal Audit',
    },
}


def _demo_mode_enabled():
    # Refused outright in production. This flag skips Firebase sign-in entirely
    # and injects an *admin* identity, and _refresh_session_profile() returns
    # early for provider == 'demo', so the DB active/role check is skipped too.
    # Set in a production environment it would hand every anonymous visitor the
    # admin panel — so IS_PRODUCTION wins regardless of how the var got there
    # (inherited shell, stray EnvironmentFile line, systemd drop-in).
    if config.IS_PRODUCTION:
        return False
    return os.environ.get('DEMO_MODE', '').strip().lower() in ('1', 'true', 'yes', 'on')


# ─── Brute-force throttle for the credential endpoints ───────────────────
# In-process on purpose. The dashboard is pinned to a single worker (a second one
# would run every scheduled job twice and send every email twice — see
# deploy/threatintel-dashboard.service), so a module-level dict *is* the whole
# picture; there is no second process to share state with and no need for Redis.
# Counters reset on restart, which is fine for a lockout measured in minutes.
_LOGIN_FAIL_WINDOW = int(os.environ.get("TI_LOGIN_FAIL_WINDOW", "900"))   # 15 min
_LOGIN_FAIL_MAX    = int(os.environ.get("TI_LOGIN_FAIL_MAX", "8"))
_LOGIN_LOCKOUT     = int(os.environ.get("TI_LOGIN_LOCKOUT", "900"))       # 15 min

_throttle_state = {}   # key -> list of recent failure timestamps
_throttle_lock = threading.Lock()


def _throttle_keys(email=None, scope="auth"):
    """Rate-limit on the client IP and, separately, on the targeted account.

    Two keys because the two attacks have different shapes: one IP trying many
    passwords against a single account, and many IPs trying one common password
    against many accounts. Keying on either alone leaves the other wide open.

    `scope` keeps unrelated limits from sharing a counter — a burst of access
    requests must not lock the same IP out of signing in.

    request.remote_addr is the real client here — ProxyFix is installed when
    TI_TRUSTED_PROXY_HOPS is set, so behind nginx this is not 127.0.0.1.
    """
    keys = [f"{scope}:ip:{request.remote_addr or '?'}"]
    if email:
        keys.append(f"{scope}:user:{email.strip().lower()}")
    return keys


def _throttle_check(email=None, scope="auth"):
    """Return a 429 response tuple if this caller is locked out, else None."""
    now = time.time()
    with _throttle_lock:
        for key in _throttle_keys(email, scope):
            hits = [t for t in _throttle_state.get(key, [])
                    if now - t < _LOGIN_FAIL_WINDOW]
            _throttle_state[key] = hits
            if len(hits) >= _LOGIN_FAIL_MAX:
                retry = int(_LOGIN_LOCKOUT - (now - hits[-1]))
                if retry > 0:
                    logger.warning(
                        f"🚫 Throttled [{key}] — {len(hits)} failures in "
                        f"{_LOGIN_FAIL_WINDOW}s, {retry}s remaining"
                    )
                    resp = jsonify({
                        'error': 'too_many_attempts',
                        'message': ('Too many failed attempts. Try again in '
                                    f'{max(1, retry // 60)} minute(s).'),
                    })
                    resp.headers['Retry-After'] = str(max(1, retry))
                    return resp, 429
    return None


def _throttle_fail(email=None, scope="auth"):
    """Record one failed attempt against every applicable key."""
    now = time.time()
    with _throttle_lock:
        for key in _throttle_keys(email, scope):
            _throttle_state.setdefault(key, []).append(now)
        # Cheap upper bound on memory: a flood of distinct source IPs must not
        # grow this dict without limit. Drop entries with nothing recent left.
        if len(_throttle_state) > 4096:
            for k in [k for k, v in _throttle_state.items()
                      if not v or now - v[-1] > _LOGIN_FAIL_WINDOW]:
                _throttle_state.pop(k, None)


def _throttle_reset(email=None, scope="auth"):
    """Clear counters after a genuine success, so a few mistyped passwords
    followed by the right one don't leave the account half-locked."""
    with _throttle_lock:
        for key in _throttle_keys(email, scope):
            _throttle_state.pop(key, None)


def _refresh_session_profile(user):
    """Re-read the signed-in user's profile so role changes and deactivations
    take effect on the *next request*, not the next sign-in.

    The session cookie caches a snapshot of the profile taken at login. Without
    this, an admin who demotes or disables someone in the Users & Access panel
    would be ignored until that person's 7-day session expired. Returns False if
    the account is gone or disabled, which ends the session.
    """
    if user.get('provider') == 'demo':
        return True
    uid = user.get('uid')
    if not uid:
        return True
    try:
        profile = db.get_user_profile(uid)
    except Exception as e:  # DB blip — keep the cached snapshot rather than
        logger.warning(f"Could not refresh profile for {user.get('email')}: {e}")
        return True          # locking everybody out.
    if profile is None:
        # Never onboarded (held at /setup-profile) is fine; a *deleted* account
        # is not. Tell them apart by whether they had a profile before.
        return not user.get('profile_complete')
    if not int(profile.get('active', 1) or 0):
        logger.warning(f"⛔ Session ended — account disabled: {user.get('email')}")
        return False
    if profile != user.get('profile'):
        user['profile'] = profile
        session['user'] = user
    return True


@app.before_request
def _require_login():
    path = request.path or '/'
    if any(path == p or path.startswith(p) for p in _AUTH_PUBLIC_PREFIXES):
        return None
    # Demo recording mode: seed a clean, fake identity and skip real auth.
    if _demo_mode_enabled() and not session.get('user'):
        session.permanent = True
        session['user'] = dict(_DEMO_USER)
    user = session.get('user')
    if not user:
        if request.accept_mimetypes.best == 'application/json' or path.startswith('/api/'):
            return jsonify({'error': 'authentication_required'}), 401
        return redirect(url_for('login_page', next=path))

    # Role/enabled state is authoritative in the DB, not in the cookie.
    if not _refresh_session_profile(user):
        session.clear()
        if request.accept_mimetypes.best == 'application/json' or path.startswith('/api/'):
            return jsonify({
                'error': 'account_disabled',
                'message': 'Your access has been revoked. Contact an administrator.',
            }), 403
        return redirect(url_for('login_page'))

    # Authenticated but onboarding incomplete: hold them at /setup-profile.
    if not user.get('profile_complete'):
        if any(path == p or path.startswith(p) for p in _PROFILE_GATE_ALLOWED):
            return None
        if request.accept_mimetypes.best == 'application/json' or path.startswith('/api/'):
            return jsonify({'error': 'profile_setup_required'}), 403
        return redirect(url_for('setup_profile_page'))
    return None


# ─── Admin notifications for onboarding events ──────────────────────────
def _admin_recipients():
    """Where to send onboarding notifications: every active admin, plus the
    bootstrap super-admins (who are admin whether or not they have a profile).
    A user's notification_email overrides their sign-in address."""
    recipients = []
    try:
        for u in db.list_users():
            if normalize_role(u.get('role')) != ROLE_ADMIN:
                continue
            if not int(u.get('active', 1) or 0):
                continue
            profile = db.get_user_profile_by_email(u.get('email') or '') or {}
            addr = (profile.get('notification_email') or u.get('email') or '').strip()
            if addr:
                recipients.append(addr)
    except Exception as e:
        logger.warning(f"Could not list admins for notification: {e}")
    for addr in getattr(config, 'BOOTSTRAP_SUPER_ADMINS', []) or []:
        if addr:
            recipients.append(addr.strip())
    # De-duplicate case-insensitively, preserving order.
    seen, unique = set(), []
    for addr in recipients:
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            unique.append(addr)
    return unique


def _send_admin_notification(subject, html):
    """Best-effort email to all admins, off the request thread.

    Never raises and never blocks sign-in: a broken SMTP config must not stop
    someone from logging in, and the in-app notification has already landed."""
    if not getattr(config, 'ACCESS_REQUEST_EMAIL_ENABLED', True):
        logger.info(f"✉️  Admin notification suppressed by config: {subject}")
        return
    recipients = _admin_recipients()
    if not recipients:
        logger.warning("No admin recipients for onboarding notification")
        return

    def _worker():
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = config.SENDER_EMAIL
            message["To"] = ", ".join(recipients)
            message.attach(MIMEText(html, "html"))
            with email_system.create_smtp_connection() as server:
                server.send_message(message)
            logger.info(f"✉️  Admin notification sent to {len(recipients)} admin(s): {subject}")
        except Exception as e:
            logger.error(f"Admin notification email failed: {type(e).__name__}: {e}")
            db.log_system_event(
                'WARNING',
                f'Could not email admins about "{subject}": {e}',
                'ACCESS_CONTROL',
            )

    threading.Thread(target=_worker, name="admin-notify", daemon=True).start()


def _onboarding_email_html(heading, lead, rows, cta_label, cta_url):
    """Plain, self-contained HTML for the two onboarding notification mails."""
    row_html = "".join(
        f'<tr><td style="padding:6px 14px 6px 0;color:#64748b;font-size:13px;">{k}</td>'
        f'<td style="padding:6px 0;color:#13294B;font-size:13px;font-weight:600;">{v}</td></tr>'
        for k, v in rows
    )
    return f"""\
<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f5f7fa;padding:24px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #d1dce8;border-radius:12px;overflow:hidden;">
    <div style="background:#13294B;color:#fff;padding:16px 20px;font-size:15px;font-weight:600;">
      🛡️ Weekly Cyber Watch · Access control
    </div>
    <div style="padding:20px;">
      <h2 style="margin:0 0 8px;font-size:17px;color:#13294B;">{heading}</h2>
      <p style="margin:0 0 16px;font-size:14px;color:#475569;line-height:1.5;">{lead}</p>
      <table style="border-collapse:collapse;margin-bottom:20px;">{row_html}</table>
      <a href="{cta_url}" style="display:inline-block;background:#2F6BFF;color:#fff;
         text-decoration:none;padding:10px 18px;border-radius:8px;font-size:14px;font-weight:600;">
        {cta_label}
      </a>
      <p style="margin:18px 0 0;font-size:12px;color:#94a3b8;">
        No access has been granted. This is a notification only.
      </p>
    </div>
  </div>
</div>"""


def _users_page_url():
    """Absolute URL of the Users & Access page, for email buttons."""
    try:
        return request.url_root.rstrip('/') + '/admin/users'
    except RuntimeError:      # called outside a request context
        # Was hardcoded to localhost:5001, which is the recipient's own machine
        # once the email leaves this host. Comes from TI_DASHBOARD_PUBLIC_URL
        # (falling back to TI_PUBLIC_BASE_URL) now.
        return config.DASHBOARD_BASE_URL + '/admin/users'


def _notify_admins_access_request(req, provider_label):
    """In-app + email notification that someone is waiting for access."""
    email = (req or {}).get('email', 'unknown')
    name = (req or {}).get('display_name') or email
    pending = db.count_pending_access_requests()
    db.log_system_event(
        'WARNING',
        f'Access request from {name} <{email}> via {provider_label} — '
        f'{pending} request(s) awaiting review',
        'ACCESS_CONTROL',
    )
    try:
        socketio.emit('access_request_new', {
            'email': email, 'display_name': name,
            'provider': provider_label, 'pending': pending,
        })
    except Exception as e:
        logger.warning(f"Could not emit access_request_new: {e}")
    logger.info(f"🔔 Access request filed: {email} via {provider_label}")

    _send_admin_notification(
        f"Access request: {name} wants access to Weekly Cyber Watch",
        _onboarding_email_html(
            "Someone is waiting for access",
            "They tried to sign in but have no account. Review the request and "
            "choose a role, or reject it.",
            [("Name", name), ("Email", email), ("Signed in with", provider_label),
             ("Pending requests", str(pending))],
            "Review access requests",
            _users_page_url(),
        ),
    )


def _notify_admins_new_member(user, role):
    """A pre-approved (allow-listed) account finished onboarding. They are in as
    a read-only viewer; the admin decides whether to give them more."""
    email = (user or {}).get('email', 'unknown')
    name = (user or {}).get('name') or email
    db.log_system_event(
        'INFO',
        f'New team member onboarded: {name} <{email}> — '
        f'starting role "{ROLE_LABELS.get(role, role)}"',
        'ACCESS_CONTROL',
    )
    try:
        socketio.emit('team_member_joined', {'email': email, 'display_name': name, 'role': role})
    except Exception as e:
        logger.warning(f"Could not emit team_member_joined: {e}")

    _send_admin_notification(
        f"New team member: {name} joined Weekly Cyber Watch",
        _onboarding_email_html(
            "A new user completed sign-up",
            "Their email domain is allow-listed, so they are in with the "
            "read-only starting role. Raise their role if they need more.",
            [("Name", name), ("Email", email),
             ("Starting role", ROLE_LABELS.get(role, role)),
             ("Signed in with", (user or {}).get('provider') or 'firebase')],
            "Manage roles",
            _users_page_url(),
        ),
    )


@app.route('/login')
def login_page():
    if session.get('user'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    # IP-keyed only: there is no trustworthy email to key on until the token
    # verifies. Bounds anonymous token-spraying, which otherwise costs us a
    # signature check (and possibly a Google cert refetch) per attempt.
    locked = _throttle_check()
    if locked:
        return locked

    data = request.get_json(silent=True) or {}
    id_token = data.get('idToken')
    claims = verify_id_token(id_token)
    if not claims:
        _throttle_fail()
        return jsonify({'error': 'invalid_token'}), 401
    user = user_from_claims(claims)

    # Has this Firebase user already completed onboarding?
    profile = db.get_user_profile(user['uid'])

    # Identity is genuine (Firebase verified the token), but only allow-listed
    # organization accounts may use the platform. Anyone else who reaches this
    # point is a real, verified person asking to be let in — file an access
    # request so an admin can decide, instead of a dead end.
    # An admin-provisioned profile is itself an authorization, so a user who
    # already has one is let through regardless of the domain allow-list.
    if not profile and not is_email_allowed(user.get('email')):
        logger.warning(f"⛔ Sign-in denied (not allow-listed): {user.get('email')}")
        provider_label = 'Google' if user.get('provider') == 'google.com' else 'Email + password'
        try:
            result = db.record_access_request(
                email=user.get('email'),
                display_name=user.get('name'),
                uid=user.get('uid'),
                provider='google' if user.get('provider') == 'google.com' else 'password',
            )
        except Exception as e:
            logger.error(f"Could not file access request for {user.get('email')}: {e}")
            return jsonify({
                'error': 'not_authorized',
                'message': 'Your account is not authorized for this platform.',
            }), 403

        if result['outcome'] == 'submitted':
            _notify_admins_access_request(result['request'], provider_label)
            message = ('Your access request has been sent to the administrators. '
                       "You'll be able to sign in once it is approved.")
        elif result['outcome'] == 'already_pending':
            message = ('You already have a request waiting. An administrator '
                       'will review it shortly.')
        else:  # exists_inactive — the profile lookup above missed it (different uid)
            message = ('Your account is disabled. Please contact an administrator.')
        return jsonify({
            'error': 'access_request',
            'outcome': result['outcome'],
            'message': message,
        }), 403

    if profile:
        if not int(profile.get('active', 1) or 0):
            logger.warning(f"⛔ Sign-in denied (account disabled): {user.get('email')}")
            return jsonify({
                'error': 'account_disabled',
                'message': 'Your account is disabled. Please contact an administrator.',
            }), 403
        user['profile_complete'] = True
        user['profile'] = profile
        db.touch_user_login(user['uid'])
    else:
        user['profile_complete'] = False

    _throttle_reset()
    session.permanent = True
    session['user'] = user
    logger.info(
        f"🔐 Login: {user.get('email')} via {user.get('provider')} "
        f"(profile_complete={user['profile_complete']})"
    )
    return jsonify({
        'status': 'ok',
        'user': user,
        'role': effective_role(user) if user['profile_complete'] else None,
        'needs_setup': not user['profile_complete'],
    })


@app.route('/api/auth/local-login', methods=['POST'])
def auth_local_login():
    """Sign in a local (non-Firebase) account with email + password.

    Local accounts are created by an admin in the Users & Roles panel and are
    authorized by their existence, so they skip the Firebase domain allow-list.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    # Password guessing is only bounded by whatever we do here — werkzeug's
    # PBKDF2 verify is slow but not slow enough to be the limit on its own.
    locked = _throttle_check(email)
    if locked:
        return locked

    profile = db.verify_local_user(email, password)
    if not profile:
        _throttle_fail(email)
        logger.warning(f"⛔ Local sign-in failed for: {email or '(blank)'}")
        # Distinguish "we disabled you" from "wrong password" only for accounts
        # that genuinely exist here — this leaks nothing an admin didn't already
        # decide, and stops a revoked user from retyping their password forever.
        existing = db.get_user_profile_by_email(email) if email else None
        if existing and not int(existing.get('active', 1) or 0):
            return jsonify({
                'error': 'account_disabled',
                'message': 'Your account is disabled. Please contact an administrator.',
            }), 403
        return jsonify({
            'error': 'invalid_credentials',
            'message': 'Email or password is incorrect.',
            # Lets the login page offer "Request access" when there is no
            # account at all, rather than only "wrong password".
            'unknown_account': existing is None,
        }), 401

    user = {
        'uid': profile['uid'],
        'email': profile['email'],
        'name': profile.get('display_name') or profile['email'].split('@')[0],
        'picture': None,
        'provider': 'local',
        'profile_complete': True,
        'profile': profile,
    }
    _throttle_reset(email)
    db.touch_user_login(profile['uid'])
    session.permanent = True
    session['user'] = user
    logger.info(f"🔐 Login: {user['email']} via local (role={effective_role(user)})")
    return jsonify({
        'status': 'ok',
        'user': user,
        'role': effective_role(user),
        'needs_setup': False,
    })


@app.route('/api/auth/request-access', methods=['POST'])
def auth_request_access():
    """Ask an admin for an account. Public by necessity — the requester has no
    session yet — so it grants nothing, stores no credentials, and de-duplicates
    by email so repeat submissions can't be used to spam the admins.

    De-duplication bounds repeats of the *same* address; the throttle below
    bounds the other direction — one source submitting a stream of distinct
    addresses, each of which would otherwise fan out a mail to every admin."""
    locked = _throttle_check(scope="access_request")
    if locked:
        return locked

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    name = (data.get('name') or '').strip()[:200]
    reason = (data.get('reason') or '').strip()[:500]

    if not email or '@' not in email or len(email) > 200:
        return jsonify({'error': 'invalid_email',
                        'message': 'Enter a valid work email address.'}), 400

    try:
        result = db.record_access_request(
            email=email, display_name=name or None, uid=None,
            provider='form', note=reason or None,
        )
    except Exception as e:
        logger.error(f"Access request failed for {email}: {e}")
        return jsonify({'error': 'request_failed',
                        'message': 'Could not submit your request. Try again later.'}), 500

    messages = {
        'submitted': ('Request sent. An administrator will review it and you will '
                      'be able to sign in once approved.'),
        'already_pending': ('You already have a request waiting. An administrator '
                            'will review it shortly.'),
        'exists_active': 'You already have an account — try signing in.',
        'exists_inactive': 'Your account is disabled. Please contact an administrator.',
    }
    if result['notify']:
        # Count only submissions that actually fan out mail — a duplicate that
        # notifies nobody costs nothing and shouldn't burn the caller's budget.
        _throttle_fail(scope="access_request")
        _notify_admins_access_request(result['request'], 'Request form')
    # Always 200 — the outcome is in the body. Note the reply does say whether
    # an account already exists: on an internal tool, telling a colleague "you
    # already have an account, just sign in" is worth more than hiding it from
    # someone who could learn the same thing from the staff directory.
    return jsonify({'status': 'ok', 'outcome': result['outcome'],
                    'message': messages.get(result['outcome'], 'Request received.')})


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    email = (session.get('user') or {}).get('email')
    session.clear()
    if email:
        logger.info(f"🔓 Logout: {email}")
    return jsonify({'status': 'ok'})


@app.route('/api/auth/me')
def auth_me():
    user = session.get('user')
    if not user:
        return jsonify({'authenticated': False}), 401
    role = effective_role(user)
    return jsonify({
        'authenticated': True,
        'user': user,
        'role': role,
        'role_label': ROLE_LABELS.get(role, role),
        # Convenience booleans so the frontend doesn't re-encode the hierarchy.
        'is_admin': role == ROLE_ADMIN,
        'can_operate': role in ('analyst_admin', 'admin'),
    })


# ─── Profile setup (first-time onboarding) ─────────────────────────────
@app.route('/setup-profile')
def setup_profile_page():
    user = session.get('user')
    if not user:
        return redirect(url_for('login_page'))
    if user.get('profile_complete'):
        return redirect(url_for('dashboard'))
    return render_template('setup_profile.html', user=user)


@app.route('/api/profile/setup', methods=['POST'])
def api_profile_setup():
    user = session.get('user')
    if not user:
        return jsonify({'error': 'not_signed_in'}), 401

    data = request.get_json(silent=True) or {}

    def _clean(v, limit=200):
        if v is None:
            return None
        v = str(v).strip()
        return v[:limit] if v else None

    display_name = _clean(data.get('display_name'))
    role         = _clean(data.get('role'),         60)
    department   = _clean(data.get('department'),   120)
    phone        = _clean(data.get('phone'),        40)
    notification_email = _clean(data.get('notification_email'), 200)

    if not display_name:
        return jsonify({'error': 'display_name_required'}), 400
    # Privileged roles are NEVER self-assignable here — an existing admin grants
    # them afterwards in the Users & Roles panel. Self-onboarding always lands on
    # the read-only "Dashboard Viewer" role regardless of what was submitted.
    role = normalize_role(role)
    if role not in SELF_SIGNUP_ROLES:
        role = ROLE_VIEWER

    try:
        db.upsert_user_profile(
            uid=user['uid'],
            email=user.get('email') or '',
            display_name=display_name,
            role=role,
            department=department,
            phone=phone,
            notification_email=notification_email,
        )
    except Exception as e:
        logger.error(f"Failed to save profile for {user.get('email')}: {e}")
        return jsonify({'error': 'save_failed'}), 500

    # Refresh the session so the auth-gate now lets them through.
    profile = db.get_user_profile(user['uid'])
    was_new = not user.get('profile_complete')
    user['profile_complete'] = True
    user['profile'] = profile
    user['name'] = display_name  # display name takes precedence in the UI
    session['user'] = user
    logger.info(f"✅ Profile saved: {user.get('email')} (role={role})")

    # First time through onboarding → tell the admins someone joined, so they
    # can grant more than the read-only starting role if that person needs it.
    # (Edits to an existing profile don't notify.)
    if was_new:
        try:
            _notify_admins_new_member(user, role)
        except Exception as e:
            logger.error(f"Could not notify admins about new member: {e}")

    return jsonify({'status': 'ok', 'user': user})


# ─── My account (self-service details & password) ───────────────────────
# Deliberately ungated beyond the global login gate: every signed-in user owns
# their own details. Nothing here can change a role — that stays with an admin
# in the Users & Access panel.

@app.route('/settings')
def account_settings_page():
    """Your own profile, role and password."""
    return render_template('settings.html')


def _password_mode(user, profile):
    """How this identity sets or changes its password.

    'local'    a password already exists — change it, current password required
    'set'      no password yet, so there is none to prove; the signed-in session
               is the proof. Offered to approved Google users so the account
               gains a second way in.
    'none'     nothing to change (the demo identity)

    The test is whether a hash exists, not how the account was created: someone
    who signed up through Google and then set a password is 'local' from here
    on, and can sign in either way.
    """
    provider = (user.get('provider') or '').strip().lower()
    if provider == 'demo':
        return 'none'
    if db.has_local_password(user.get('uid')):
        return 'local'
    return 'set'


# How the person got in, as the settings page labels it.
_PROVIDER_LABELS = {
    'google.com': 'Google sign-in',
    'password':   'Email + password (Firebase)',
    'local':      'Email + password (local account)',
    'demo':       'Demo mode',
}


@app.route('/api/profile/me')
def api_profile_me():
    """Everything the account-settings page shows about the signed-in user."""
    user = session.get('user')
    if not user:
        return jsonify({'error': 'not_signed_in'}), 401

    # Prefer the live DB row over the session snapshot: an admin may have
    # changed the role or department since this cookie was minted.
    profile = {}
    try:
        profile = db.get_user_profile(user.get('uid')) or {}
    except Exception as e:
        logger.warning(f"Could not read profile for {user.get('email')}: {e}")
        profile = user.get('profile') or {}

    role = effective_role(user)
    provider = (user.get('provider') or profile.get('auth_provider') or '').strip().lower()
    is_bootstrap = (user.get('email') or '').strip().lower() in _bootstrap_admin_set()

    return jsonify({
        'status': 'success',
        'account': {
            'uid': user.get('uid'),
            'email': user.get('email'),
            'name': profile.get('display_name') or user.get('name'),
            'picture': user.get('picture'),
            'provider': provider,
            'provider_label': _PROVIDER_LABELS.get(provider, 'Email + password'),
            'role': role,
            'role_label': ROLE_LABELS.get(role, role),
            'role_description': ROLE_DESCRIPTIONS.get(role, ''),
            'capabilities': [
                {'name': name, 'allowed': allowed}
                for name, allowed in ROLE_CAPABILITIES.get(role, [])
            ],
            'department': profile.get('department'),
            'phone': profile.get('phone'),
            'notification_email': profile.get('notification_email'),
            'created_at': profile.get('created_at'),
            'last_login': profile.get('last_login'),
            'active': bool(int(profile.get('active', 1) or 0)),
            'email_verified': bool(user.get('email_verified')),
            'identity_verified': is_verified_identity(user),
            'is_bootstrap': is_bootstrap,
            'password_mode': _password_mode(user, profile),
            'editable': provider != 'demo',
        },
    })


@app.route('/api/profile/update', methods=['POST'])
def api_profile_update():
    """Save the fields a user owns about themselves.

    Role is read from the stored row and written back unchanged — this endpoint
    must never be a privilege-escalation path, and passing None would wipe the
    role that an admin granted.
    """
    user = session.get('user')
    if not user:
        return jsonify({'status': 'error', 'error': 'not_signed_in'}), 401
    if (user.get('provider') or '').strip().lower() == 'demo':
        return jsonify({'status': 'error',
                        'message': 'The demo identity cannot be edited.'}), 403

    data = request.get_json(silent=True) or {}

    def _clean(v, limit=200):
        if v is None:
            return None
        v = str(v).strip()
        return v[:limit] if v else None

    display_name = _clean(data.get('display_name'))
    department = _clean(data.get('department'), 120)
    phone = _clean(data.get('phone'), 40)
    notification_email = _clean(data.get('notification_email'))

    if not display_name:
        return jsonify({'status': 'error',
                        'message': 'A display name is required.'}), 400
    if notification_email and '@' not in notification_email:
        return jsonify({'status': 'error',
                        'message': 'Enter a valid notification email, or leave it blank.'}), 400

    existing = db.get_user_profile(user.get('uid'))
    if not existing:
        return jsonify({'status': 'error',
                        'message': 'No profile on file — finish onboarding first.'}), 409

    try:
        db.upsert_user_profile(
            uid=user['uid'],
            email=existing.get('email') or user.get('email') or '',
            display_name=display_name,
            role=existing.get('role'),        # unchanged, on purpose
            department=department,
            phone=phone,
            notification_email=notification_email,
        )
    except Exception as e:
        logger.error(f"Profile update failed for {user.get('email')}: {e}")
        return jsonify({'status': 'error', 'message': 'Could not save your details.'}), 500

    profile = db.get_user_profile(user['uid'])
    user['profile'] = profile
    user['name'] = display_name
    session['user'] = user
    logger.info(f"✏️  Profile updated by {user.get('email')}")
    return jsonify({'status': 'success', 'account_name': display_name})


@app.route('/api/profile/password', methods=['POST'])
def api_profile_password():
    """Change your own password — local accounts only.

    Firebase identities never reach here: their credential lives with Firebase,
    so the settings page sends them a reset link from the browser instead.
    """
    user = session.get('user')
    if not user:
        return jsonify({'status': 'error', 'error': 'not_signed_in'}), 401

    profile = db.get_user_profile(user.get('uid')) or {}
    mode = _password_mode(user, profile)
    if mode == 'none':
        return jsonify({
            'status': 'error',
            'message': 'This identity cannot hold a password.',
        }), 409
    # 'set' is a first-time set: there is no current password to prove, so the
    # signed-in session is the authorisation. Deliberately only when no hash
    # exists — allowing it once one does would turn a stolen session into a
    # full account takeover needing no password at all.
    first_time = (mode == 'set')

    data = request.get_json(silent=True) or {}
    current = data.get('current_password') or ''
    new_password = data.get('new_password') or ''

    if len(new_password) < 8:
        return jsonify({'status': 'error',
                        'message': 'New password must be at least 8 characters.'}), 400
    if current and new_password == current:
        return jsonify({'status': 'error',
                        'message': 'The new password must differ from the current one.'}), 400

    # Proving the current password is what makes this self-service rather than
    # a session-hijack handing over the account. Throttled for the same reason
    # the login endpoint is: a stolen session should not also be an oracle for
    # guessing the password behind it.
    locked = _throttle_check(user.get('email'), scope="pwchange")
    if locked:
        return locked

    if not first_time:
        if not db.verify_local_user(user.get('email') or '', current):
            _throttle_fail(user.get('email'), scope="pwchange")
            logger.warning(f"🔑 Password change refused (bad current password): {user.get('email')}")
            return jsonify({'status': 'error',
                            'message': 'Your current password is incorrect.'}), 403
    _throttle_reset(user.get('email'), scope="pwchange")

    try:
        db.set_local_password(user['uid'], new_password)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 409
    except Exception as e:
        logger.error(f"Self password change failed for {user.get('email')}: {e}")
        return jsonify({'status': 'error', 'message': 'Could not change the password.'}), 500

    what = 'Password set' if first_time else 'Password changed'
    logger.info(f"🔑 {what} by {user.get('email')} (self-service)")
    db.log_system_event('WARNING',
                        f"{what} by {user.get('email')} (self-service)",
                        'ACCESS_CONTROL')
    return jsonify({'status': 'success'})


# Global status tracking
system_status = {
    'running': False,
    'current_operation': None,
    # Which stage of the work we're in: 'scraping' | 'selecting' | 'saving' |
    # 'sending' | 'clearing' | 'stopping' | 'done' | 'error'. The dashboard maps
    # this to an icon (OPERATION_ICONS in dashboard.html), so status messages
    # stay plain prose — no emoji, and rewording never changes the icon.
    'operation_phase': None,
    'operation_type': None,   # e.g. 'fresh_scraping' — lets the UI show a Stop button
    'last_scraping': None,
    'last_email_sent': None,
    'pending_approvals': 0,
    'scheduled_deliveries': 0,
    'next_delivery': None,
    'system_health': 'good'
}

def _set_operation(message, phase=None):
    """Set the live status message the dashboard shows in its header pill.

    `phase` is the machine-readable stage (see 'operation_phase' above); the UI
    derives the icon from it. Keep `message` plain prose — no emoji, no leading
    icon — because the UI already renders one and would otherwise show both.
    """
    system_status['current_operation'] = message
    system_status['operation_phase'] = phase


def update_system_status():
    """Update system status from database"""
    global system_status
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Count pending approvals (top 10 articles ready for manager approval)
        cursor.execute('''
            SELECT COUNT(*) FROM (
                SELECT id FROM news_articles 
                WHERE status = "pending"
                ORDER BY relevance_score DESC, created_at DESC 
                LIMIT 10
            )
        ''')
        system_status['pending_approvals'] = cursor.fetchone()[0]
        
        # Count scheduled deliveries
        cursor.execute('SELECT COUNT(*) FROM soc_deliveries WHERE status = "pending"')
        system_status['scheduled_deliveries'] = cursor.fetchone()[0]

        # …and when the earliest one actually goes out. The dashboard had a
        # "Next Delivery" field that nothing ever wrote to, so it showed
        # "Loading..." permanently.
        cursor.execute(
            'SELECT MIN(scheduled_time) FROM soc_deliveries WHERE status = "pending"'
        )
        system_status['next_delivery'] = cursor.fetchone()[0]
        
        # Get last scraping time
        cursor.execute('SELECT MAX(created_at) FROM news_articles')
        last_scrape = cursor.fetchone()[0]
        system_status['last_scraping'] = last_scrape
        
        conn.close()
        
        # Emit update to all connected clients (only if socketio is available)
        try:
            socketio.emit('status_update', system_status)
        except Exception as e:
            # No client connected yet, or the server isn't accepting emits during
            # startup. Not worth failing the status refresh over, but a bare
            # `except: pass` here also swallowed KeyboardInterrupt.
            logger.debug(f"status_update emit skipped: {e}")
        
    except Exception as e:
        logger.error(f"Error updating system status: {e}")
        system_status['system_health'] = 'error'

@app.route('/')
def dashboard():
    """Main dashboard page"""
    update_system_status()
    return render_template('dashboard.html', status=system_status)

@app.route('/healthz')
def healthz():
    """Fast liveness probe (unauthenticated, no network calls). Point an
    uptime monitor here; anything but HTTP 200 means the app is unhealthy."""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH, timeout=3)
        try:
            conn.execute("SELECT 1")
        finally:
            conn.close()
        return jsonify({'status': 'ok'}), 200
    except Exception:
        return jsonify({'status': 'error'}), 503

@app.route('/api/health')
@require_admin
def api_health():
    """Full health report (same checks as `python health_checks.py`).
    Default is the fast subset; add ?deep=1 to also probe news feeds and
    SMTP reachability (takes a few seconds, sends no email)."""
    from health_checks import run_all_checks
    deep = request.args.get('deep') in ('1', 'true', 'yes')
    report = run_all_checks(deep=deep)
    return jsonify(report), (200 if report['status'] != 'fail' else 503)

@app.route('/api/fresh_scraping', methods=['POST'])
@require_operator
def fresh_scraping():
    """API endpoint to perform fresh scraping and start complete workflow.
    Window is fixed at the last 7 days (top 10 articles by relevance)."""
    try:
        # Clear any stale cancel flag from a previous run before we begin.
        scraper.cancel_requested.clear()

        system_status['running'] = True
        system_status['operation_type'] = 'fresh_scraping'
        _set_operation('Starting a fresh scrape of the last 7 days…', 'scraping')
        socketio.emit('status_update', system_status)

        thread = threading.Thread(target=fresh_scraping_async)
        thread.daemon = True
        thread.start()

        return jsonify({'success': True, 'message': 'Fresh scraping started (last 7 days)'})

    except Exception as e:
        logger.error(f"Error starting fresh scraping: {e}")
        system_status['running'] = False
        system_status['operation_type'] = None
        _set_operation(None)
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})


@app.route('/api/stop_scraping', methods=['POST'])
@require_operator
def stop_scraping():
    """Ask the running fresh-scrape to stop. The scraper checks this flag
    between sources and aborts without saving partial results or emailing."""
    try:
        if not system_status.get('running') or system_status.get('operation_type') != 'fresh_scraping':
            return jsonify({'success': False, 'message': 'No scrape is currently running.'})

        scraper.cancel_requested.set()
        _set_operation('Stopping — finishing the current source first…', 'stopping')
        socketio.emit('status_update', system_status)

        return jsonify({'success': True, 'message': 'Stop requested. The scrape will stop shortly.'})

    except Exception as e:
        logger.error(f"Error stopping scrape: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

# POST only. This used to accept GET as well, which made it reachable by
# cross-site top-level navigation: SameSite=Lax withholds the session cookie
# from cross-site POSTs but *sends* it on a plain link click, so any page an
# operator visited could kick off the whole Manager → Sender → SOC workflow —
# and that workflow sends real email. There are no CSRF tokens in this app;
# keeping state-changing endpoints POST-only is what makes SameSite=Lax
# sufficient. Do not re-add 'GET' here.
@app.route('/api/run_system', methods=['POST'])
@require_operator
def run_system():
    """API endpoint to start workflow with already scraped news: Manager → Sender → SOC"""
    try:
        system_status['running'] = True
        _set_operation('Starting the review workflow…')
        socketio.emit('status_update', system_status)

        # Start async operation
        thread = threading.Thread(target=run_system_async)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': 'System started successfully'})
    
    except Exception as e:
        logger.error(f"Error starting system: {e}")
        system_status['running'] = False
        _set_operation(None)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/send_to_manager', methods=['POST'])
@require_operator
def send_to_manager():
    """API endpoint to send current articles to manager for approval"""
    try:
        # Get pending articles (max 10)
        articles = db.get_pending_articles_for_manager(10)
        
        if not articles:
            return jsonify({'success': False, 'message': 'No articles found to send to manager'})
        
        # Send to manager
        success = email_system.send_manager_approval_email(articles)
        
        if success:
            return jsonify({
                'success': True, 
                'message': f'Successfully sent {len(articles)} articles to manager',
                'count': len(articles)
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to send email to manager'})
    
    except Exception as e:
        logger.error(f"Error sending to manager: {e}")
        return jsonify({'success': False, 'message': str(e)})

def run_system_async():
    """Start workflow with already scraped news: Send to manager → Sender validation → SOC delivery"""
    try:
        # Step 1: Start workflow
        system_status['running'] = True
        _set_operation('Checking for scraped articles…')
        socketio.emit('status_update', system_status)
        
        # Get all scraped articles (not yet sent to manager)
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM news_articles 
            WHERE status = 'pending' OR status = 'scraped'
        """)
        total_scraped = cursor.fetchone()[0]
        conn.close()
        
        if total_scraped == 0:
            _set_operation('No scraped articles yet — run Scraper first.', 'error')
            system_status['running'] = False
            socketio.emit('status_update', system_status)
            socketio.emit('operation_complete', {
                'success': False,
                'message': 'No scraped articles yet — run Scraper first.',
                'articles_count': 0,
                'total_scraped': 0
            })
            return
        
        # Step 2: Get top 10 articles for manager
        _set_operation(f'Ranking {total_scraped} articles to pick the top 10…', 'selecting')
        socketio.emit('status_update', system_status)
        
        articles = db.get_pending_articles_for_manager(10)  # Top 10 articles
        print(f"🔍 DEBUG: Retrieved {len(articles) if articles else 0} articles for manager email")
        
        if articles:
            # Step 3: Send manager email with beautiful formatting
            # Read the address from config — this used to be a hardcoded dev
            # address, which showed the wrong recipient once /admin was changed.
            _set_operation(
                f'Sending {len(articles)} articles to {config.MANAGER_EMAIL}…',
                'sending')
            socketio.emit('status_update', system_status)
            
            print(f"📧 DEBUG: Attempting to send email to manager with {len(articles)} articles")
            
            try:
                success = email_system.send_manager_approval_email(articles)
                print(f"📧 DEBUG: Email send result: {success}")
                
                if success:
                    _set_operation(
                        f'Sent {len(articles)} articles to {config.MANAGER_EMAIL} — '
                        f'awaiting approval.', 'done')
                    system_status['last_email_sent'] = datetime.now().isoformat()
                    
                    # Log the operation
                    db.log_system_event(
                        'INFO',
                        f'Manager workflow started: {len(articles)} articles sent from {total_scraped} scraped',
                        'START_WORKFLOW'
                    )
                    
                    # Log activity for dashboard
                    db.log_activity(
                        'EMAIL_SENT',
                        f'Manager approval email sent with {len(articles)} articles',
                        details=f'Total scraped: {total_scraped}',
                        component='WORKFLOW'
                    )
                    print(f"✅ Manager email sent successfully!")
                else:
                    _set_operation(
                        'Could not send the approval email — check the SMTP '
                        'settings in Admin.', 'error')
                    print(f"❌ Manager email send failed!")

            except Exception as email_error:
                _set_operation(f'Could not send the approval email — {email_error}',
                               'error')
                print(f"❌ Email error: {email_error}")
                success = False
        else:
            _set_operation(
                f'None of the {total_scraped} scraped articles were relevant enough '
                f'to send.', 'error')
            print(f"❌ No articles retrieved for manager email from {total_scraped} scraped articles")
        
        # Update final status
        system_status['running'] = False
        update_system_status()
        
        # Emit completion
        socketio.emit('operation_complete', {
            'success': bool(articles),
            'message': system_status['current_operation'],
            'articles_count': len(articles) if articles else 0,
            'total_scraped': total_scraped
        })
        
    except Exception as e:
        logger.error(f"Error in run_system_async: {e}")
        system_status['running'] = False
        _set_operation(f'The workflow stopped unexpectedly — {e}', 'error')
        socketio.emit('status_update', system_status)

def fresh_scrape_async():
    """Enhanced scraping — pull 10+ articles from every configured source."""
    try:
        # Step 2: Enhanced scraping with better targeting
        from config import NEWS_SOURCES

        # Step 1: Start enhanced scraping. Count the sources rather than
        # hardcoding it — the message used to claim 4 while config had 1.
        source_count = len(NEWS_SOURCES)
        _set_operation(
            f'Starting a scrape of {source_count} '
            f'{"source" if source_count == 1 else "sources"}…', 'scraping')
        system_status['running'] = True
        socketio.emit('status_update', system_status)

        all_articles = []
        articles_found = 0
        target_articles = 15  # Increased target for better selection
        
        # Add debug logging
        logger.info(f"🔍 FRESH_SCRAPE: Starting scraping from {len(NEWS_SOURCES)} sources")
        print(f"🔍 FRESH_SCRAPE: Starting scraping from {len(NEWS_SOURCES)} sources")
        
        for i, source in enumerate(NEWS_SOURCES):
            if articles_found >= target_articles:
                break
                
            _set_operation(
                f'Scraping {source["name"]} — {articles_found} of '
                f'{target_articles} articles so far…', 'scraping')
            socketio.emit('status_update', system_status)
            
            try:
                logger.info(f"📰 FRESH_SCRAPE: Scraping {source['name']} from {source['rss']}")
                print(f"📰 FRESH_SCRAPE: Scraping {source['name']} from {source['rss']}")
                
                # Use scraper's RSS method with enhanced error handling
                articles = scraper.scrape_rss_feed(source)

                # Same fallback as run_scraping_session_limited: if RSS yields
                # nothing (feed blocked/unreachable), scrape the site directly.
                if not articles:
                    logger.warning(f"FRESH_SCRAPE: RSS empty for {source['name']}, falling back to direct scraping")
                    print(f"⚠️ FRESH_SCRAPE: RSS empty for {source['name']}, trying direct scraping...")
                    articles = scraper.scrape_website_direct(source)

                logger.info(f"📊 FRESH_SCRAPE: Got {len(articles) if articles else 0} articles from {source['name']}")
                print(f"📊 FRESH_SCRAPE: Got {len(articles) if articles else 0} articles from {source['name']}")
                
                if articles:
                    # Add articles until we reach target, but get the best ones
                    for article in articles[:5]:  # Take top 5 from each source
                        if articles_found >= target_articles:
                            break
                        all_articles.append(article)
                        articles_found += 1
                        
                        # Real-time feedback
                        title_preview = article.get("title", "Unknown")[:40] + "…"
                        _set_operation(
                            f'Found {articles_found} of {target_articles}: '
                            f'{title_preview}', 'scraping')
                        socketio.emit('status_update', system_status)
                        
                        print(f"✅ FRESH_SCRAPE: Added article {articles_found}: {title_preview}")
                        
            except Exception as e:
                logger.error(f"❌ FRESH_SCRAPE: Error scraping {source['name']}: {e}")
                print(f"❌ FRESH_SCRAPE: Error scraping {source['name']}: {e}")
                continue
            
            # Shorter rate limiting for faster scraping
            time.sleep(0.3)
        
        # Step 3: Save exactly the articles we found to database
        _set_operation(f'Saving {len(all_articles)} articles…', 'saving')
        socketio.emit('status_update', system_status)
        
        articles_saved = 0
        if all_articles:
            # Save each article individually for better control
            for article in all_articles:
                article_id = db.add_news_article(
                    title=article.get('title', ''),
                    summary=article.get('summary', ''),
                    content=article.get('content', ''),
                    url=article.get('url', ''),
                    source=article.get('source', ''),
                    keywords=article.get('keywords', []),
                    relevance_score=article.get('relevance_score', 0)
                )
                if article_id:
                    articles_saved += 1
        
        # Step 4: Complete and update counts
        _set_operation(
            f'Scrape finished — {articles_saved} articles saved and ready for review.',
            'done')
        system_status['running'] = False
        system_status['pending_approvals'] = articles_saved
        
        # Update system status to reflect new pending approvals
        update_system_status()
        
        # Log the operation
        db.log_system_event(
            'INFO',
            f'Fast scraping completed: {articles_saved} articles saved',
            'FAST_SCRAPING'
        )
        
        # Emit completion with clear numbers
        socketio.emit('operation_complete', {
            'success': True,
            'message': f'Scrape finished — {articles_saved} articles saved and ready for review.',
            'articles_count': articles_saved,
            'total_found': articles_saved  # Same number for clarity
        })

    except Exception as e:
        logger.error(f"Error in fresh_scrape_async: {e}")
        system_status['running'] = False
        _set_operation(f'The scrape stopped unexpectedly — {e}', 'error')
        socketio.emit('status_update', system_status)

def fresh_scraping_async():
    """Fresh scraping with proper 1-10 numbering for manager approval.
    Always scrapes the last 7 days."""
    try:
        # Step 1: Clear ALL existing articles for truly fresh start
        _set_operation('Clearing previous articles…', 'clearing')
        system_status['running'] = True
        socketio.emit('status_update', system_status)

        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()

        # Clear ALL articles for fresh start
        cursor.execute('DELETE FROM news_articles')
        cursor.execute('DELETE FROM manager_approvals')
        cursor.execute('DELETE FROM soc_deliveries')
        cursor.execute('DELETE FROM sender_validations')
        conn.commit()
        conn.close()

        # Step 2: Enhanced scraping to get EXACTLY 10 quality articles (last 7 days)
        _set_operation(
            f'Scraping the last 7 days for the top '
            f'{config.MAX_NEWS_TO_MANAGER} articles…', 'scraping')
        socketio.emit('status_update', system_status)

        # Run the scraping session — last 7 days, top 10 by relevance
        scraping_results = scraper.run_scraping_session_limited(config.MAX_NEWS_TO_MANAGER)

        # If the user stopped the scrape, halt here: nothing was saved and
        # nothing goes to the manager.
        if scraping_results and scraping_results.get('cancelled'):
            system_status['running'] = False
            system_status['operation_type'] = None
            _set_operation('Stopped at your request — nothing was saved or emailed.',
                           'done')
            db.log_system_event('INFO', 'Fresh scraping stopped by user', 'FRESH_SCRAPING_WORKFLOW')
            update_system_status()
            socketio.emit('operation_complete', {
                'success': False,
                'cancelled': True,
                'message': 'Scraping stopped at your request. No articles were saved, and nothing was sent to the manager.',
                'articles_count': 0,
                'total_scraped': 0
            })
            return

        # Step 3: Get exactly 10 articles and number them 1-10 (NO DOUBLE NUMBERING)
        _set_operation('Ranking the top 10 articles…', 'selecting')
        socketio.emit('status_update', system_status)
        
        # FIRST: Clean up any existing articles with multiple numbering
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Get all articles and clean their titles
        cursor.execute('SELECT id, title FROM news_articles')
        all_articles_to_clean = cursor.fetchall()
        
        for article_id, title in all_articles_to_clean:
            import re
            # Clean title of all existing numbering
            clean_title = title
            clean_title = re.sub(r'^\d+\.\s*', '', clean_title)
            clean_title = re.sub(r'^#?\d+\.\s*', '', clean_title)
            clean_title = re.sub(r'\s+', ' ', clean_title).strip()
            
            # Update only if title changed
            if clean_title != title:
                cursor.execute('UPDATE news_articles SET title = ? WHERE id = ?', (clean_title, article_id))
        
        conn.commit()
        conn.close()
        
        # Get exactly 10 newly scraped articles
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Get exactly 10 articles that were just scraped
        cursor.execute('''
            SELECT id, title, summary, content, url, source, relevance_score, keywords, created_at
            FROM news_articles 
            WHERE status = 'pending'
            ORDER BY relevance_score DESC, created_at DESC
            LIMIT 10
        ''')
        
        top_articles = cursor.fetchall()
        
        if top_articles:
            # Update articles with proper numbering (1-10) - FIXED: No double numbering
            for i, article_data in enumerate(top_articles, 1):
                article_id = article_data[0]
                original_title = article_data[1]
                
                # FIXED: Remove any existing numbering first, then add clean numbering
                clean_title = original_title
                # Remove all existing numbering patterns like "01. ", "1. ", "001. ", etc.
                import re
                clean_title = re.sub(r'^\d+\.\s*', '', clean_title)
                # Also remove patterns like "#1. ", "#01. ", etc.
                clean_title = re.sub(r'^#?\d+\.\s*', '', clean_title)
                # Remove multiple consecutive spaces
                clean_title = re.sub(r'\s+', ' ', clean_title).strip()
                
                # Add clean numbering
                numbered_title = f"{i:02d}. {clean_title}"
                
                cursor.execute('''
                    UPDATE news_articles 
                    SET title = ?, status = 'pending'
                    WHERE id = ?
                ''', (numbered_title, article_id))
                
                _set_operation(f'Ranked {i} of 10: {clean_title[:40]}…', 'selecting')
                socketio.emit('status_update', system_status)
        
        conn.commit()
        conn.close()
        
        # Step 4: Send to manager for approval
        if top_articles:
            # Keep this short: the header pill truncates at ~440px, and the
            # recipient is the part worth seeing mid-send.
            _set_operation(
                f'Sending {len(top_articles)} articles to {config.MANAGER_EMAIL}…',
                'sending')
            socketio.emit('status_update', system_status)
            
            # Get the updated articles for email
            articles_for_email = db.get_pending_articles_for_manager(10)
            
            if articles_for_email:
                success = email_system.send_manager_approval_email(articles_for_email)

                if success:
                    _set_operation(
                        f'Sent {len(articles_for_email)} articles to '
                        f'{config.MANAGER_EMAIL} — awaiting approval.', 'done')
                    system_status['last_email_sent'] = datetime.now().isoformat()

                    # Log the operation
                    db.log_system_event(
                        'INFO',
                        f'Fresh scraping workflow: {len(articles_for_email)} articles sent to manager',
                        'FRESH_SCRAPING_WORKFLOW'
                    )
                else:
                    err = getattr(email_system, '_last_error', None) or 'see the server log'
                    _set_operation(f'Could not send the approval email — {err}', 'error')
            else:
                _set_operation('Nothing to email — no articles were ranked.', 'error')
        else:
            _set_operation('The scrape found no relevant articles.', 'error')
        
        # Step 5: Complete operation
        system_status['running'] = False
        system_status['operation_type'] = None
        update_system_status()

        # Emit completion
        socketio.emit('operation_complete', {
            'success': len(top_articles) > 0,
            'message': system_status['current_operation'],
            'articles_count': len(top_articles) if top_articles else 0,
            'total_scraped': scraping_results.get('articles_saved_to_db', 0) if scraping_results else 0
        })
        
    except Exception as e:
        logger.error(f"Error in fresh_scraping_async: {e}")
        system_status['running'] = False
        system_status['operation_type'] = None
        _set_operation(f'The scrape stopped unexpectedly — {e}', 'error')
        socketio.emit('status_update', system_status)
        socketio.emit('operation_complete', {
            'success': False,
            'message': f'Fresh scraping failed: {str(e)}',
            'articles_count': 0,
            'total_scraped': 0
        })

@app.context_processor
def _inject_firebase_config():
    """Make the Firebase browser config and branding available to every template.

    The three sign-in templates used to each carry their own hardcoded copy of
    firebaseConfig — three places to keep in sync, and the project identifiers
    baked into committed files. They now render this single server-supplied
    value, sourced from TI_FIREBASE_* in the gitignored .env.

    `brand` does the same for the logo, wordmark and favicon, which were six
    templates' worth of hardcoded company asset paths. Defaults are neutral; a
    deployment sets TI_BRAND_* to restore its own identity.
    """
    return {
        'firebase_config': config.FIREBASE_CONFIG,
        'firebase_configured': config.FIREBASE_CONFIGURED,
        'brand': config.BRAND,
    }


def _require_internal_caller():
    """Reject anything that isn't one of our own local processes.

    Two independent conditions, both required:

    1. An HMAC token in the X-Internal-Token header, signed with the shared
       .flask_secret_key. Only a process running as the app user on this host
       can mint one.
    2. The peer address is loopback.

    The IP check alone used to be the whole gate, and it quietly stops being a
    gate the moment a reverse proxy is added: nginx connects from 127.0.0.1, so
    every proxied request — including one from the public internet — would have
    passed. ProxyFix restores the real client IP when a proxy is configured, and
    the token means the guard holds even if the proxy setup is wrong.
    """
    token = request.headers.get(INTERNAL_HEADER, '')
    if not verify_internal_token(token):
        logger.warning(
            f"🚫 notify_* rejected — missing/invalid {INTERNAL_HEADER} "
            f"(from {request.remote_addr})"
        )
        return jsonify({'error': 'forbidden'}), 403

    remote = request.remote_addr or ''
    if remote not in ('127.0.0.1', '::1', 'localhost'):
        logger.warning(f"🚫 notify_* called from non-local address: {remote}")
        return jsonify({'error': 'forbidden'}), 403
    return None


@app.route('/api/notify_approval', methods=['POST'])
def notify_approval():
    """Handle approval notifications from callback server"""
    deny = _require_internal_caller()
    if deny:
        return deny
    try:
        data = request.get_json()
        article_id = data.get('article_id')
        status = data.get('status')
        message = data.get('message')
        
        logger.info(f"📢 Dashboard notification: Article {article_id} {status}")
        
        # Update system status
        update_system_status()
        
        # Emit real-time update to all connected clients
        socketio.emit('approval_notification', {
            'article_id': article_id,
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({'success': True, 'message': 'Notification received'})
    
    except Exception as e:
        logger.error(f"Error handling approval notification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notify_validation', methods=['POST'])
def notify_validation():
    """Handle validation notifications"""
    deny = _require_internal_caller()
    if deny:
        return deny
    try:
        data = request.get_json()
        article_id = data.get('article_id')
        status = data.get('status')
        message = data.get('message')
        
        logger.info(f"📢 Dashboard validation notification: Article {article_id} {status}")
        
        # Update system status
        update_system_status()
        
        # Emit real-time update
        socketio.emit('validation_notification', {
            'article_id': article_id,
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({'success': True, 'message': 'Validation notification received'})
    
    except Exception as e:
        logger.error(f"Error handling validation notification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/notify_delivery', methods=['POST'])
def notify_delivery():
    """Handle SOC delivery notifications"""
    deny = _require_internal_caller()
    if deny:
        return deny
    try:
        data = request.get_json()
        article_id = data.get('article_id')
        status = data.get('status')
        message = data.get('message')
        
        logger.info(f"📢 Dashboard delivery notification: Article {article_id} {status}")
        
        # Update system status
        update_system_status()
        
        # Emit real-time update
        socketio.emit('delivery_notification', {
            'article_id': article_id,
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({'success': True, 'message': 'Delivery notification received'})
    
    except Exception as e:
        logger.error(f"Error handling delivery notification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/api/fresh-scrape', methods=['POST'])
@require_operator
def fresh_scrape():
    """Fresh scraping with complete data reset - clean start"""
    try:
        # Clear all existing data first for truly fresh start
        import sqlite3
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Clear all data tables
        tables_to_clear = [
            "news_articles", "manager_approvals", "soc_deliveries", 
            "sender_validations", "scraping_sessions", "system_logs"
        ]
        
        for table in tables_to_clear:
            try:
                cursor.execute(f"DELETE FROM {table}")
            except sqlite3.Error as e:
                # A missing table is fine (older database). Anything else —
                # notably "database is locked" — used to be swallowed silently
                # here, so a wipe that only half happened still reported a clean
                # fresh start. Say so instead.
                logger.warning(f"Could not clear {table}: {e}")

        conn.commit()
        conn.close()
        
        # Log the fresh start
        db.log_system_event('INFO', 'Fresh scraping started - all data cleared', 'FRESH_SCRAPING')
        
        system_status['running'] = True
        _set_operation('Previous data cleared — starting the scrape…', 'clearing')
        socketio.emit('status_update', system_status)
        
        # Start async operation
        thread = threading.Thread(target=fresh_scrape_async)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': 'Fresh scraping started with data reset'})
    except Exception as e:
        logger.error(f"Error starting fresh scraping: {e}")
        return jsonify({'success': False, 'message': f'Failed to start scraping: {str(e)}'})

@app.route('/api/news')
def get_news():
    """Get all news articles with filters"""
    try:
        status_filter = request.args.get('status', 'all')
        source_filter = request.args.get('source', 'all')
        limit = int(request.args.get('limit', 50))
        
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Show articles that are in the workflow with approval and validation status
        query = """
            SELECT DISTINCT na.id, na.title, na.summary, na.source, na.relevance_score, na.status, 
                   na.created_at, na.url,
                   CASE WHEN ma.decision = 'approved' THEN 1 ELSE 0 END as manager_approved,
                   COALESCE(na.sender_validated, 0) as sender_validated,
                   CASE WHEN sd.id IS NOT NULL AND sd.status = 'pending' THEN 1 ELSE 0 END as soc_scheduled,
                   CASE WHEN sd.id IS NOT NULL AND sd.status = 'sent' THEN 1 ELSE 0 END as soc_delivered
            FROM news_articles na
            LEFT JOIN manager_approvals ma ON na.id = ma.article_id AND ma.decision = 'approved'
            LEFT JOIN soc_deliveries sd ON na.id = sd.article_id
            WHERE na.status IN ('pending', 'approved', 'rejected', 'manager_approved')
        """
        params = []
        
        if status_filter != 'all':
            query += " AND na.status = ?"
            params.append(status_filter)
            
        if source_filter != 'all':
            query += " AND na.source = ?"
            params.append(source_filter)
            
        query += " ORDER BY na.relevance_score DESC, na.created_at DESC LIMIT ?"
        params.append(limit)  # Show all articles in workflow
        
        cursor.execute(query, params)
        news = []
        
        for row in cursor.fetchall():
            news.append({
                'id': row[0],  # Use actual database ID for callback compatibility
                'title': row[1],
                'summary': (row[2][:200] + '...' if row[2] and len(row[2]) > 200 else row[2]) if row[2] else 'No summary available',
                'source': row[3],
                'relevance_score': row[4],
                'status': row[5],
                'created_at': row[6],
                'url': row[7],
                'manager_approved': bool(row[8]),
                'sender_validated': bool(row[9]),
                'soc_scheduled': bool(row[10]),
                'soc_delivered': bool(row[11])
            })
        
        conn.close()
        return jsonify({'articles': news, 'total': len(news)})
        
    except Exception as e:
        logger.error(f"Error getting news: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/schedule')
def get_schedule():
    """Get delivery schedule"""
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Get scheduled deliveries — include all statuses so the user sees
        # pending + their own past Send-now / Cancel actions.
        # sd.delivery_date is the *actual* sent timestamp (stamped by
        # _finalize_delivery); sd.scheduled_for is the originally planned slot.
        cursor.execute("""
            SELECT sd.id, sd.article_id, na.title, sd.status,
                   sd.created_at, sd.scheduled_for, sd.position, sd.delivery_date,
                   sd.retry_count, sd.error_message
            FROM soc_deliveries sd
            JOIN news_articles na ON sd.article_id = na.id
            ORDER BY
                CASE sd.status WHEN 'pending' THEN 0 ELSE 1 END,
                sd.scheduled_for ASC, sd.created_at ASC
            LIMIT 100
        """)
        
        schedule = []
        for row in cursor.fetchall():
            db_position = row[6] if row[6] is not None else len(schedule)  # position from database
            position = db_position
            delivery_time = "10:00 AM"  # Standard SOC delivery time
            
            # Use database delivery_date if available, otherwise calculate
            db_delivery_date = row[5]  # delivery_date from database
            
            if db_delivery_date:
                # Parse the stored delivery date
                try:
                    delivery_datetime_obj = datetime.fromisoformat(db_delivery_date.replace('Z', '+00:00'))
                    delivery_date = delivery_datetime_obj.date()
                    delivery_time = delivery_datetime_obj.strftime('%I:%M %p')
                    delivery_day = delivery_date.strftime('%A')
                except (ValueError, TypeError, AttributeError):
                    # Fallback to old calculation if parsing fails
                    delivery_date = datetime.fromisoformat(db_delivery_date).date()
                    delivery_day = delivery_date.strftime('%A')
            else:
                # Fallback: Calculate delivery day and time based on position (TUESDAY ONLY at 11:00 AM)
                delivery_day = "Tuesday"
                # Each position adds 1 week (all deliveries on Tuesday)
                delivery_date = get_next_weekday(1, weeks=position)  # Tuesday
            
            # Format full delivery info
            delivery_datetime = f"{delivery_date.strftime('%B %d, %Y')} at {delivery_time}"
            days_from_now = (delivery_date - datetime.now().date()).days

            # Actual sent/finalized timestamp (sd.delivery_date in row[7]).
            # Set by _finalize_delivery in scheduler.py when the row leaves the
            # 'pending' state. For pending rows this is null.
            sent_dt_raw = row[7]
            sent_iso = None
            sent_human = None
            if sent_dt_raw:
                try:
                    # SQLite returns 'YYYY-MM-DD HH:MM:SS' (UTC, no tz info)
                    sent_dt = datetime.fromisoformat(str(sent_dt_raw).replace(' ', 'T').replace('Z', ''))
                    # If it's naive, treat as UTC and convert to IST for display
                    if sent_dt.tzinfo is None:
                        sent_dt = sent_dt.replace(tzinfo=pytz.utc).astimezone(config.SYSTEM_TIMEZONE)
                    sent_iso = sent_dt.isoformat()
                    sent_human = sent_dt.strftime('%b %d, %Y at %I:%M %p').replace(' 0', ' ')
                except Exception:
                    sent_iso = str(sent_dt_raw)
                    sent_human = str(sent_dt_raw)

            schedule.append({
                'id': row[0],
                'article_id': row[1],
                'title': row[2][:60] + '...' if len(row[2]) > 60 else row[2],
                'status': row[3],
                'created_at': row[4],
                'delivery_day': delivery_day,
                'delivery_date': delivery_date.strftime('%Y-%m-%d'),
                'delivery_time': delivery_time,
                'delivery_datetime': delivery_datetime,
                'days_from_now': days_from_now,
                'position': position + 1,
                'sent_datetime': sent_human,   # human string for the UI
                'sent_iso': sent_iso,          # ISO for the relative-time JS
                'retry_count': row[8] or 0,    # failed send attempts so far
                'error_message': row[9] or '', # last send error (SMTP etc.)
            })
        
        conn.close()
        return jsonify({'schedule': schedule, 'total': len(schedule)})
        
    except Exception as e:
        logger.error(f"Error getting schedule: {e}")
        return jsonify({'error': str(e)}), 500

def get_next_weekday(weekday, weeks=0):
    """Get next occurrence of weekday (0=Monday, 1=Tuesday, etc.)"""
    today = datetime.now().date()
    days_ahead = weekday - today.weekday()
    if days_ahead <= 0:  # Target day already happened this week
        days_ahead += 7
    return today + timedelta(days=days_ahead, weeks=weeks)

@app.route('/api/reports')
def get_reports():
    """Get reports status and management - FIXED undefined error"""
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Get approved articles with report status (FIXED - No duplicates)
        cursor.execute("""
            SELECT DISTINCT na.id, na.title, na.source, 
                   (SELECT ma.decision_date FROM manager_approvals ma WHERE ma.article_id = na.id AND ma.decision = 'approved' LIMIT 1) as decision_date,
                   COALESCE(na.sender_validated, 0) as sender_validated, 
                   na.sender_validation_date,
                   COALESCE((SELECT sd.status FROM soc_deliveries sd WHERE sd.article_id = na.id LIMIT 1), 'not_scheduled') as soc_status, 
                   (SELECT sd.delivery_date FROM soc_deliveries sd WHERE sd.article_id = na.id LIMIT 1) as delivery_date
            FROM news_articles na
            WHERE na.status = 'approved'
            ORDER BY COALESCE((SELECT ma.decision_date FROM manager_approvals ma WHERE ma.article_id = na.id AND ma.decision = 'approved' LIMIT 1), na.created_at) DESC
        """)
        
        reports = []
        for row in cursor.fetchall():
            # Determine report status with better handling
            soc_status = row[6] if row[6] else 'not_scheduled'
            sender_validated = row[4] if row[4] is not None else 0
            
            if soc_status == 'sent':
                report_status = "Delivered to SOC"
                status_class = "delivered"
            elif soc_status == 'pending':
                report_status = "Scheduled for SOC"
                status_class = "scheduled"
            elif sender_validated == 1:
                report_status = "Sender Approved"
                status_class = "sender-approved"
            elif sender_validated == 0:
                report_status = "Awaiting Sender"
                status_class = "awaiting-sender"
            else:
                report_status = "Report Ready"
                status_class = "ready"
            
            reports.append({
                'id': row[0] or 0,
                'title': (row[1][:60] + '...' if len(str(row[1] or '')) > 60 else str(row[1] or 'No title')) or 'No title',
                'source': row[2] or 'Unknown',
                'approved_date': row[3] or 'N/A',
                'report_status': report_status,
                'status_class': status_class,
                'sender_validated': bool(sender_validated),
                'validation_date': row[5] or 'N/A',
                'soc_status': soc_status,
                'delivery_date': row[7] or 'N/A'
            })
        
        # Calculate report summary counts with NULL handling (FIXED)
        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN (SELECT sd.status FROM soc_deliveries sd WHERE sd.article_id = na.id LIMIT 1) = 'sent' THEN 1 END) as delivered_to_soc,
                COUNT(CASE WHEN (SELECT sd.status FROM soc_deliveries sd WHERE sd.article_id = na.id LIMIT 1) = 'pending' THEN 1 END) as scheduled_for_soc,
                COUNT(CASE WHEN COALESCE(na.sender_validated, 0) = 1 THEN 1 END) as sender_approved,
                COUNT(CASE WHEN COALESCE(na.sender_validated, 0) = 0 AND na.status = 'approved' THEN 1 END) as awaiting_sender,
                COUNT(CASE WHEN na.status = 'approved' AND (SELECT COUNT(*) FROM soc_deliveries sd WHERE sd.article_id = na.id) = 0 THEN 1 END) as reports_ready
            FROM news_articles na
            WHERE na.status = 'approved'
        """)
        
        summary_row = cursor.fetchone()
        summary = {
            'delivered_to_soc': summary_row[0] if summary_row[0] is not None else 0,
            'scheduled_for_soc': summary_row[1] if summary_row[1] is not None else 0,
            'sender_approved': summary_row[2] if summary_row[2] is not None else 0,
            'awaiting_sender': summary_row[3] if summary_row[3] is not None else 0,
            'reports_ready': summary_row[4] if summary_row[4] is not None else 0
        }
        
        conn.close()
        
        # Return structured response
        return jsonify({
            'reports': reports,
            'summary': summary,
            'total_reports': len(reports),
            'status': 'success'
        })
        
    except Exception as e:
        logger.error(f"Error getting reports: {e}")
        return jsonify({
            'error': str(e),
            'reports': [],
            'summary': {
                'delivered_to_soc': 0,
                'scheduled_for_soc': 0,
                'sender_approved': 0,
                'awaiting_sender': 0,
                'reports_ready': 0
            },
            'total_reports': 0,
            'status': 'error'
        }), 200  # Return 200 instead of 500 to avoid undefined errors

@app.route('/api/analytics')
def get_analytics():
    """Get system analytics"""
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        # Approval rates (only for articles actually sent to manager)
        cursor.execute('SELECT COUNT(*) FROM news_articles WHERE status = "approved"')
        approved = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM news_articles WHERE status = "rejected"')
        rejected = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM news_articles WHERE status = "pending"')
        pending = cursor.fetchone()[0]
        
        # The rate is "approved out of what a manager actually decided".
        # It used to divide by approved + rejected + PENDING, so ten articles
        # sitting in the review queue dragged the figure toward zero — one
        # approval out of one decision showed as 1.3% rather than 100%. An
        # article nobody has looked at yet is not a rejection.
        decided = approved + rejected
        total = decided + pending
        
        # Source breakdown (only for workflow articles)
        cursor.execute("""
            SELECT source, COUNT(*) as count, AVG(relevance_score) as avg_score
            FROM news_articles 
            WHERE status IN ('pending', 'approved', 'rejected')
            GROUP BY source 
            ORDER BY count DESC
        """)
        sources = [{'source': row[0], 'count': row[1], 'avg_score': round(row[2], 1)} 
                  for row in cursor.fetchall()]
        
        # Recent activity
        cursor.execute("""
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM news_articles 
            WHERE created_at >= date('now', '-7 days')
            AND status IN ('pending', 'approved', 'rejected')
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        """)
        activity = [{'date': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        analytics = {
            'approval_rates': {
                'approved': approved,
                'rejected': rejected,
                'pending': pending,
                'total': total,
                'decided': decided,
                'approval_rate': round((approved / decided * 100) if decided > 0 else 0, 1)
            },
            'sources': sources,
            'recent_activity': activity
        }
        
        return jsonify(analytics)
        
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/activity-log')
def get_activity_log():
    """Get system activity log"""
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, action, description, article_id, details
            FROM activity_log
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        
        activities = []
        for row in cursor.fetchall():
            timestamp, action, description, article_id, details = row
            activities.append({
                'timestamp': timestamp,
                'action': action,
                'description': description,
                'article_id': article_id,
                'details': details
            })
        
        conn.close()
        return jsonify({
            'success': True,
            'activities': activities,
            'total': len(activities)
        })
        
    except Exception as e:
        logger.error(f"Error getting activity log: {e}")
        return jsonify({'error': str(e), 'activities': [], 'total': 0}), 500

@app.route('/api/scraping-history')
def get_scraping_history():
    """Get scraping session history"""
    try:
        limit = request.args.get('limit', 20, type=int)
        history = db.get_scraping_history(limit)
        
        return jsonify({
            'status': 'success',
            'history': history,
            'total_sessions': len(history)
        })
        
    except Exception as e:
        logger.error(f"Error getting scraping history: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scraping-session/<int:session_id>')
def get_scraping_session_details(session_id):
    """Get detailed information about a specific scraping session"""
    try:
        session_details = db.get_scraping_session_details(session_id)

        if not session_details:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404

        return jsonify({
            'status': 'success',
            'session': session_details
        })

    except Exception as e:
        logger.error(f"Error getting scraping session details: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/scraping-session/<int:session_id>', methods=['DELETE'])
@require_operator
def delete_scraping_session(session_id):
    """Remove a single scraping session row from the history.
    Only affects scraping_sessions metadata — articles already saved during
    that scrape are NOT touched."""
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM scraping_sessions WHERE id = ?", (session_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'status': 'error', 'message': f'Session #{session_id} not found'}), 404
        cursor.execute("DELETE FROM scraping_sessions WHERE id = ?", (session_id,))
        conn.commit()
        conn.close()
        db.log_system_event('INFO', f'Scraping session #{session_id} deleted by admin', 'ADMIN')
        return jsonify({'status': 'success', 'message': f'Session #{session_id} removed'})
    except Exception as e:
        logger.error(f"Error deleting scraping session {session_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500





# Socket events for real-time updates
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected")
    update_system_status()
    emit('status_update', system_status)

@socketio.on('disconnect') 
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")

# Background task for periodic updates
def background_updates():
    """Background task to send periodic updates"""
    try:
        while True:
            time.sleep(30)  # Update every 30 seconds
            try:
                update_system_status()
            except Exception as e:
                logger.error(f"Error in background update: {e}")
    except Exception as e:
        logger.error(f"Background update thread error: {e}")

@app.route('/api/trigger-delivery', methods=['POST'])
@require_operator
def trigger_manual_delivery():
    """Manually trigger delivery of scheduled articles"""
    try:
        data = request.get_json()
        article_id = data.get('article_id') if data else None
        
        # Import scheduler here to avoid circular imports
        from scheduler import threat_scheduler
        
        success = threat_scheduler.trigger_manual_delivery(article_id)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Delivery triggered successfully for {"all pending articles" if not article_id else f"article {article_id}"}'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to trigger delivery'
            }), 500
        
    except Exception as e:
        logger.error(f"Error triggering manual delivery: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/schedule-delivery', methods=['POST'])
@require_operator
def api_schedule_delivery():
    """Schedule a SOC delivery — either immediately or at a specific datetime.

    Body:
      {"when": "now"}                           → send right now
      {"when": "2026-05-26T15:30"}              → schedule at that local time
      Optional: {"article_id": 123}             → for a single article only
                                                  (default: all pending)
    """
    from datetime import datetime as _dt
    from apscheduler.triggers.date import DateTrigger
    from scheduler import threat_scheduler

    payload = request.get_json(silent=True) or {}
    when = (payload.get("when") or "").strip()
    article_id = payload.get("article_id")

    if not when:
        return jsonify({"status": "error", "message": "Missing 'when' (use 'now' or ISO datetime)"}), 400

    tz = config.SYSTEM_TIMEZONE

    # Immediate dispatch
    if when.lower() == "now":
        try:
            ok = threat_scheduler.trigger_manual_delivery(article_id)
            return jsonify({
                "status": "success" if ok else "error",
                "message": "Delivery triggered immediately" if ok else "Delivery failed (no pending articles or send error)",
                "mode": "now",
            })
        except Exception as e:
            return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"}), 500

    # Scheduled dispatch
    try:
        # Accept formats like "2026-05-26T15:30" or "2026-05-26 15:30:00"
        normalized = when.replace("T", " ")
        try:
            run_dt = _dt.strptime(normalized, "%Y-%m-%d %H:%M")
        except ValueError:
            run_dt = _dt.strptime(normalized, "%Y-%m-%d %H:%M:%S")
        run_dt = tz.localize(run_dt)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Invalid datetime '{when}': {e}"}), 400

    now_local = _dt.now(tz)
    if run_dt <= now_local:
        return jsonify({"status": "error",
                        "message": f"Scheduled time must be in the future (you picked {run_dt.strftime('%Y-%m-%d %H:%M %Z')})"}), 400

    job_id = f"manual-delivery-{int(run_dt.timestamp())}-{article_id or 'all'}"
    try:
        threat_scheduler.scheduler.add_job(
            func=lambda aid=article_id: threat_scheduler.trigger_manual_delivery(aid),
            trigger=DateTrigger(run_date=run_dt),
            id=job_id,
            name=f"Manual SOC delivery → {run_dt.strftime('%Y-%m-%d %H:%M %Z')} ({'all pending' if not article_id else f'article {article_id}'})",
            replace_existing=True,
        )
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to schedule: {e}"}), 500

    return jsonify({
        "status": "success",
        "mode": "scheduled",
        "job_id": job_id,
        "scheduled_for": run_dt.isoformat(),
        "message": f"Delivery scheduled for {run_dt.strftime('%Y-%m-%d %H:%M %Z')}",
    })


@app.route('/api/scheduled-jobs', methods=['GET'])
def api_scheduled_jobs():
    """List apscheduler jobs (recurring + one-off scheduled deliveries)."""
    from scheduler import threat_scheduler
    jobs = []
    for j in threat_scheduler.scheduler.get_jobs():
        jobs.append({
            "id": j.id,
            "name": j.name,
            "next_run": j.next_run_time.isoformat() if j.next_run_time else None,
            "kind": "one-off" if j.id.startswith("manual-delivery-") else "recurring",
        })
    jobs.sort(key=lambda j: j["next_run"] or "")
    return jsonify({"status": "success", "jobs": jobs})


@app.route('/api/scheduled-jobs/<job_id>', methods=['DELETE'])
@require_operator
def api_cancel_job(job_id):
    """Cancel a scheduled (one-off) job."""
    from scheduler import threat_scheduler
    try:
        threat_scheduler.scheduler.remove_job(job_id)
        return jsonify({"status": "success", "message": f"Cancelled {job_id}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 404


@app.route('/api/delivery/<int:delivery_id>/cancel', methods=['POST'])
@require_operator
def api_cancel_pending_delivery(delivery_id):
    """Cancel a single pending row in the Delivery Schedule.
    Marks soc_deliveries.status = 'cancelled' and removes any apscheduler
    auto-job that would re-deliver the same article."""
    from scheduler import threat_scheduler
    result = threat_scheduler.cancel_pending_delivery(delivery_id)
    if result.get("ok"):
        return jsonify({"status": "success", **result})
    return jsonify({"status": "error", **result}), 400


@app.route('/api/delivery/<int:delivery_id>/send-now', methods=['POST'])
@require_operator
def api_send_pending_delivery_now(delivery_id):
    """Send a single pending delivery row right now.
    Looks up its article_id, calls trigger_manual_delivery (which finalizes
    the row and cancels the auto-job)."""
    from scheduler import threat_scheduler
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        cursor = conn.cursor()
        cursor.execute("SELECT article_id, status FROM soc_deliveries WHERE id = ?", (delivery_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return jsonify({"status": "error", "message": f"No delivery with id {delivery_id}"}), 404
        article_id, status = row
        if status != "pending":
            return jsonify({"status": "error", "message": f"Delivery is already '{status}'"}), 400

        ok = threat_scheduler.trigger_manual_delivery(article_id)
        if ok:
            return jsonify({"status": "success", "message": f"Article {article_id} delivered to SOC", "article_id": article_id})

        # trigger returned False. It may be a genuine send failure OR the 15s
        # poller may have claimed & sent this same row a moment ago (send-once).
        # Re-read the row so we report the TRUE outcome, not a false "failed".
        conn = sqlite3.connect(db.db_path, timeout=30)
        cur = conn.cursor()
        cur.execute("SELECT status, error_message FROM soc_deliveries WHERE id = ?", (delivery_id,))
        after = cur.fetchone()
        conn.close()
        now_status = after[0] if after else None
        row_err = (after[1] if after else None) or getattr(email_system, '_last_error', None)

        if now_status == "sent":
            return jsonify({"status": "success",
                            "message": "Delivery was already sent (auto-delivered at its scheduled time).",
                            "article_id": article_id})
        return jsonify({"status": "error",
                        "message": f"Delivery failed{(' — ' + row_err) if row_err else ''}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"}), 500


@app.route('/api/delivery/<int:delivery_id>/reschedule', methods=['POST'])
@require_operator
def api_reschedule_pending_delivery(delivery_id):
    """Move a single pending delivery to a new future date/time.

    Body: {"when": "2026-07-08T15:30"}. enhanced_scheduler polls
    soc_deliveries.scheduled_for every 30s, so updating the row is all
    that's needed for the new time to take effect."""
    from datetime import datetime as _dt

    payload = request.get_json(silent=True) or {}
    when = (payload.get("when") or "").strip()
    if not when:
        return jsonify({"status": "error", "message": "Missing 'when' (ISO datetime)"}), 400

    tz = config.SYSTEM_TIMEZONE
    try:
        normalized = when.replace("T", " ")
        try:
            run_dt = _dt.strptime(normalized, "%Y-%m-%d %H:%M")
        except ValueError:
            run_dt = _dt.strptime(normalized, "%Y-%m-%d %H:%M:%S")
        run_dt = tz.localize(run_dt)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Invalid datetime '{when}': {e}"}), 400

    if run_dt <= _dt.now(tz):
        return jsonify({"status": "error",
                        "message": f"Scheduled time must be in the future (you picked {run_dt.strftime('%Y-%m-%d %H:%M %Z')})"}), 400

    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        cursor = conn.cursor()
        cursor.execute("SELECT article_id, status FROM soc_deliveries WHERE id = ?", (delivery_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": f"No delivery with id {delivery_id}"}), 404
        article_id, status = row
        if status != "pending":
            conn.close()
            return jsonify({"status": "error", "message": f"Delivery is already '{status}', only pending deliveries can be rescheduled"}), 400
        cursor.execute("UPDATE soc_deliveries SET scheduled_for = ? WHERE id = ?",
                       (run_dt.isoformat(), delivery_id))
        conn.commit()
        conn.close()

        # The DB row is now the single source of truth for this delivery's time
        # (enhanced_scheduler re-reads scheduled_for every 15s). Drop any stale
        # one-off apscheduler job for this article so it can't fire at the OLD
        # time — otherwise a reschedule to a later time could still send early.
        try:
            from scheduler import threat_scheduler
            removed = threat_scheduler._cancel_auto_jobs_for_article(article_id)
            if removed:
                logger.info(f"Reschedule: removed {removed} stale one-off job(s) for article {article_id}")
        except Exception as _e:
            logger.warning(f"Reschedule: could not clean up stale jobs for article {article_id}: {_e}")

        db.log_system_event(
            'INFO',
            f'Delivery {delivery_id} (article {article_id}) rescheduled to {run_dt.strftime("%Y-%m-%d %H:%M %Z")} by user',
            'SCHEDULER',
        )
        return jsonify({
            "status": "success",
            "message": f"Delivery scheduled for {run_dt.strftime('%b %d, %Y at %I:%M %p')}",
            "scheduled_for": run_dt.isoformat(),
            "article_id": article_id,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"}), 500


@app.route('/api/schedule-info')
def api_get_schedule_info():
    """Live, non-secret schedule state for the Schedule tab side panel.
    Combines values from config (admin_settings.json) with the apscheduler
    runtime state so the user sees what's actually configured + what's
    scheduled to fire next."""
    from scheduler import threat_scheduler

    def _fmt_time(t):
        # config.SCRAPING_TIME / SOC_DELIVERY_TIME are datetime.time objects
        try:
            return t.strftime('%I:%M %p').lstrip('0')
        except AttributeError:
            return str(t)

    soc_days = config.SOC_DELIVERY_DAYS or []
    if isinstance(soc_days, str):
        soc_days = [soc_days]

    # Inspect live apscheduler state
    jobs = threat_scheduler.scheduler.get_jobs()
    recurring = [j for j in jobs if not j.id.startswith('manual-delivery-') and not j.id.startswith('soc_delivery_')]
    one_off  = [j for j in jobs if j.id.startswith('manual-delivery-') or j.id.startswith('soc_delivery_')]
    upcoming = sorted(jobs, key=lambda j: j.next_run_time or datetime.max.replace(tzinfo=config.SYSTEM_TIMEZONE))
    next_run = upcoming[0].next_run_time.isoformat() if upcoming and upcoming[0].next_run_time else None
    next_name = upcoming[0].name if upcoming and upcoming[0].next_run_time else None

    return jsonify({
        "status": "success",
        "info": {
            "scraping_day":      config.SCRAPING_DAY,
            "scraping_time":     _fmt_time(config.SCRAPING_TIME),
            "soc_delivery_days": soc_days,
            "soc_delivery_time": _fmt_time(config.SOC_DELIVERY_TIME),
            # Auto delivery is currently OFF in scheduler.py — only manual triggers send mail.
            "auto_delivery_enabled": False,
            "auto_scraping_enabled": True,
            "recurring_jobs": len(recurring),
            "one_off_jobs":   len(one_off),
            "next_run_iso":   next_run,
            "next_run_name":  next_name,
        },
    })


@app.route('/api/activity')
def api_get_activity():
    """Recent activity / system events for the Activity Log tab."""
    try:
        limit = max(1, min(int(request.args.get('limit', 100)), 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        conn = sqlite3.connect(db.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=10000")
        cur = conn.cursor()
        cur.execute(
            "SELECT id, log_level, message, component, timestamp "
            "FROM system_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = [{
            "id": r[0],
            "level": r[1],
            "message": r[2],
            "component": r[3],
            "timestamp": r[4],
        } for r in cur.fetchall()]
        conn.close()
        return jsonify({"status": "success", "events": rows, "total": len(rows)})
    except Exception as e:
        logger.error(f"Error loading activity: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/admin/refresh-everything', methods=['POST'])
@require_admin
def api_admin_refresh_everything():
    """Reset the workflow to a clean state — wipes scraped articles,
    approvals, deliveries, validations, and scraping-session history.
    DELIBERATELY KEEPS:
      - system_logs (audit trail)
      - admin_settings.json (your saved emails/SMTP/schedule)
    Also cancels any pending apscheduler one-off delivery jobs since the
    articles they reference are gone."""
    from scheduler import threat_scheduler

    tables_to_clear = [
        "sender_validations",
        "soc_deliveries",
        "manager_approvals",
        "news_articles",
        "scraping_sessions",
    ]
    cleared_counts = {}
    total = 0
    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        cur = conn.cursor()
        for tbl in tables_to_clear:
            cur.execute(f"SELECT COUNT(*) FROM {tbl}")
            n = cur.fetchone()[0]
            cleared_counts[tbl] = n
            total += n
            cur.execute(f"DELETE FROM {tbl}")
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"refresh-everything failed during DB clear: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    # Remove any pending one-off delivery jobs whose articles just vanished.
    jobs_cancelled = 0
    for j in list(threat_scheduler.scheduler.get_jobs()):
        if j.id.startswith("manual-delivery-") or j.id.startswith("soc_delivery_"):
            try:
                threat_scheduler.scheduler.remove_job(j.id)
                jobs_cancelled += 1
            except Exception:
                pass

    # Reset in-memory dashboard status so the UI doesn't show stale counts.
    system_status['running'] = False
    _set_operation('Project reset — ready to scrape.', 'done')
    system_status['pending_approvals'] = 0
    system_status['scheduled_deliveries'] = 0
    system_status['next_delivery'] = None
    system_status['last_scraping'] = None
    system_status['last_email_sent'] = None
    try:
        socketio.emit('status_update', system_status)
    except Exception:
        pass

    # Audit trail line in system_logs (kept on purpose)
    db.log_system_event(
        'INFO',
        f'Project refreshed by admin — cleared {total} rows ({", ".join(f"{k}={v}" for k, v in cleared_counts.items())}); cancelled {jobs_cancelled} pending job(s)',
        'ADMIN',
    )

    return jsonify({
        "status": "success",
        "message": f"Cleared {total} rows. System logs were kept.",
        "cleared": cleared_counts,
        "jobs_cancelled": jobs_cancelled,
    })


@app.route('/api/scheduled-deliveries')
def get_scheduled_deliveries():
    """Get all scheduled deliveries"""
    try:
        deliveries = db.get_scheduled_deliveries(limit=100)
        
        return jsonify({
            'status': 'success',
            'deliveries': deliveries,
            'total': len(deliveries)
        })
        
    except Exception as e:
        logger.error(f"Error getting scheduled deliveries: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# Admin panel — edit hardcoded values stored in admin_settings.json
# ---------------------------------------------------------------------------

# Single source of truth: config resolves this to STATE_DIR, which is writable
# at runtime. Defining a second code-directory path here is what made every
# panel save return 500 under ProtectSystem=strict.
ADMIN_SETTINGS_PATH = config._ADMIN_SETTINGS_PATH

ADMIN_FIELDS = {
    "SENDER_EMAIL": {"type": "email", "label": "Sender email (Gmail account that sends mail)"},
    "SENDER_PASSWORD": {"type": "password", "label": "Sender Gmail app password", "hint": "16 characters. Spaces in 'xxxx xxxx xxxx xxxx' format are removed automatically."},
    "MANAGER_EMAIL": {"type": "email", "label": "Manager email (receives approval requests)"},
    "SOC_EMAIL": {"type": "email", "label": "SOC primary recipient"},
    "SOC_EMAIL_CC": {"type": "email_list", "label": "SOC CC recipients (one per row)"},
    "SMTP_SERVER": {"type": "text", "label": "SMTP server"},
    "SMTP_PORT": {"type": "int", "label": "SMTP port"},
    "COMPANY_NAME": {"type": "text", "label": "Company name (used in email templates)"},
    "EMAIL_SUBJECT_MANAGER": {"type": "text", "label": "Subject — manager approval email"},
    "EMAIL_SUBJECT_SOC": {"type": "text", "label": "Subject — SOC delivery email"},
    "MAX_NEWS_TO_MANAGER": {"type": "int", "label": "Max articles per manager email"},
    "MAX_NEWS_PER_SOC_EMAIL": {"type": "int", "label": "Max articles per SOC email"},
    "SCRAPING_DAY": {"type": "weekday", "label": "Scraping day"},
    "SCRAPING_HOUR": {"type": "int", "label": "Scraping hour (0-23)"},
    "SCRAPING_MINUTE": {"type": "int", "label": "Scraping minute (0-59)"},
    "SOC_DELIVERY_DAYS": {"type": "weekday_list", "label": "SOC delivery days"},
    "SOC_DELIVERY_HOUR": {"type": "int", "label": "SOC delivery hour (0-23)"},
    "SOC_DELIVERY_MINUTE": {"type": "int", "label": "SOC delivery minute (0-59)"},
}


def _read_admin_settings():
    try:
        with open(ADMIN_SETTINGS_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _write_admin_settings(settings):
    # Secret fields are encrypted at rest; config.decrypt_setting reverses this
    # on load, so nothing else in the app has to know.
    on_disk = dict(settings)
    for name in config.SECRET_SETTINGS:
        if name in on_disk:
            on_disk[name] = config.encrypt_setting(on_disk[name])
    # Write via a temp file in the same directory, then rename: a crash or a
    # full disk mid-write would otherwise leave truncated JSON, and the loader
    # would fall back to stale cached settings with no obvious cause.
    tmp = ADMIN_SETTINGS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(on_disk, f, indent=2, sort_keys=False)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ADMIN_SETTINGS_PATH)


def _coerce(field_name, value):
    spec = ADMIN_FIELDS[field_name]
    t = spec["type"]
    if t == "int":
        return int(value)
    if t in ("email_list", "weekday_list"):
        if isinstance(value, str):
            items = [s.strip() for s in value.replace(",", "\n").splitlines() if s.strip()]
        else:
            items = [str(s).strip() for s in value if str(s).strip()]
        if t == "weekday_list":
            items = [s.lower() for s in items]
        return items
    if t == "password":
        # Gmail/Workspace app passwords are 16 chars with no internal whitespace.
        # Google's settings page presents them as "xxxx xxxx xxxx xxxx" for
        # readability, so strip ALL whitespace and let either form be pasted.
        return "".join(str(value).split())
    return str(value).strip()


@app.route('/admin')
@require_operator
def admin_page():
    return render_template('admin.html')


# ─── Users & Access (team roster, RBAC, access requests) ────────────────
# Everything below is @require_admin: analyst_admin can reach the settings
# panel but must not be able to hand out roles.

def _bootstrap_admin_set():
    return {e.strip().lower() for e in getattr(config, 'BOOTSTRAP_SUPER_ADMINS', []) if e}


def _current_uid():
    return (session.get('user') or {}).get('uid')


def _current_email():
    return (session.get('user') or {}).get('email') or 'unknown'


def _would_orphan_admins(uid):
    """True if removing this user's admin rights leaves nobody who can manage
    users. Refusing that is the difference between a mistake and a lockout."""
    return db.count_admins(exclude_uid=uid) == 0


def _parse_role(raw, default=ROLE_VIEWER):
    """Validate a role coming off the wire, returning (role, error).

    Checks the RAW string, not normalize_role()'s output: normalize_role fails
    safe to viewer for anything it doesn't recognise, so validating its result
    would silently turn a typo — or a tampered request — into a real grant
    instead of rejecting it."""
    if raw is None or raw == '':
        return default, None
    raw = str(raw).strip().lower()
    if raw not in ASSIGNABLE_ROLES:
        return None, (f"'{raw}' is not an assignable role. Choose one of: "
                      + ", ".join(ASSIGNABLE_ROLES))
    return normalize_role(raw), None


def _shape_user(u, bootstraps):
    """One roster row, as the Users & Access page wants it."""
    email = (u.get('email') or '').lower()
    stored_role = normalize_role(u.get('role'))
    is_bootstrap = email in bootstraps
    role = ROLE_ADMIN if is_bootstrap else stored_role
    return {
        'uid': u.get('uid'),
        'email': u.get('email'),
        'display_name': u.get('display_name') or (u.get('email') or '').split('@')[0],
        'department': u.get('department'),
        'role': role,
        'role_label': ROLE_LABELS.get(role, role),
        'auth_provider': u.get('auth_provider') or 'firebase',
        'active': bool(int(u.get('active', 1) or 0)),
        'created_at': u.get('created_at'),
        'last_login': u.get('last_login'),
        'is_bootstrap': is_bootstrap,
        'is_self': u.get('uid') == _current_uid(),
    }


@app.route('/admin/users')
@require_admin
def admin_users_page():
    """Team roster, role management, and the access-request inbox."""
    return render_template('users.html')


@app.route('/api/admin/users', methods=['GET'])
@require_admin
def api_admin_list_users():
    bootstraps = _bootstrap_admin_set()
    users = [_shape_user(u, bootstraps) for u in db.list_users()]
    return jsonify({
        'status': 'success',
        'users': users,
        'roles': [
            {
                'value': r,
                'label': ROLE_LABELS.get(r, r),
                'summary': ROLE_SUMMARIES.get(r, ''),
                'description': ROLE_DESCRIPTIONS.get(r, ''),
                'capabilities': [
                    {'name': name, 'allowed': allowed}
                    for name, allowed in ROLE_CAPABILITIES.get(r, [])
                ],
            }
            for r in ASSIGNABLE_ROLES
        ],
        'me': {
            'uid': _current_uid(),
            'email': _current_email(),
            # Lets the page hide the audit panel instead of rendering it and
            # then failing the fetch with a 403.
            'identity_verified': is_verified_identity(session.get('user')),
        },
        'pending_requests': db.count_pending_access_requests(),
        'counts': {
            'total': len(users),
            'active': sum(1 for u in users if u['active']),
            'admins': sum(1 for u in users if u['role'] == ROLE_ADMIN and u['active']),
        },
    })


@app.route('/api/admin/users', methods=['POST'])
@require_admin
def api_admin_create_user():
    """Create a local email+password account directly, no request needed."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    name = (data.get('display_name') or '').strip()[:200]
    password = data.get('password') or ''
    department = (data.get('department') or '').strip()[:120] or None
    role, role_error = _parse_role(data.get('role'))

    if not email or '@' not in email:
        return jsonify({'status': 'error', 'message': 'A valid email is required'}), 400

    # Reject markup in the display name explicitly. Without this the request is
    # refused further out by the proxy, which returns a bare 403 with no body —
    # the admin sees "Request failed (403)" and has no idea which field to fix.
    # The name is rendered in the roster and the audit log, so this is also the
    # right place to keep angle brackets out of stored data.
    if re.search(r'[<>]', name):
        return jsonify({
            'status': 'error',
            'message': "Full name cannot contain the characters < or >.",
        }), 400
    if len(password) < 8:
        return jsonify({'status': 'error',
                        'message': 'Password must be at least 8 characters'}), 400
    if role_error:
        return jsonify({'status': 'error', 'message': role_error}), 400

    try:
        uid = db.create_local_user(email=email, password=password,
                                   display_name=name or email.split('@')[0],
                                   role=role, department=department)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 409
    except Exception as e:
        logger.error(f"Create user failed: {e}")
        return jsonify({'status': 'error', 'message': 'Could not create the user'}), 500

    logger.info(f"👤 User created by {_current_email()}: {email} (role={role})")
    db.log_system_event('INFO',
                        f'User {email} created with role "{ROLE_LABELS.get(role, role)}" '
                        f'by {_current_email()}', 'ACCESS_CONTROL')
    return jsonify({'status': 'success', 'uid': uid})


@app.route('/api/admin/users/<string:uid>/role', methods=['POST'])
@require_admin
def api_admin_set_user_role(uid):
    data = request.get_json(silent=True) or {}
    # A role change must name a role explicitly — no silent default here, or a
    # malformed request would quietly demote someone to viewer.
    if not (data.get('role') or '').strip():
        return jsonify({'status': 'error', 'message': 'A role is required'}), 400
    role, role_error = _parse_role(data.get('role'))
    if role_error:
        return jsonify({'status': 'error', 'message': role_error}), 400

    target = db.get_user_profile(uid)
    if not target:
        return jsonify({'status': 'error', 'message': 'No such user'}), 404
    if (target.get('email') or '').lower() in _bootstrap_admin_set():
        return jsonify({
            'status': 'error',
            'message': 'This address is a bootstrap super-admin in config.py, so its '
                       'role is always Admin. Remove it from BOOTSTRAP_SUPER_ADMINS '
                       'to manage it here.',
        }), 409
    if uid == _current_uid() and role != ROLE_ADMIN:
        return jsonify({'status': 'error',
                        'message': 'You cannot lower your own role. Ask another '
                                   'admin to do it.'}), 409
    if (normalize_role(target.get('role')) == ROLE_ADMIN and role != ROLE_ADMIN
            and _would_orphan_admins(uid)):
        return jsonify({'status': 'error',
                        'message': 'This is the last active admin — promote someone '
                                   'else first.'}), 409

    db.set_user_role(uid, role)
    logger.info(f"🔑 Role change by {_current_email()}: {target.get('email')} → {role}")
    db.log_system_event('INFO',
                        f"Role for {target.get('email')} changed to "
                        f"\"{ROLE_LABELS.get(role, role)}\" by {_current_email()}",
                        'ACCESS_CONTROL')
    return jsonify({'status': 'success', 'role': role,
                    'role_label': ROLE_LABELS.get(role, role)})


@app.route('/api/admin/users/<string:uid>/active', methods=['POST'])
@require_admin
def api_admin_set_user_active(uid):
    data = request.get_json(silent=True) or {}
    active = bool(data.get('active'))

    target = db.get_user_profile(uid)
    if not target:
        return jsonify({'status': 'error', 'message': 'No such user'}), 404
    if uid == _current_uid() and not active:
        return jsonify({'status': 'error',
                        'message': 'You cannot disable your own account.'}), 409
    if (not active and normalize_role(target.get('role')) == ROLE_ADMIN
            and _would_orphan_admins(uid)):
        return jsonify({'status': 'error',
                        'message': 'This is the last active admin — promote someone '
                                   'else first.'}), 409

    db.set_user_active(uid, active)
    verb = 'enabled' if active else 'disabled'
    logger.info(f"👤 Account {verb} by {_current_email()}: {target.get('email')}")
    db.log_system_event('INFO',
                        f"Account {target.get('email')} {verb} by {_current_email()}",
                        'ACCESS_CONTROL')
    return jsonify({'status': 'success', 'active': active})


@app.route('/api/admin/users/<string:uid>/password', methods=['POST'])
@require_admin
def api_admin_set_user_password(uid):
    """Set a new password on a local account. Firebase identities manage their
    own passwords, so those are rejected."""
    data = request.get_json(silent=True) or {}
    password = data.get('password') or ''
    if len(password) < 8:
        return jsonify({'status': 'error',
                        'message': 'Password must be at least 8 characters'}), 400
    try:
        db.set_local_password(uid, password)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 409
    except Exception as e:
        logger.error(f"Password reset failed for {uid}: {e}")
        return jsonify({'status': 'error', 'message': 'Could not set the password'}), 500

    logger.info(f"🔑 Password reset by {_current_email()} for uid={uid}")
    db.log_system_event('WARNING',
                        f'Password reset for uid={uid} by {_current_email()}',
                        'ACCESS_CONTROL')
    return jsonify({'status': 'success'})


@app.route('/api/admin/users/<string:uid>', methods=['DELETE'])
@require_admin
def api_admin_delete_user(uid):
    target = db.get_user_profile(uid)
    if not target:
        return jsonify({'status': 'error', 'message': 'No such user'}), 404
    if uid == _current_uid():
        return jsonify({'status': 'error',
                        'message': 'You cannot delete your own account.'}), 409
    if normalize_role(target.get('role')) == ROLE_ADMIN and _would_orphan_admins(uid):
        return jsonify({'status': 'error',
                        'message': 'This is the last active admin — promote someone '
                                   'else first.'}), 409

    db.delete_user(uid)
    logger.info(f"🗑 User deleted by {_current_email()}: {target.get('email')}")
    db.log_system_event('WARNING',
                        f"User {target.get('email')} deleted by {_current_email()}",
                        'ACCESS_CONTROL')
    return jsonify({'status': 'success'})


@app.route('/api/admin/access-requests', methods=['GET'])
@require_admin
def api_admin_access_requests():
    pending = db.list_access_requests(status='pending', limit=100)
    reviewed = [r for r in db.list_access_requests(limit=100)
                if r['status'] != 'pending'][:15]
    return jsonify({
        'status': 'success',
        'pending': pending,
        'reviewed': reviewed,
        'pending_count': len(pending),
    })


@app.route('/api/admin/audit-log', methods=['GET'])
@require_verified_admin
def api_admin_audit_log():
    """The access-control audit trail.

    Stricter than the rest of this panel: @require_verified_admin demands a
    verified identity on top of the admin role, because these rows name who
    granted which privileges to whom.
    """
    limit = min(int(request.args.get('limit', 200) or 200), 500)
    entries = db.list_access_control_log(limit=limit)

    # Classify each line so the UI can group and icon them without re-parsing
    # prose. Keyed off the phrasing used by the log_system_event calls above.
    def kind_of(message):
        m = (message or '').lower()
        if m.startswith('access request from') and 'approved' in m:
            return 'request_approved'
        if m.startswith('access request from') and 'rejected' in m:
            return 'request_rejected'
        if m.startswith('access request from'):
            return 'request_filed'
        if m.startswith('role for'):
            return 'role_changed'
        if m.startswith('password reset'):
            return 'password_reset'
        if ' deleted by ' in m:
            return 'account_deleted'
        if ' disabled by ' in m:
            return 'account_disabled'
        if ' enabled by ' in m:
            return 'account_enabled'
        if ' created with role ' in m:
            return 'account_created'
        return 'other'

    for e in entries:
        e['kind'] = kind_of(e.get('message'))

    return jsonify({
        'status': 'success',
        'entries': entries,
        'decisions': [r for r in db.list_access_requests(limit=100)
                      if r['status'] != 'pending'],
        'viewer': _current_email(),
    })


@app.route('/api/admin/access-requests/<int:req_id>/approve', methods=['POST'])
@require_admin
def api_admin_approve_access_request(req_id):
    data = request.get_json(silent=True) or {}
    role, role_error = _parse_role(data.get('role'))
    if role_error:
        return jsonify({'status': 'error', 'message': role_error}), 400
    password = data.get('password') or None
    if password and len(password) < 8:
        return jsonify({'status': 'error',
                        'message': 'Password must be at least 8 characters'}), 400

    try:
        result = db.approve_access_request(
            req_id=req_id, role=role, reviewer_email=_current_email(),
            password=password, department=(data.get('department') or '').strip() or None,
        )
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 409
    except Exception as e:
        logger.error(f"Approving request {req_id} failed: {e}")
        return jsonify({'status': 'error', 'message': 'Could not approve the request'}), 500

    logger.info(f"✅ Access approved by {_current_email()}: {result['email']} → {role}")
    db.log_system_event('INFO',
                        f"Access request from {result['email']} approved as "
                        f"\"{ROLE_LABELS.get(role, role)}\" by {_current_email()}",
                        'ACCESS_CONTROL')
    try:
        socketio.emit('access_request_reviewed',
                      {'email': result['email'], 'outcome': 'approved'})
    except Exception:
        pass
    return jsonify({'status': 'success', **result})


@app.route('/api/admin/access-requests/<int:req_id>/reject', methods=['POST'])
@require_admin
def api_admin_reject_access_request(req_id):
    data = request.get_json(silent=True) or {}
    note = (data.get('note') or '').strip()[:500] or None
    try:
        result = db.reject_access_request(req_id, _current_email(), note)
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 409
    except Exception as e:
        logger.error(f"Rejecting request {req_id} failed: {e}")
        return jsonify({'status': 'error', 'message': 'Could not reject the request'}), 500

    logger.info(f"🚫 Access rejected by {_current_email()}: {result['email']}")
    db.log_system_event('INFO',
                        f"Access request from {result['email']} rejected by "
                        f"{_current_email()}" + (f" — {note}" if note else ""),
                        'ACCESS_CONTROL')
    try:
        socketio.emit('access_request_reviewed',
                      {'email': result['email'], 'outcome': 'rejected'})
    except Exception:
        pass
    return jsonify({'status': 'success'})


@app.route('/api/admin/settings', methods=['GET'])
@require_operator
def api_admin_get_settings():
    settings = _read_admin_settings()
    # Ensure every known field has a value (fall back to live config attribute)
    field_map = {
        "SCRAPING_HOUR": getattr(config, "SCRAPING_TIME").hour,
        "SCRAPING_MINUTE": getattr(config, "SCRAPING_TIME").minute,
        "SOC_DELIVERY_HOUR": getattr(config, "SOC_DELIVERY_TIME").hour,
        "SOC_DELIVERY_MINUTE": getattr(config, "SOC_DELIVERY_TIME").minute,
    }
    for name in ADMIN_FIELDS:
        if name not in settings:
            if name in field_map:
                settings[name] = field_map[name]
            else:
                settings[name] = getattr(config, name, "")
    # A field pinned by a TI_* environment variable cannot be changed from this
    # panel — the panel writes admin_settings.json, which the environment then
    # overrides. Report it as locked (with the live effective value) so an admin
    # is told that, instead of saving happily and seeing no effect.
    fields = []
    for name, spec in ADMIN_FIELDS.items():
        locked = config.is_env_managed(name)
        entry = {"name": name, **spec, "value": settings.get(name, "")}
        if locked:
            entry["value"] = getattr(config, name, entry["value"])
            entry["locked"] = True
            entry["locked_reason"] = (
                f"Set by the TI_{name} environment variable on this server; "
                f"edit the service EnvironmentFile to change it."
            )
        # Never echo a stored password back to the browser. The save endpoint
        # treats an empty password as "leave unchanged", so a blank box here
        # cannot wipe the stored credential — the hint says so.
        if spec.get("type") == "password" and entry["value"]:
            entry["value"] = ""
            entry["is_set"] = True
            entry["hint"] = (
                (spec.get("hint", "") + " ").lstrip()
                + "A password is saved. Click show to reveal it, or type a new "
                  "one to replace it."
            )
        fields.append(entry)
    return jsonify({"status": "success", "fields": fields})


@app.route('/api/admin/settings/reveal', methods=['POST'])
@require_operator
def api_admin_reveal_setting():
    """Return the plaintext of one secret setting, on explicit request.

    The settings GET deliberately blanks passwords, so they are not sitting in
    the DOM of every admin page load. This endpoint exists for the panel's
    "show" button: one field, one deliberate action, operator-only, and logged.

    Env-pinned fields are refused rather than revealed — their value lives in a
    root-owned file the app can read but the panel cannot change, and echoing it
    into a browser would undo that separation for no benefit.
    """
    name = (request.get_json(silent=True) or {}).get("field", "")
    spec = ADMIN_FIELDS.get(name)
    if not spec or spec.get("type") != "password":
        return jsonify({"status": "error", "message": "Not a secret field"}), 400
    if config.is_env_managed(name):
        return jsonify({
            "status": "error",
            "message": "Set by an environment variable; not editable here.",
        }), 403

    value = _read_admin_settings().get(name, "")
    value = config.decrypt_setting(value)
    try:
        db.log_system_event(
            'INFO', 'ADMIN',
            f"Secret setting '{name}' revealed in the admin panel",
        )
    except Exception:
        pass   # never fail the request because the audit write failed
    return jsonify({"status": "success", "value": value})


def _pycache_dirs():
    """List __pycache__ dirs in the project root (excludes .venv and .trash)."""
    project_root = os.path.dirname(os.path.abspath(__file__))
    matches = []
    for root, dirs, _files in os.walk(project_root):
        # don't descend into venvs or trash
        dirs[:] = [d for d in dirs if d not in ('.venv', 'venv', '.trash', 'node_modules', '.git')]
        if os.path.basename(root) == '__pycache__':
            matches.append(root)
    return matches


def _dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


@app.route('/api/admin/cache/stats', methods=['GET'])
@require_operator
def api_admin_cache_stats():
    """Return current size/count of each clearable cache."""
    stats = {}
    try:
        conn = sqlite3.connect(db.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=10000")
        cur = conn.cursor()
        for tbl in ('news_articles', 'manager_approvals', 'soc_deliveries',
                    'sender_validations', 'system_logs', 'scraping_sessions'):
            try:
                stats[tbl] = cur.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            except sqlite3.OperationalError:
                stats[tbl] = None
        conn.close()
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    try:
        stats['db_file_kb'] = round(os.path.getsize(db.db_path) / 1024, 1)
    except OSError:
        stats['db_file_kb'] = None

    pycache = _pycache_dirs()
    stats['pycache_dirs'] = len(pycache)
    stats['pycache_kb'] = round(sum(_dir_size(p) for p in pycache) / 1024, 1)

    return jsonify({"status": "success", "stats": stats})


@app.route('/api/admin/cache/clear', methods=['POST'])
@require_operator
def api_admin_cache_clear():
    """Clear a specific cache target.

    Body: {"target": "<name>"}

    Targets:
      workflow_state    — wipe news_articles + manager_approvals + soc_deliveries
                          + sender_validations + their session join rows
                          (fresh start, doesn't scrape)
      activity_logs     — wipe system_logs (free up most of the bloat)
      scraping_sessions — wipe scraping_sessions metadata + its join rows
      retention_sweep   — run the nightly age-based sweep now (keeps recent data)
      pycache           — remove every __pycache__ dir under the project root
      vacuum_db         — run VACUUM to reclaim free pages on disk

    The wipe targets are blunt — they delete regardless of age. retention_sweep
    is the one to reach for on a live system.
    """
    import shutil
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()

    if target == "pycache":
        removed = 0
        for d in _pycache_dirs():
            try:
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
            except Exception as e:
                logger.warning(f"Could not remove {d}: {e}")
        return jsonify({"status": "success", "target": target,
                        "message": f"Removed {removed} __pycache__ director{'y' if removed == 1 else 'ies'}"})

    if target == "vacuum_db":
        # Delegates to db.vacuum() rather than repeating the VACUUM here, so
        # the manual button and the nightly sweep cannot drift apart.
        freed_kb = round(db.vacuum(reason='admin') / 1024, 1)
        return jsonify({"status": "success", "target": target,
                        "message": f"Database vacuumed ({freed_kb} KB reclaimed)"})

    if target == "retention_sweep":
        # The same sweep the scheduler runs at 03:40, on demand — for a first
        # deploy, where waiting a night to clear an existing backlog is silly.
        try:
            deleted = db.cleanup_old_records(
                days=config.LOG_RETENTION_DAYS,
                audit_days=config.AUDIT_RETENTION_DAYS,
                session_days=config.SESSION_RETENTION_DAYS,
                content_days=config.ARTICLE_CONTENT_RETENTION_DAYS,
            )
            summary = {k: v for k, v in deleted.items() if v}
            total = sum(deleted.values())
            db.log_system_event('INFO', f"Admin ran retention sweep ({total} rows)", 'ADMIN')
            return jsonify({"status": "success", "target": target, "detail": summary,
                            "message": f"Retention sweep affected {total} row{'' if total == 1 else 's'}"
                                       + (f": {summary}" if summary else "")})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Retention sweep failed: {e}"}), 500

    # scraping_session_articles rides along with both targets that delete its
    # parents. Leaving it out is what stranded 1600+ join rows pointing at
    # articles and sessions that no longer existed.
    table_targets = {
        "workflow_state":    ["scraping_session_articles", "sender_validations",
                              "soc_deliveries", "manager_approvals", "news_articles"],
        "activity_logs":     ["system_logs"],
        "scraping_sessions": ["scraping_session_articles", "scraping_sessions"],
    }
    if target not in table_targets:
        return jsonify({"status": "error",
                        "message": f"Unknown target {target!r}. Allowed: workflow_state, activity_logs, "
                                   f"scraping_sessions, retention_sweep, pycache, vacuum_db"}), 400

    try:
        conn = sqlite3.connect(db.db_path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        cur = conn.cursor()
        total = 0
        for tbl in table_targets[target]:
            cur.execute(f"SELECT COUNT(*) FROM {tbl}")
            before = cur.fetchone()[0]
            cur.execute(f"DELETE FROM {tbl}")
            total += before
        conn.commit()
        conn.close()
        db.log_system_event('INFO', f"Admin cleared cache target '{target}' ({total} rows)", 'ADMIN')
        return jsonify({"status": "success", "target": target,
                        "message": f"Cleared {total} row{'' if total == 1 else 's'} from {', '.join(table_targets[target])}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"}), 500


@app.route('/api/admin/test-email', methods=['POST'])
@require_operator
def api_admin_test_email():
    """Send a minimal test email using the LIVE config so the user sees
    the real SMTP outcome (auth error, success, etc.) without scraping."""
    import smtplib
    import ssl
    from email.mime.text import MIMEText

    payload = request.get_json(silent=True) or {}
    recipient = (payload.get("recipient") or config.MANAGER_EMAIL).strip()

    smtp_server = config.SMTP_SERVER
    smtp_port = config.SMTP_PORT
    sender = config.SENDER_EMAIL
    password = config.SENDER_PASSWORD

    diag = {
        "sender": sender,
        "recipient": recipient,
        "smtp": f"{smtp_server}:{smtp_port}",
    }

    if not sender or not password:
        return jsonify({"status": "error", "stage": "validation",
                        "message": "SENDER_EMAIL or SENDER_PASSWORD is empty — set them in /admin first.",
                        "diag": diag}), 400

    try:
        message = MIMEText(
            "This is a test email from the Threat Intelligence dashboard /admin panel.\n"
            "If you received this, the configured SMTP credentials are working.",
            "plain",
        )
        message["Subject"] = "Weekly Cyber Watch — admin test email"
        message["From"] = sender
        message["To"] = recipient

        with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(sender, password)
            server.send_message(message)

        return jsonify({"status": "success",
                        "message": f"Test email sent. Check {recipient} (and the spam folder).",
                        "diag": diag})
    except smtplib.SMTPAuthenticationError as e:
        code = getattr(e, "smtp_code", "?")
        body = e.smtp_error.decode(errors="replace") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        return jsonify({"status": "error", "stage": "auth",
                        "message": f"SMTP {code} authentication failed. The {smtp_server} server rejected the SENDER_EMAIL + SENDER_PASSWORD combination.",
                        "detail": body, "diag": diag}), 200
    except smtplib.SMTPRecipientsRefused as e:
        return jsonify({"status": "error", "stage": "recipient",
                        "message": f"Recipient address rejected by {smtp_server}.",
                        "detail": str(e.recipients), "diag": diag}), 200
    except smtplib.SMTPConnectError as e:
        return jsonify({"status": "error", "stage": "connect",
                        "message": f"Could not connect to {smtp_server}:{smtp_port}.",
                        "detail": str(e), "diag": diag}), 200
    except Exception as e:
        return jsonify({"status": "error", "stage": "other",
                        "message": f"{type(e).__name__}: {e}", "diag": diag}), 200


@app.route('/api/admin/settings', methods=['POST'])
@require_operator
def api_admin_save_settings():
    payload = request.get_json(silent=True) or {}
    incoming = payload.get("settings") or {}
    current = _read_admin_settings()
    errors = {}
    skipped_locked = []
    for name, raw_value in incoming.items():
        if name not in ADMIN_FIELDS:
            continue
        spec = ADMIN_FIELDS[name]

        # The GET endpoint no longer echoes stored passwords back to the browser,
        # and the admin page posts every field it rendered — so an untouched
        # password field arrives empty. Writing that through would silently wipe
        # the Gmail app password and stop all email. Empty means "unchanged";
        # to actually change it, type a new one.
        if spec.get("type") == "password" and not str(raw_value or "").strip():
            continue

        # Values pinned by the environment are read-only here: the file we write
        # is overridden by TI_* at read time, so accepting the edit would look
        # like it worked and change nothing.
        if config.is_env_managed(name):
            skipped_locked.append(name)
            continue

        try:
            current[name] = _coerce(name, raw_value)
        except (ValueError, TypeError) as e:
            errors[name] = str(e)
    if errors:
        return jsonify({"status": "error", "errors": errors}), 400
    _write_admin_settings(current)

    # Re-arm the cron jobs if any schedule field moved. The settings file is
    # already written at this point, so a failure here degrades to "restart to
    # apply" rather than losing the save.
    SCHEDULE_FIELDS = {
        'SCRAPING_DAY', 'SCRAPING_HOUR', 'SCRAPING_MINUTE',
        'SOC_DELIVERY_DAYS', 'SOC_DELIVERY_HOUR', 'SOC_DELIVERY_MINUTE',
    }
    schedule_touched = bool(SCHEDULE_FIELDS & set(incoming))
    rearmed = None
    if schedule_touched:
        try:
            from scheduler import threat_scheduler
            rearmed = threat_scheduler.reapply_schedules()
        except Exception as e:
            logger.warning(f"Schedule re-arm after settings save failed: {e}")

    if schedule_touched and rearmed:
        message = f"Settings saved and the schedule is live now ({rearmed})."
        db.log_system_event('INFO', f"Schedule updated from the admin panel: {rearmed}",
                            'SCHEDULER')
    elif schedule_touched:
        message = ("Settings saved. The schedule could not be re-armed on this "
                   "process — restart the service to apply it.")
    else:
        message = "Settings saved. Email, SMTP and limit changes are live now."
    if skipped_locked:
        message += (
            " Not changed (pinned by environment variables on this server): "
            + ", ".join(sorted(skipped_locked))
            + "."
        )
    return jsonify({
        "status": "success",
        "message": message,
        "settings": current,
    })


_runtime_started = False
_runtime_lock = threading.Lock()


def start_runtime():
    """Seed the admin account and start the background status thread.

    This lived inside `if __name__ == '__main__'`, which meant it only ran when
    the file was executed directly. Under a WSGI server the module is IMPORTED
    (`gunicorn web_dashboard:app`), so none of it ran: no admin seeded on a
    fresh database, and no background status updates. Called from both paths
    now, guarded so it happens exactly once per process.
    """
    global _runtime_started
    with _runtime_lock:
        if _runtime_started:
            return
        _runtime_started = True

    # Seed the default local admin account on first run so the platform is
    # usable out of the box (idempotent — only seeds a genuinely empty table).
    try:
        db.ensure_default_admin(
            email=getattr(config, 'DEFAULT_ADMIN_EMAIL', None),
            password=getattr(config, 'DEFAULT_ADMIN_PASSWORD', None),
            display_name=getattr(config, 'DEFAULT_ADMIN_NAME', None),
        )
    except Exception as e:
        logger.warning(f"Could not seed default admin: {e}")

    # On a fresh production database the seeded admin password is generated
    # rather than "password". Surface it once so the operator can actually log
    # in — it is also in .initial_admin_password (0600).
    if config.IS_PRODUCTION and not os.environ.get("TI_DEFAULT_ADMIN_PASSWORD", "").strip():
        if config.DEFAULT_ADMIN_PASSWORD_PERSISTED:
            # Point at the 0600 file rather than echoing the credential. It used
            # to be logged in full, which put a working admin password into
            # journald — readable by more accounts than the file itself, and
            # retained for as long as the journal is.
            logger.warning(
                "Bootstrap admin account seeded — CHANGE THIS PASSWORD AFTER "
                "FIRST LOGIN, then delete the file:\n"
                f"    email:    {config.DEFAULT_ADMIN_EMAIL}\n"
                f"    password: (not logged) read it with "
                f"`sudo cat {config.INITIAL_ADMIN_PW_FILE}`"
            )
        else:
            # Persisting failed, so the log is the only channel left.
            logger.warning(
                "Bootstrap admin credentials — could not write "
                f"{config.INITIAL_ADMIN_PW_FILE}, so the password appears here "
                "ONCE. Change it after first login and purge this log line:\n"
                f"    email:    {config.DEFAULT_ADMIN_EMAIL}\n"
                f"    password: {config.DEFAULT_ADMIN_PASSWORD}"
            )

    update_thread = threading.Thread(
        target=background_updates, name="background_updates", daemon=True
    )
    update_thread.start()
    logger.info("Background status thread started")


# Runs under gunicorn (module import) as well as `python web_dashboard.py`.
#
# TI_SKIP_RUNTIME=1 skips only this block. It does NOT make importing this module
# side-effect free: `from scheduler import threat_scheduler` above starts the
# APScheduler jobs and the SOC delivery poller at import time, and that poller
# sends real email. Do not import this module in a test.
if os.environ.get("TI_SKIP_RUNTIME", "").strip() not in ("1", "true", "yes"):
    start_runtime()


# Optional React front end (frontend/). Adds /api/public-config and serves the
# built bundle under /app/ — a prefix nothing else uses. Every existing route,
# template and background job is unaffected, and deleting frontend_bridge.py
# along with this block restores the previous behaviour exactly.
#
# Wrapped because the dashboard hosts the scheduler, the delivery poller and
# the approval callbacks: a missing or broken front end must never be the
# reason this process fails to start.
try:
    import frontend_bridge
    frontend_bridge.mount(app)
except Exception as _e:  # noqa: BLE001 - startup must survive anything here
    logger.warning(f"React front end not mounted ({_e}); Jinja pages unaffected.")


if __name__ == '__main__':
    logger.info("🚀 Starting Threat Intelligence Web Dashboard...")
    logger.info(f"📍 Listening on {config.DASHBOARD_BIND_HOST}:{config.DASHBOARD_PORT}")
    logger.info(f"📍 Public URL: {config.DASHBOARD_BASE_URL}")
    logger.info(f"🔗 Callback server expected on port {config.CALLBACK_SERVER_PORT}")

    if config.IS_PRODUCTION:
        # Werkzeug's dev server is single-process, has no request timeouts and
        # no slow-client protection. Fine for a handful of internal users, but
        # gunicorn is the supported way — see deploy/threatintel-dashboard.service.
        logger.warning(
            "Running the Werkzeug development server in production. Prefer: "
            "gunicorn -k gthread -w 1 -b "
            f"{config.DASHBOARD_BIND_HOST}:{config.DASHBOARD_PORT} web_dashboard:app"
        )

    # Bind host/port are configurable now: 127.0.0.1 was hardcoded, which on a
    # server means nothing outside the machine can ever connect. Keep 127.0.0.1
    # when nginx proxies; set TI_DASHBOARD_BIND_HOST=0.0.0.0 to expose directly.
    socketio.run(
        app,
        host=config.DASHBOARD_BIND_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        allow_unsafe_werkzeug=True,
    )
