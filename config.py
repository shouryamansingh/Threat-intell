"""Configuration file for Threat Intelligence Automation System

Editable settings live in `admin_settings.json` (managed via the /admin panel).

Access them as `config.SENDER_EMAIL`, `config.SMTP_SERVER`, etc. — the
module-level __getattr__ re-reads the JSON file on every access (with
mtime-based caching, so it's cheap), so a save in /admin takes effect
immediately, no restart needed.

DO NOT use `from config import SENDER_EMAIL` — that snapshots the value
at import time and won't see admin updates. Always do `import config`
and `config.SENDER_EMAIL` at the call site.
"""

import os
import re
import json
from datetime import time as datetime_time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ADMIN_SETTINGS_PATH = os.path.join(_HERE, "admin_settings.json")


# ── .env loading ────────────────────────────────────────────────────────
# Site-specific values (real email addresses, allowed domains, credentials)
# live in a gitignored `.env` file rather than in this committed source file,
# so the repository can be published without leaking them. `.env.example`
# documents every variable.
#
# Deliberately a few lines rather than a python-dotenv dependency, and a real
# environment variable always wins over the file — so systemd's
# EnvironmentFile, an AWS Secrets Manager injection, or a one-off
# `TI_ENV=production python ...` all override it without surprises.
def _load_dotenv(path=None):
    path = path or os.path.join(_HERE, ".env")
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        # Strip one layer of matching quotes, so both KEY=v and KEY="v" work.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


def _env_list(name, default=None):
    """Parse a comma-separated environment variable into a list of strings."""
    raw = os.environ.get(name, "")
    items = [part.strip() for part in raw.split(",") if part.strip()]
    return items if items else list(default or [])

# Mtime-cached loader: stat() on every call, full re-read only when the file changes.
_cache = {"mtime": None, "settings": {}}


def _load_admin_settings():
    try:
        mtime = os.path.getmtime(_ADMIN_SETTINGS_PATH)
    except FileNotFoundError:
        _cache["mtime"] = None
        _cache["settings"] = {}
        return _cache["settings"]
    if mtime != _cache["mtime"]:
        try:
            with open(_ADMIN_SETTINGS_PATH, "r") as f:
                _cache["settings"] = json.load(f)
            _cache["mtime"] = mtime
        except (json.JSONDecodeError, OSError):
            # Keep last good cache rather than blow up live config reads
            pass
    return _cache["settings"]


# Defaults for every editable setting. Used when the key is missing from
# admin_settings.json. Touch these only to change project-wide defaults.
_DEFAULTS = {
    "SENDER_EMAIL":   "threat.intel@sentinel-demo.io",
    "SENDER_PASSWORD": "",
    "MANAGER_EMAIL":  "security.lead@sentinel-demo.io",
    "VALIDATOR_EMAIL": "",  # Recipient for the sender-validation preview email. Leave blank to fall back to SENDER_EMAIL (note: same address means the email lands in Sent only, not Inbox).
    "SOC_EMAIL":      "soc.team@sentinel-demo.io",
    "SOC_EMAIL_CC":   [],
    "SMTP_SERVER":    "smtp.gmail.com",
    "SMTP_PORT":      587,
    "COMPANY_NAME":   "Financial Services Corp",
    "EMAIL_SUBJECT_MANAGER": "Weekly Threat Intelligence Report - Approval Required",
    "EMAIL_SUBJECT_SOC":     "Weekly Cyber Watch - Action Required",
    "MAX_NEWS_TO_MANAGER":   10,
    "MAX_NEWS_PER_SOC_EMAIL": 10,
    "SCRAPING_DAY":      "monday",
    "SCRAPING_HOUR":     10,
    "SCRAPING_MINUTE":   0,
    "SOC_DELIVERY_DAYS": ["tuesday"],
    "SOC_DELIVERY_HOUR": 11,
    "SOC_DELIVERY_MINUTE": 0,
}

# Coercers for fields that need type conversion (JSON strings → ints, etc.)
_COERCERS = {
    "SMTP_PORT":           int,
    "MAX_NEWS_TO_MANAGER": int,
    "MAX_NEWS_PER_SOC_EMAIL": int,
    "SCRAPING_HOUR":       int,
    "SCRAPING_MINUTE":     int,
    "SOC_DELIVERY_HOUR":   int,
    "SOC_DELIVERY_MINUTE": int,
}


# Settings that may be supplied by the environment instead of the JSON file, as
# `TI_<NAME>`. The environment wins, so a server deployment can keep credentials
# in systemd's EnvironmentFile / AWS Secrets Manager and leave the on-disk
# admin_settings.json free of secrets. Everything else still comes from the JSON
# file so the /admin panel keeps working exactly as before.
#
# Note the trade-off: a value set in the environment cannot be changed from the
# /admin panel (the panel writes the JSON, which the environment then overrides).
# That is deliberate for credentials — see is_env_managed() below, which the
# panel uses to show the field as locked rather than silently ignoring an edit.
_ENV_OVERRIDABLE = {
    "SENDER_EMAIL", "SENDER_PASSWORD", "MANAGER_EMAIL", "VALIDATOR_EMAIL",
    "SOC_EMAIL", "SMTP_SERVER", "SMTP_PORT", "COMPANY_NAME",
}


def is_env_managed(name):
    """True if `name` is currently pinned by an environment variable."""
    return name in _ENV_OVERRIDABLE and bool(os.environ.get(f"TI_{name}", "").strip())


def _get_setting(name):
    env_value = os.environ.get(f"TI_{name}") if name in _ENV_OVERRIDABLE else None
    if env_value is not None and env_value.strip() != "":
        value = env_value.strip()
    else:
        settings = _load_admin_settings()
        value = settings.get(name, _DEFAULTS[name])
    if name in _COERCERS:
        try:
            value = _COERCERS[name](value)
        except (ValueError, TypeError):
            value = _COERCERS[name](_DEFAULTS[name])
    return value


# PEP 562 module __getattr__: every access to an editable field on this
# module re-reads from the JSON file (mtime-cached), so /admin saves apply
# to the live process without any restart.
def __getattr__(name):
    if name in _DEFAULTS:
        return _get_setting(name)
    if name == "SCRAPING_TIME":
        return datetime_time(_get_setting("SCRAPING_HOUR"), _get_setting("SCRAPING_MINUTE"))
    if name == "SOC_DELIVERY_TIME":
        return datetime_time(_get_setting("SOC_DELIVERY_HOUR"), _get_setting("SOC_DELIVERY_MINUTE"))
    raise AttributeError(f"module 'config' has no attribute {name!r}")


# Non-editable constants below. These stay as plain module attributes
# (not routed through __getattr__) because they're code-not-config.

DOMAIN = "fintech"

# ── Deployment environment ──────────────────────────────────────────────
# Set TI_ENV=production on a server. It tightens defaults that are
# deliberately loose for local development: secure session cookies, a
# required admin password, no wildcard Socket.IO origins.
ENVIRONMENT = (os.environ.get("TI_ENV") or "development").strip().lower()
IS_PRODUCTION = ENVIRONMENT == "production"

# All wall-clock scheduling and display happens in this zone. APScheduler
# otherwise falls back to the machine's local timezone, which is IST on a
# developer laptop and UTC on a default EC2 instance — a silent 5h30m shift
# in when the scrape and the SOC delivery fire.
APP_TIMEZONE = (os.environ.get("TI_TIMEZONE") or "Asia/Kolkata").strip()

# Absolute by default. A relative path resolves against the current working
# directory, so a service started from elsewhere (systemd's WorkingDirectory,
# a cron job, a shell in another folder) would silently create a second, empty
# database instead of opening the real one. Point TI_DATABASE_PATH at a
# location OUTSIDE this folder in production so redeploying the code cannot
# overwrite live data.
# Keep it on a local disk: SQLite's locking is not reliable over NFS/EFS.
DATABASE_PATH = os.environ.get("TI_DATABASE_PATH") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "threat_intel.db"
)

# Writable directory for runtime state the app generates itself: the shared
# signing secret and the generated bootstrap admin password. Defaults to the
# project folder (unchanged local behaviour), but must be moved off it in
# production — a hardened systemd unit mounts the code directory read-only, and
# state belongs with the data anyway.
STATE_DIR = os.environ.get("TI_STATE_DIR") or _HERE

# The HMAC secret shared by every process: it signs email action links, the
# internal API tokens and Flask sessions. All processes MUST agree on this path
# or links minted by one will not verify in another.
SECRET_KEY_FILE = os.environ.get("TI_SECRET_KEY_FILE") or os.path.join(
    STATE_DIR, ".flask_secret_key"
)

SOC_DELIVERY_DELAY_HOURS = 0  # Hours to wait before sending first approved news to SOC (0 = immediate)

# How long system_logs / activity_log rows and old rejected articles are kept.
# Enforced daily by scheduler.setup_log_retention.
LOG_RETENTION_DAYS = int(os.environ.get("TI_LOG_RETENTION_DAYS", "90"))

# Testing Configuration
TESTING_MODE = False  # Set to True for immediate testing

# ── Access control (Phase 0) ────────────────────────────────────────────
# Firebase verifies a sign-in is genuine; these settings restrict WHICH
# accounts from the organization are actually allowed in and who is privileged.
# Phase 1 moves these into managed database tables.

# Only e-mail addresses in these domains may sign in. Empty/unknown domains are
# rejected (fail closed). Bootstrap admins below are exempt.
#
# Set via TI_ALLOWED_EMAIL_DOMAINS (comma-separated) in .env — the real company
# domains are deliberately NOT hardcoded here so this file is safe to publish.
ALLOWED_EMAIL_DOMAINS = _env_list("TI_ALLOWED_EMAIL_DOMAINS", ["sentinel-demo.io"])

# These accounts are always treated as admin regardless of stored role, so the
# platform owner can never be locked out while RBAC is being set up.
# Set via TI_BOOTSTRAP_SUPER_ADMINS (comma-separated) in .env. Empty by default:
# a published copy of this repo must not grant anyone standing admin rights.
BOOTSTRAP_SUPER_ADMINS = _env_list("TI_BOOTSTRAP_SUPER_ADMINS", [])

# ── RBAC roles ──────────────────────────────────────────────────────────
# Every user carries exactly one role (see rbac.py for the authoritative
# definitions and the hierarchy):
#   viewer         "Dashboard Viewer" — read-only
#   analyst_admin  "Analyst + Admin"  — all operations + the settings panel
#   admin          "Admin"            — the above + user / role management
#
# Local (non-Firebase) accounts are created by an admin in the Users & Roles
# panel and authenticate with the email+password box on the login page. On a
# fresh database this default admin is seeded so the app is usable immediately.
# Change the password from the admin panel after first sign-in.
DEFAULT_ADMIN_EMAIL = os.environ.get(
    "TI_DEFAULT_ADMIN_EMAIL", "admin@sentinel-demo.io"
).strip().lower()
DEFAULT_ADMIN_NAME = "Threat Intelligence Admin"

# Bootstrap password for the seeded admin. Only ever used on a completely empty
# database (see database.ensure_default_admin), but "password" on a
# network-reachable server is an open door, so it is no longer the production
# default:
#   1. TI_DEFAULT_ADMIN_PASSWORD, if set, always wins.
#   2. In production with nothing set, generate a random one and persist it to
#      .initial_admin_password (0600) so the operator can read it once, log in,
#      and change it. Same pattern Jenkins uses for its first-run secret.
#   3. Locally, keep "password" so development stays frictionless.
_INITIAL_ADMIN_PW_FILE = os.path.join(STATE_DIR, ".initial_admin_password")


# True once the generated bootstrap password is readable from
# _INITIAL_ADMIN_PW_FILE (0600). Entry points use this to decide whether they
# still have to print the credential: if it is on disk, the log should carry
# only the path. journald is far more widely readable than a 0600 file, and log
# lines get pasted into tickets and chat.
DEFAULT_ADMIN_PASSWORD_PERSISTED = False


def _bootstrap_admin_password():
    global DEFAULT_ADMIN_PASSWORD_PERSISTED
    from_env = os.environ.get("TI_DEFAULT_ADMIN_PASSWORD", "").strip()
    if from_env:
        return from_env
    if not IS_PRODUCTION:
        return "password"
    # Reuse an already-generated password so restarts stay consistent.
    try:
        with open(_INITIAL_ADMIN_PW_FILE, "r") as f:
            existing = f.read().strip()
        if existing:
            DEFAULT_ADMIN_PASSWORD_PERSISTED = True
            return existing
    except OSError:
        pass
    import secrets as _secrets
    generated = _secrets.token_urlsafe(18)
    try:
        fd = os.open(_INITIAL_ADMIN_PW_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, generated.encode("utf-8"))
        finally:
            os.close(fd)
        DEFAULT_ADMIN_PASSWORD_PERSISTED = True
    except FileExistsError:
        with open(_INITIAL_ADMIN_PW_FILE, "r") as f:
            DEFAULT_ADMIN_PASSWORD_PERSISTED = True
            return f.read().strip()
    except OSError:
        # Can't persist it — still better than a known default, but now the log
        # is the only channel left, so entry points fall back to printing it.
        pass
    return generated


DEFAULT_ADMIN_PASSWORD = _bootstrap_admin_password()
INITIAL_ADMIN_PW_FILE = _INITIAL_ADMIN_PW_FILE

# When someone with no account tries to sign in, an access request is filed for
# review on the Users & Access page. Admins are always notified in-app (system
# log + live badge); this additionally emails every active admin.
# Set ACCESS_REQUEST_EMAIL=0 in the environment to silence the emails on a dev
# or staging box while keeping the in-app notification.
ACCESS_REQUEST_EMAIL_ENABLED = os.environ.get(
    "ACCESS_REQUEST_EMAIL", "1"
).strip().lower() not in ("0", "false", "no", "off")

# ── Web server addresses ────────────────────────────────────────────────
# Three genuinely different things, previously conflated into one value:
#
#   *_BIND_HOST   the interface a server listens on. 127.0.0.1 accepts only
#                 local connections; 0.0.0.0 accepts from the network. Keep it
#                 at 127.0.0.1 when nginx proxies (nginx reaches it locally).
#   CALLBACK_BASE_URL   the address written into email buttons. This is
#                 resolved in the RECIPIENT's browser, so "localhost" means
#                 the recipient's own laptop — which is why the Approve /
#                 Reject links do nothing once mail leaves this machine.
#   INTERNAL_DASHBOARD_URL  how our own processes reach the dashboard API.
#
CALLBACK_BIND_HOST = os.environ.get("TI_CALLBACK_BIND_HOST", "127.0.0.1").strip()
CALLBACK_SERVER_PORT = int(os.environ.get("TI_CALLBACK_PORT", "5000"))

DASHBOARD_BIND_HOST = os.environ.get("TI_DASHBOARD_BIND_HOST", "127.0.0.1").strip()
DASHBOARD_PORT = int(os.environ.get("TI_DASHBOARD_PORT", "5001"))

# Backwards-compatible alias — callback_server.py imports this name.
CALLBACK_SERVER_HOST = CALLBACK_BIND_HOST

# The externally reachable base URL for email action links. MUST be set in
# production to something every recipient can resolve, e.g.
#   TI_PUBLIC_BASE_URL=https://threatintel.internal.example.com
# The startup check below refuses to run in production without it rather than
# letting a week's worth of emails ship with dead buttons.
CALLBACK_BASE_URL = (
    os.environ.get("TI_PUBLIC_BASE_URL", "").strip().rstrip("/")
    or f"http://localhost:{CALLBACK_SERVER_PORT}"
)

# Public base URL of the dashboard, used for links in notification emails.
# Defaults to the callback URL because a single nginx vhost usually fronts both.
DASHBOARD_BASE_URL = (
    os.environ.get("TI_DASHBOARD_PUBLIC_URL", "").strip().rstrip("/")
    or os.environ.get("TI_PUBLIC_BASE_URL", "").strip().rstrip("/")
    or f"http://localhost:{DASHBOARD_PORT}"
)

# Loopback address our own background processes use to POST workflow events to
# the dashboard. Always local — never route this through the public hostname.
INTERNAL_DASHBOARD_URL = (
    os.environ.get("TI_INTERNAL_DASHBOARD_URL", "").strip().rstrip("/")
    or f"http://127.0.0.1:{DASHBOARD_PORT}"
)

# ── Remote inference (split deployment) ──────────────────────────────────────
# Unset (the default) means the summarisation and sentence-ranking models load
# inside this process — how a laptop and the single-box deployment both work.
# Set it, and only those two calls become HTTP requests to a box that holds the
# models; article cleaning, sentence splitting and report assembly stay here.
# See deploy/SPLIT-DEPLOYMENT.md.
INFERENCE_URL = os.environ.get("TI_INFERENCE_URL", "").strip().rstrip("/")

# Shared secret sent as `Authorization: Bearer <token>`. The inference service
# has no other authentication, so this is required whenever INFERENCE_URL is set
# — see validate_deployment() below.
INFERENCE_TOKEN = os.environ.get("TI_INFERENCE_TOKEN", "").strip()

# Seconds to wait on one inference call. bart-large-cnn on CPU is single-digit
# seconds per article; the generous default absorbs a cold model load right after
# a restart of the inference box without failing the article outright.
INFERENCE_TIMEOUT = int(os.environ.get("TI_INFERENCE_TIMEOUT", "120"))

# Consecutive failures before the client stops calling the inference service and
# falls back to non-AI summaries for a cooldown. Without this, an inference box
# that is down turns a 50-article scrape into 50 sequential timeouts — over an
# hour of waiting to produce exactly the same output the fallback gives
# immediately. The counter resets on any success.
INFERENCE_FAILURE_LIMIT = int(os.environ.get("TI_INFERENCE_FAILURE_LIMIT", "3"))
INFERENCE_COOLDOWN_SECONDS = int(os.environ.get("TI_INFERENCE_COOLDOWN", "300"))

# Number of reverse proxies in front of the app. 0 means "no proxy" and the
# app reads the peer address directly. Set to 1 behind a single nginx/ALB so
# Flask resolves the real client IP from X-Forwarded-For. Setting this higher
# than the actual number of proxies lets a client spoof its own IP by sending
# its own X-Forwarded-For header, so count carefully.
TRUSTED_PROXY_HOPS = int(os.environ.get("TI_TRUSTED_PROXY_HOPS", "0"))

# Socket.IO CORS. "*" is fine on a laptop; in production it lets any website a
# logged-in user visits open an authenticated socket to the dashboard.
_cors = os.environ.get("TI_CORS_ORIGINS", "").strip()
if _cors:
    CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors.split(",") if o.strip()]
elif IS_PRODUCTION:
    CORS_ALLOWED_ORIGINS = [DASHBOARD_BASE_URL]
else:
    CORS_ALLOWED_ORIGINS = "*"


# ── Firebase browser sign-in ────────────────────────────────────────────
# These identify the Firebase project to the browser SDK. Google ships them in
# client-side JavaScript by design, so they are identifiers rather than secrets
# — access is controlled by Firebase's Authorized Domains list and by this app's
# own domain allowlist and RBAC, not by keeping these values hidden.
#
# They still live in the gitignored .env rather than in this committed file, so
# a published copy of the repository does not name your Firebase project. A
# fresh clone therefore has no sign-in configured until .env is filled in; the
# login page says so explicitly instead of failing with a JavaScript error.
FIREBASE_CONFIG = {
    "apiKey": os.environ.get("TI_FIREBASE_API_KEY", "").strip(),
    "authDomain": os.environ.get("TI_FIREBASE_AUTH_DOMAIN", "").strip(),
    "projectId": os.environ.get("TI_FIREBASE_PROJECT_ID", "").strip(),
    "storageBucket": os.environ.get("TI_FIREBASE_STORAGE_BUCKET", "").strip(),
    "messagingSenderId": os.environ.get("TI_FIREBASE_MESSAGING_SENDER_ID", "").strip(),
    "appId": os.environ.get("TI_FIREBASE_APP_ID", "").strip(),
    "measurementId": os.environ.get("TI_FIREBASE_MEASUREMENT_ID", "").strip(),
}

# Sign-in is only possible when at least the API key and project are known.
FIREBASE_CONFIGURED = bool(FIREBASE_CONFIG["apiKey"] and FIREBASE_CONFIG["projectId"])


# ── Visual branding ─────────────────────────────────────────────────────
# The templates and the approval emails used to hardcode a specific company's
# logo files, wordmark and signature colour. That named the employer in every
# committed file, so it moved here: the repository ships a neutral identity and
# a deployment overrides it from the environment.
#
# BRAND_LOGO is the wide wordmark slot (height-constrained, width auto).
# BRAND_ICON is the fixed square slot — sidebar mark and favicon.
# Both are URL paths served by Flask, so a deployment drops its own file into
# static/ (the static/brand-* names are gitignored) and points these at it.
BRAND_NAME = (os.environ.get("TI_BRAND_NAME") or "Threat Intel").strip()
BRAND_LOGO = (os.environ.get("TI_BRAND_LOGO") or "/static/shield-logo.svg").strip()
BRAND_ICON = (os.environ.get("TI_BRAND_ICON") or "/static/shield-logo.svg").strip()

# Primary accent, used for headings and links in the HTML emails. Must be a CSS
# hex colour: it is interpolated straight into a style attribute, and email
# clients strip anything they cannot parse, so a malformed value would silently
# render unstyled text.
_brand_color = (os.environ.get("TI_BRAND_COLOR") or "").strip()
BRAND_COLOR = _brand_color if re.fullmatch(r"#[0-9A-Fa-f]{3,8}", _brand_color) else "#2F6BFF"

BRAND = {
    "name": BRAND_NAME,
    "logo": BRAND_LOGO,
    "icon": BRAND_ICON,
    "color": BRAND_COLOR,
}


def _is_private_host(url: str) -> bool:
    """True when `url`'s host is a private/loopback IP address.

    Used to allow plain HTTP for the inference link: over a Lightsail↔VPC peering
    connection the traffic never leaves AWS's network, so requiring TLS there
    would mean issuing certificates for an RFC1918 address for no gain. A
    hostname (rather than an IP) returns False — we cannot tell where it resolves,
    so it is treated as public and must use HTTPS.
    """
    import ipaddress
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or ""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def validate_deployment():
    """Fail fast on misconfiguration that would otherwise show up as silently
    broken email links or an unreachable dashboard.

    Returns a list of human-readable problem strings; empty means OK. Called by
    each entry point at startup — fatal in production, a warning locally.
    """
    problems = []
    if IS_PRODUCTION:
        if not os.environ.get("TI_PUBLIC_BASE_URL", "").strip():
            problems.append(
                "TI_PUBLIC_BASE_URL is not set. Approve/Reject buttons in email "
                "would point at http://localhost and do nothing for recipients."
            )
        elif "localhost" in CALLBACK_BASE_URL or "127.0.0.1" in CALLBACK_BASE_URL:
            problems.append(
                f"TI_PUBLIC_BASE_URL is {CALLBACK_BASE_URL!r}, which resolves to the "
                "recipient's own machine. Use the server's hostname."
            )
        elif not CALLBACK_BASE_URL.startswith("https://"):
            problems.append(
                f"TI_PUBLIC_BASE_URL is {CALLBACK_BASE_URL!r} — plain HTTP. Approval "
                "links and login tokens would cross the network unencrypted."
            )
        if not os.environ.get("TI_DEFAULT_ADMIN_PASSWORD", "").strip():
            problems.append(
                "TI_DEFAULT_ADMIN_PASSWORD is not set; a random one is generated "
                f"on first run and written to {_INITIAL_ADMIN_PW_FILE} (0600). "
                "Read it, log in, change it, delete the file."
            )
        if not _get_setting("SENDER_PASSWORD"):
            problems.append("No SENDER_PASSWORD configured — no email can be sent.")
        if not FIREBASE_CONFIGURED:
            problems.append(
                "Firebase is not configured (TI_FIREBASE_API_KEY / "
                "TI_FIREBASE_PROJECT_ID) — nobody will be able to sign in."
            )
        if not ALLOWED_EMAIL_DOMAINS:
            problems.append(
                "TI_ALLOWED_EMAIL_DOMAINS is empty — the domain allowlist fails "
                "closed, so every sign-in will be rejected."
            )

    # Checked in every environment, not just production: article text should not
    # be posted to an endpoint that authenticates nobody, on a laptop either.
    if INFERENCE_URL:
        if not INFERENCE_TOKEN:
            problems.append(
                "TI_INFERENCE_URL is set but TI_INFERENCE_TOKEN is empty. The "
                "inference service authenticates on that token alone, so this "
                "would post article text to an open endpoint."
            )
        if IS_PRODUCTION and not (
            INFERENCE_URL.startswith("https://") or _is_private_host(INFERENCE_URL)
        ):
            problems.append(
                f"TI_INFERENCE_URL is {INFERENCE_URL!r} — plain HTTP to a host that "
                "is not a private address. The bearer token would cross the public "
                "internet in clear text. Use the peered private IP, or HTTPS."
            )
    return problems

# News Sources Configuration - OPTIMIZED FOR FINANCIAL SERVICES & COMPLIANCE
#
# All six are live. Five of them sat commented out for a while, which left the
# whole pipeline resting on one site staying reachable — and the README still
# advertised six, so a source silently going dark looked like "a quiet news week"
# rather than a fault. `python health_checks.py` fetches every feed here
# end-to-end and is the thing that tells them apart.
#
# Two rules learned the hard way, both about failures that look like success:
#   * The feed URL must stay on the source's own host. An off-site redirect
#     (Blogger -> feeds.feedburner.com) is commonly blocked by corporate
#     VPNs/firewalls, and that broke scraping entirely once.
#   * A feed URL can return HTTP 200 and still parse to zero entries. That is
#     how bankinfosecurity.com/rss.xml behaves now — it is a page, not a feed —
#     so this list uses /rss-feeds, which actually yields items. Re-check with
#     health_checks.py rather than trusting a 200.
#
# `selectors` are only used by the direct-scrape fallback when a feed fails, so
# they are best-effort; RSS is the primary path for every source.
NEWS_SOURCES = [
    {
        "name": "The Hacker News",
        "url": "https://thehackernews.com",
        # redirect=false keeps the feed on thehackernews.com — without it,
        # Blogger 302-redirects to feeds.feedburner.com, which corporate
        # VPNs/firewalls commonly block (this broke scraping entirely).
        "rss": "https://thehackernews.com/feeds/posts/default?redirect=false",
        "selectors": {
            "title": "h2.home-title",
            "link": "a",
            "summary": ".home-desc"
        }
    },
    {
        "name": "Security Week",
        "url": "https://www.securityweek.com",
        "rss": "https://www.securityweek.com/feed/",
        "selectors": {
            # Was h3.entry-title, which matched nothing after a site redesign —
            # the direct-scrape fallback had been silently dead. `article h2`
            # yields 15/15 headlines whose link resolves to the matching story.
            # Preferred over the theme-specific .zox-art-title, which also works
            # but breaks whenever the WordPress theme changes.
            "title": "article h2",
            "link": "a",
            "summary": ".entry-summary"
        }
    },
    {
        "name": "CSO Online",
        "url": "https://www.csoonline.com",
        "rss": "https://www.csoonline.com/feed/",
        "selectors": {
            "title": "h3",
            "link": "a",
            "summary": ".excerpt"
        }
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com",
        "rss": "https://krebsonsecurity.com/feed/",
        "selectors": {
            "title": "h2",
            "link": "a",
            "summary": ".entry-summary"
        }
    },
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com",
        "rss": "https://www.bleepingcomputer.com/feed/",
        "selectors": {
            # Was "h2", which matched nothing — headlines are h4 here. Scoped to
            # the main news wrapper rather than a bare "h4" so sidebar and
            # webinar-promo blocks stay out of the article list.
            "title": "#bc-home-news-main-wrap h4",
            "link": "a",
            "summary": ".summary"
        }
    },
    # Bank Info Security is deliberately NOT enabled. Every feed URL it exposes
    # fails one of the two rules above:
    #   /rss.xml      → HTTP 200, zero entries (it is a page, not a feed)
    #   /rss-feeds    → 20 entries, but not one carries a date, and the items
    #                   include evergreen/archive material (e.g. "End of
    #                   Microsoft Support for Windows XP")
    # Undated entries defeat the scraper's 7-day freshness filter, which then
    # errs on the side of inclusion — so enabling it would quietly place
    # decade-old advisories into a weekly digest presented as current threat
    # intelligence. A missing source is a smaller problem than a wrong one.
    # Re-enable only with a feed whose entries carry real publish dates; verify
    # with `python health_checks.py` before trusting it.
]

# Keywords for filtering relevant news - ENHANCED FOR FINTECH COMPANIES
CYBERSECURITY_KEYWORDS = [
    # Indian Financial Regulatory Bodies
    "SEBI", "Securities and Exchange Board", "RBI", "Reserve Bank of India", "NPCI", "National Payments Corporation",
    "IRDAI", "Insurance Regulatory", "PFRDA", "Pension Fund Regulatory", "CERT-In", "IDRBT",
    
    # Financial services & Banking
    "payment", "fintech", "financial services", "banking", "digital wallet", "mobile payment", 
    "online banking", "financial technology", "payment processing", "digital finance", "neobank",
    "payment gateway", "UPI", "RTGS", "NEFT", "IMPS", "digital rupee", "CBDC", "core banking",
    "merchant services", "acquirer", "payment service provider", "PSP", "payment facilitator",
    
    # Payment Systems & Technologies
    "payment gateway breach", "UPI fraud", "digital wallet hack", "mobile payment security",
    "peer-to-peer payment", "QR code fraud", "contactless payment", "tap-to-pay", "NFC security",
    "payment tokenization", "3D Secure", "EMV", "chip-and-pin", "payment orchestration",
    "Bharat QR", "RuPay", "Aadhaar Pay", "Bharat Bill Payment", "FASTag", "e-RUPI",
    
    # Technology Stacks & Infrastructure  
    "API security", "cloud security", "mobile security", "web application", "database security",
    "microservices", "container security", "Kubernetes", "Docker", "AWS", "Azure", "Google Cloud",
    "DevSecOps", "CI/CD security", "infrastructure security", "network security", "serverless",
    "payment API", "banking API", "open banking", "PSD2", "financial API security", "REST API",
    "GraphQL security", "SWIFT security", "ISO 20022",
    
    # Critical Cybersecurity Terms
    "cyber security", "cybersecurity", "security breach", "data breach", "cyber attack", 
    "security vulnerability", "malware", "ransomware", "phishing", "fraud", "hacking", 
    "threat intelligence", "security incident", "cyber threat", "incident response",
    
    # Financial Sector Threats & Malware
    "payment fraud", "financial malware", "banking trojan", "banking malware", "ATM malware",
    "POS malware", "card cloning", "card skimming", "ATM security", "POS security",
    "card-not-present fraud", "account takeover", "synthetic identity fraud", "first-party fraud",
    "SIM swap fraud", "vishing", "smishing", "fake payment app", "rogue banking app",
    "man-in-the-browser", "session hijacking", "credential stuffing", "money mule",
    
    # Cryptocurrency & Blockchain
    "cryptocurrency security", "blockchain security", "crypto exchange", "cryptocurrency wallet",
    "DeFi", "decentralized finance", "smart contract vulnerability", "blockchain attack",
    "crypto theft", "NFT security", "cryptocurrency fraud", "wallet compromise",
    
    # Financial Data & Transactions
    "financial data", "transaction security", "financial crime", "money laundering", "KYC", "AML",
    "credit card data", "debit card", "account number", "IFSC code", "PAN card", "Aadhaar number",
    "financial credentials", "bank statement", "transaction history", "credit score", "CIBIL",
    "transaction monitoring", "fraud detection", "risk scoring", "behavioral biometrics",
    
    # High-Impact Vulnerabilities
    "zero-day", "CVE", "critical vulnerability", "security patch", "exploit", "remote code execution",
    "privilege escalation", "authentication bypass", "data exposure", "information disclosure",
    "SQL injection", "XSS", "CSRF", "OWASP", "penetration testing", "deserialization",
    
    # Compliance & Regulatory
    "PCI DSS", "PA-DSS", "financial compliance", "regulatory compliance", "GDPR", "data protection",
    "financial regulation", "security standards", "ISO 27001", "NIST framework", "SOX compliance",
    "Basel III", "COSO framework", "risk management", "governance", "RBI cyber security framework",
    "SEBI cyber resilience", "data localization", "data residency", "PMLA", "IT Act 2000",
    "Digital Personal Data Protection", "Payment and Settlement Systems Act", "FEMA",
    
    # Modern Attack Vectors
    "supply chain attack", "social engineering", "insider threat", "advanced persistent threat", 
    "APT", "nation-state", "business email compromise", "deepfake", "AI security",
    "machine learning attacks", "adversarial AI", "screen overlay attack", "SMS interception",
    "BIN attack", "payment orchestration attack",
    
    # Technology Security
    "application security", "endpoint security", "identity management", "zero trust",
    "multi-factor authentication", "2FA", "OTP security", "encryption", "tokenization",
    "secure coding", "SAST", "DAST", "biometric authentication", "fingerprint payment",
    "face recognition payment", "voice authentication",
    
    # Fintech Infrastructure & Systems
    "banking as a service", "BaaS", "embedded finance", "financial SaaS", "cloud banking",
    "fintech microservices", "CBS", "banking software", "financial application",
    "loan management system", "credit scoring system", "KYC system", "AML software",
    "transaction processing", "clearing house", "settlement system", "payment switch",
    "HSM", "hardware security module", "TPM", "tokenization vault", "card data environment",
    "lending platform", "crowdfunding platform", "robo-advisor", "insurtech", "regtech",
    
    # Emerging Technologies
    "artificial intelligence", "machine learning", "blockchain", "smart contracts", "IoT security",
    "5G security", "quantum computing", "quantum cryptography", "edge computing"
]

# Priority keywords (higher weight in scoring) - ENHANCED FOR FINTECH COMPANIES
HIGH_PRIORITY_KEYWORDS = [
    # Indian Regulatory & Compliance (HIGHEST PRIORITY)
    "SEBI", "RBI", "Reserve Bank of India", "Securities and Exchange Board", "NPCI", "CERT-In",
    "regulatory action", "RBI guidelines", "SEBI regulations", "NPCI security standards",
    "RBI cyber security framework", "SEBI cyber resilience", "data localization",
    
    # Financial Services & Payment Systems (HIGHEST PRIORITY)
    "payment", "fintech", "financial services", "banking", "digital payment", "financial institution", 
    "payment gateway", "UPI", "RTGS", "NEFT", "IMPS", "digital rupee", "CBDC", "neobank",
    "payment fraud", "UPI fraud", "mobile banking", "digital wallet", "payment processing",
    "core banking", "CBS", "payment API", "banking API", "open banking", "BaaS",
    
    # Critical Security Events (HIGHEST PRIORITY)
    "critical vulnerability", "zero-day", "security breach", "data breach", "financial fraud", 
    "payment fraud", "ransomware", "banking trojan", "banking malware", "ATM malware",
    "emergency", "widespread", "active exploitation", "actively exploited", "in the wild",
    "supply chain attack", "APT", "nation-state", "incident response", "emergency patch",
    "account takeover", "credential stuffing", "SIM swap", "card cloning",
    
    # Financial Data & Compliance (HIGHEST PRIORITY)
    "PCI DSS", "financial data", "card data", "transaction data", "customer data",
    "data localization", "regulatory compliance", "AML", "KYC", "financial crime",
    "money laundering", "payment card", "credit card data", "financial PII",
    
    # Technology Infrastructure (HIGH PRIORITY)
    "API security", "cloud security", "AWS", "Azure", "Google Cloud", "microservices",
    "container security", "Kubernetes", "database security", "web application security",
    "payment gateway", "HSM", "hardware security module", "tokenization", "encryption"
]

# Static delivery flags (not exposed in /admin)
MAX_NEWS_PER_DAY_SOC = 1
ENFORCE_NUMBERING_1_TO_10 = True

# Timezone Configuration
import pytz

# Set system timezone to Asia/Kolkata
SYSTEM_TIMEZONE = pytz.timezone('Asia/Kolkata')

def get_current_time():
    """Get current time in system timezone"""
    from datetime import datetime
    return datetime.now(SYSTEM_TIMEZONE)

def format_timestamp(dt=None):
    """Format timestamp in system timezone"""
    if dt is None:
        dt = get_current_time()
    elif dt.tzinfo is None:
        dt = SYSTEM_TIMEZONE.localize(dt)
    return dt.strftime('%Y-%m-%d %H:%M:%S %Z')
