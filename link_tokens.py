"""Unforgeable tokens for email action links (approve / reject / validate).

The callback server exposes state-changing endpoints (approve an article, reject
it, schedule the SOC delivery) that are reached when the recipient clicks a link
in an email. Those endpoints used to trust the bare, sequential article id in the
URL — so anyone who could reach the server (including a browser lured to
`http://localhost:5000/approve/1` by any web page) could drive the workflow and
trigger real email deliveries.

Every action link now carries an HMAC token bound to (action, article_id). The
token is signed with a secret shared across the project's processes (dashboard,
scheduler, callback server) via the on-disk `.flask_secret_key` file, so a link
minted by the mail-sending process verifies in the separate callback process.

Usage:
    make_token("approve", article_id)          -> token string for the URL
    verify_token(token, "approve", article_id) -> True / False
"""

import os
import hmac
import time
import base64
import hashlib

import config

# Single source of truth for the secret's location (TI_SECRET_KEY_FILE). It used
# to be hardcoded to the project directory, which a hardened deployment mounts
# read-only — and every process must agree on the path or a link minted by the
# mail sender will not verify in the callback server.
_KEY_FILE = config.SECRET_KEY_FILE

# Links live in emails that may legitimately be actioned days after they are
# sent, so tokens stay valid for a generous window rather than a session.
DEFAULT_MAX_AGE = 30 * 24 * 3600  # 30 days, in seconds


def _secret() -> bytes:
    """Return the shared signing secret, creating it once if absent.

    Mirrors the dashboard's own key handling: 32 random bytes persisted with
    0600 perms. Uses O_EXCL so concurrent first-run processes don't clobber
    each other."""
    try:
        with open(_KEY_FILE, "rb") as f:
            data = f.read()
        if data:
            return data
    except FileNotFoundError:
        pass
    key = os.urandom(32)
    try:
        fd = os.open(_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    except FileExistsError:
        # Another process created it between our read and create; use theirs.
        with open(_KEY_FILE, "rb") as f:
            return f.read()


def _sign(message: bytes) -> str:
    digest = hmac.new(_secret(), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def make_token(action: str, article_id) -> str:
    """Mint a URL-safe token authorizing `action` on `article_id`."""
    ts = str(int(time.time()))
    signature = _sign(f"{action}:{article_id}:{ts}".encode("utf-8"))
    return f"{ts}.{signature}"


def verify_token(token: str, action: str, article_id, max_age: int = DEFAULT_MAX_AGE) -> bool:
    """True iff `token` is a valid, unexpired token for (action, article_id)."""
    if not token or "." not in token:
        return False
    ts_str, signature = token.split(".", 1)
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if max_age is not None and abs(time.time() - ts) > max_age:
        return False
    expected = _sign(f"{action}:{article_id}:{ts}".encode("utf-8"))
    return hmac.compare_digest(signature, expected)


# ── Process-to-process authentication ───────────────────────────────────────
# The dashboard's /api/notify_* endpoints accept workflow events from the
# callback server and the validation sender. Those used to be protected purely
# by "is request.remote_addr localhost?", which silently stops being a check the
# moment a reverse proxy is put in front — every proxied request then arrives
# from 127.0.0.1. These tokens make the guard independent of network topology:
# only a process that can read .flask_secret_key (i.e. one running as the app
# user on the app host) can mint one.

INTERNAL_HEADER = "X-Internal-Token"

# Short window: unlike email links, these calls are made immediately by a local
# process, so there is no reason to honour an old one.
INTERNAL_MAX_AGE = 300  # 5 minutes


def internal_token() -> str:
    """Mint a token proving the caller is a local project process."""
    ts = str(int(time.time()))
    return f"{ts}.{_sign(f'internal:{ts}'.encode('utf-8'))}"


def verify_internal_token(token: str, max_age: int = INTERNAL_MAX_AGE) -> bool:
    """True iff `token` was minted by a process sharing our signing secret."""
    if not token or "." not in token:
        return False
    ts_str, signature = token.split(".", 1)
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if max_age is not None and abs(time.time() - ts) > max_age:
        return False
    return hmac.compare_digest(signature, _sign(f"internal:{ts}".encode("utf-8")))


def internal_headers() -> dict:
    """Ready-made headers for an internal POST to the dashboard."""
    return {INTERNAL_HEADER: internal_token()}
