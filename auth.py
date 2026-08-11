"""Firebase ID-token verification for the dashboard.

The dashboard does not own the user database — Firebase Auth does. The browser
signs the user in via the Firebase JS SDK and posts the resulting ID token to
the server. We verify the token's signature against Google's published public
keys (no service-account key required) and trust its claims.
"""

import time
import threading
import logging
from typing import Dict, Optional

import jwt
import requests

import config

logger = logging.getLogger(__name__)

# Public Firebase project identifier. Must match the `firebaseConfig` block the
# browser uses — both now come from the same place (config.FIREBASE_CONFIG,
# populated from TI_FIREBASE_* in the gitignored .env), so the server and the
# client can no longer drift apart or leak the project name into the repository.
PROJECT_ID = config.FIREBASE_CONFIG["projectId"]
ISSUER = f"https://securetoken.google.com/{PROJECT_ID}"

# Google's public keys rotate; cache them with their stated max-age.
_GOOGLE_CERTS_URL = (
    "https://www.googleapis.com/robot/v1/metadata/x509/"
    "securetoken@system.gserviceaccount.com"
)
_certs_cache: Dict[str, str] = {}
_certs_expiry: float = 0.0
_certs_lock = threading.Lock()


def _fetch_certs() -> Dict[str, str]:
    """Return Firebase's signing certificates, refreshing on cache miss."""
    global _certs_cache, _certs_expiry
    now = time.time()
    if _certs_cache and now < _certs_expiry:
        return _certs_cache
    with _certs_lock:
        if _certs_cache and time.time() < _certs_expiry:
            return _certs_cache
        resp = requests.get(_GOOGLE_CERTS_URL, timeout=5)
        resp.raise_for_status()
        _certs_cache = resp.json()
        # Honor the Cache-Control max-age, fall back to one hour.
        cache_control = resp.headers.get("cache-control", "")
        max_age = 3600
        for part in cache_control.split(","):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        _certs_expiry = time.time() + max_age
        return _certs_cache


def verify_id_token(id_token: str) -> Optional[Dict]:
    """Verify a Firebase ID token. Returns claims dict on success, None on failure."""
    if not id_token:
        return None
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as e:
        logger.warning(f"Bad JWT header: {e}")
        return None

    kid = header.get("kid")
    if not kid:
        logger.warning("JWT missing kid")
        return None

    certs = _fetch_certs()
    cert_pem = certs.get(kid)
    if not cert_pem:
        # Key may have rotated; clear cache once and retry.
        global _certs_expiry
        _certs_expiry = 0.0
        cert_pem = _fetch_certs().get(kid)
        if not cert_pem:
            logger.warning(f"No Firebase public key for kid={kid}")
            return None

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    public_key = cert.public_key()

    try:
        claims = jwt.decode(
            id_token,
            public_key,
            algorithms=["RS256"],
            audience=PROJECT_ID,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt.PyJWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        return None

    # auth_time must be in the past (Firebase contract).
    auth_time = claims.get("auth_time")
    if auth_time is not None and auth_time > time.time():
        logger.warning("JWT auth_time in the future")
        return None
    if not claims.get("sub"):
        return None
    return claims


def user_from_claims(claims: Dict) -> Dict:
    """Pull the fields we want to put into the Flask session."""
    return {
        "uid":     claims.get("sub"),
        "email":   claims.get("email"),
        "name":    claims.get("name") or claims.get("email", "").split("@")[0],
        "picture": claims.get("picture"),
        "provider": (claims.get("firebase") or {}).get("sign_in_provider"),
        # Whether the IdP actually proved control of this address. Google
        # sign-in is always true; a Firebase email+password sign-up stays false
        # until the confirmation link is clicked. rbac.is_verified_identity()
        # gates the access audit log on this.
        "email_verified": bool(claims.get("email_verified")),
    }
