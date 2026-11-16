"""Everything the React front end needs from Flask, in one optional file.

This module is deliberately self-contained and additive. It defines no
behaviour for any existing URL: it adds one read-only API endpoint and serves
the built React bundle under /app/, a prefix nothing else uses. Deleting this
file and its one registration line returns the app to exactly what it was.

Wiring it up — one line near the bottom of web_dashboard.py, after `app` and
its routes exist:

    import frontend_bridge; frontend_bridge.mount(app)

plus '/api/public-config' in that module's _AUTH_PUBLIC_PREFIXES, so the config
endpoint is reachable before sign-in (see public_config below for why that is
safe). Nothing else changes. The Jinja pages, the scheduler, email delivery and
the approval flow are untouched.

/app/ is deliberately NOT exempt: the auth gate redirects signed-out visitors
to /login before the bundle is served, exactly as it does for the Jinja pages.

Two things live here:

  /api/public-config   The branding and Firebase values that the Jinja
                       templates get from a context processor. React renders in
                       the browser and cannot read Jinja context, so it reads
                       them over HTTP instead. Both are already public — today
                       they are inlined into the HTML of every page served.

  /app/...             The built bundle from frontend/dist, if one exists.
                       Not needed for development: `npm run dev` serves the app
                       from Vite and proxies /api back here, so the only
                       endpoint dev mode needs from this file is the one above.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path

from flask import Blueprint, abort, jsonify, send_from_directory

import config

# frontend/dist, resolved relative to this file so the working directory does
# not matter (systemd and gunicorn do not agree on what it should be).
DIST = Path(__file__).resolve().parent / "frontend" / "dist"

bp = Blueprint("frontend_bridge", __name__)


@bp.get("/api/public-config")
def public_config():
    """Branding and Firebase browser config.

    Unauthenticated on purpose, matching the Jinja pages: the sign-in page
    needs the Firebase config before anyone is signed in. These are browser
    credentials — public by design, and already visible in the page source of
    every request this app serves. Nothing secret belongs in this response.

    That exemption is not automatic. web_dashboard's @app.before_request gate
    401s every path outside _AUTH_PUBLIC_PREFIXES, so '/api/public-config' has
    to be listed there for this to be reachable while signed out. Without it
    the endpoint still answers signed-in callers, which is why the settings
    page worked before anyone noticed — a React login page would not.
    """
    return jsonify(
        {
            "brand": config.BRAND,
            "firebase_config": config.FIREBASE_CONFIG,
            "firebase_configured": config.FIREBASE_CONFIGURED,
        }
    )


@bp.get("/app/")
@bp.get("/app/<path:subpath>")
def spa(subpath: str = ""):
    """Serve the built React app, with a client-side-routing fallback.

    A request for a real file gets that file. Anything else gets index.html so
    React Router can resolve the path — that is what makes /app/settings work
    on a hard refresh rather than 404ing.
    """
    index = DIST / "index.html"
    if not index.is_file():
        # No build present. Say so plainly instead of 404ing, because the
        # likeliest cause is a deploy that skipped `npm run build`.
        abort(
            503,
            description=(
                "The React front end has not been built. Run `npm install && "
                "npm run build` in frontend/, or use `npm run dev` for development."
            ),
        )

    target = (DIST / subpath).resolve() if subpath else None
    # The resolve()/is_relative_to() pair keeps a crafted subpath from escaping
    # dist; send_from_directory refuses traversal too, but the fallback below
    # would otherwise quietly turn a rejected path into an index.html response.
    if target and target.is_file() and target.is_relative_to(DIST):
        resp = send_from_directory(DIST, subpath)
        # Vite fingerprints everything in assets/, so those are safe to pin.
        if subpath.startswith("assets/"):
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return resp

    resp = send_from_directory(DIST, "index.html")
    # The entry point must never be cached, or a deploy ships new assets that
    # a stale index.html does not reference.
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


def mount(app) -> bool:
    """Register the blueprint. Returns True if it was added.

    Never raises. A front end that fails to mount must not stop the dashboard
    from starting — the scheduler, the delivery poller and the approval
    callbacks all run in this process, and none of them care about React.
    """
    try:
        if "frontend_bridge" in app.blueprints:
            return False
        # .mjs is missing from the system mime table on some macOS installs,
        # and a module script served as text/plain is refused by the browser.
        mimetypes.add_type("text/javascript", ".mjs")
        app.register_blueprint(bp)
        app.logger.info(
            "React front end mounted at /app/ (build %s)",
            "present" if (DIST / "index.html").is_file() else "not built yet",
        )
        return True
    except Exception as exc:  # pragma: no cover - defensive by design
        app.logger.warning("Front-end bridge not mounted: %s", exc)
        return False
