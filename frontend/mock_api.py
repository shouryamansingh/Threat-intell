"""A throwaway stand-in for the dashboard, for front-end work only.

Why this exists: importing web_dashboard starts the APScheduler jobs and the
SOC delivery poller, and that poller sends real email. Nobody should have to
start the live system to restyle a form. This serves the same JSON shapes as
the real endpoints, backed by fake data, so `npm run dev` has something to talk
to.

    python frontend/mock_api.py          # then: npm run dev
    TI_DASHBOARD_URL=http://127.0.0.1:5055 npm run dev

It writes nothing, reads nothing, and sends no mail. Never deploy it.
"""

from flask import Flask, jsonify, request

# static_folder=None so Flask's built-in /static route does not shadow the
# placeholder-asset handler below — there is no frontend/static directory, and
# the default route would 404 every brand image.
app = Flask(__name__, static_folder=None)

ACCOUNT = {
    "uid": "mock-uid-0001",
    "email": "alex.morgan@example.com",
    "name": "Alex Morgan",
    "picture": None,
    "provider": "google.com",
    "provider_label": "Google",
    "role": "admin",
    "role_label": "Administrator",
    "role_description": "Full control: manage users, settings, schedules and deliveries.",
    "capabilities": [
        {"name": "Approve and send SOC reports", "allowed": True},
        {"name": "Manage users and access requests", "allowed": True},
        {"name": "Change admin settings", "allowed": True},
        {"name": "Trigger scraping runs", "allowed": True},
        {"name": "View the access audit log", "allowed": True},
        {"name": "Delete the article archive", "allowed": False},
    ],
    "department": "IT Internal Audit",
    "phone": "+91 98765 43210",
    "notification_email": None,
    "created_at": "2026-02-11 09:14:02",
    "last_login": "2026-08-20 06:41:17",
    "active": True,
    "email_verified": True,
    "identity_verified": True,
    "is_bootstrap": False,
    # Try 'local', 'firebase' or 'none' to exercise the other password panels.
    "password_mode": "set",
    "editable": True,
}


@app.get("/api/public-config")
def public_config():
    return jsonify({
        "brand": {"name": "Threat Intel", "logo": "/static/shield-logo.svg",
                  "icon": "/static/shield-logo.svg", "color": "#2F6BFF"},
        "firebase_config": {},
        "firebase_configured": False,
    })


@app.get("/api/profile/me")
def profile_me():
    return jsonify({"status": "success", "account": ACCOUNT})


@app.post("/api/profile/update")
def profile_update():
    data = request.get_json(silent=True) or {}
    if not (data.get("display_name") or "").strip():
        return jsonify({"status": "error", "message": "A display name is required."}), 400
    ACCOUNT.update({
        "name": data["display_name"].strip(),
        "department": data.get("department") or None,
        "phone": data.get("phone") or None,
        "notification_email": data.get("notification_email") or None,
    })
    return jsonify({"status": "success", "account_name": ACCOUNT["name"]})


@app.post("/api/profile/password")
def profile_password():
    data = request.get_json(silent=True) or {}
    if len(data.get("new_password") or "") < 8:
        return jsonify({"status": "error",
                        "message": "New password must be at least 8 characters."}), 400
    ACCOUNT["password_mode"] = "local"
    return jsonify({"status": "success"})


@app.get("/api/admin/access-requests")
def access_requests():
    return jsonify({"status": "success", "pending_count": 3, "requests": []})


@app.post("/api/auth/logout")
def logout():
    return jsonify({"status": "success"})


@app.get("/static/<path:_f>")
def brand_asset(_f):
    """A plain square so the sidebar and top bar have something to draw."""
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
           '<rect width="24" height="24" rx="5" fill="#2F6BFF"/></svg>')
    return app.response_class(svg, mimetype="image/svg+xml")


if __name__ == "__main__":
    print("Mock dashboard API on http://127.0.0.1:5055 — no database, no email.")
    app.run(host="127.0.0.1", port=5055, debug=False)
