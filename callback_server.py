"""Flask callback server for handling email button clicks"""

import os
import sys

# Windows consoles often use cp1252; emoji in print() would raise UnicodeEncodeError.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError, TypeError):
        pass

# Configure logging before the project imports, so import-time messages are
# captured to file as well as the console.
from log_setup import setup_logging
logger = setup_logging("callback")

from flask import Flask, request, render_template_string, jsonify, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from markupsafe import escape
import logging
from datetime import datetime
from typing import Dict

import config
from config import CALLBACK_BIND_HOST, CALLBACK_SERVER_PORT
# Kept for any external caller that still imports the old name.
CALLBACK_SERVER_HOST = CALLBACK_BIND_HOST
from database import db
from link_tokens import make_token, verify_token, internal_headers


# Configure Flask app
app = Flask(__name__)
# Sign sessions/tokens with the same random, on-disk secret the rest of the
# project uses (link_tokens manages the .flask_secret_key file) instead of a
# hardcoded, source-visible key.
from link_tokens import _secret as _shared_secret
app.config['SECRET_KEY'] = _shared_secret()

# See the equivalent block in web_dashboard.py. Needed here too so that the
# approve/reject audit trail records the manager's real IP rather than nginx's.
if config.TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=config.TRUSTED_PROXY_HOPS,
        x_proto=config.TRUSTED_PROXY_HOPS,
        x_host=config.TRUSTED_PROXY_HOPS,
        x_prefix=config.TRUSTED_PROXY_HOPS,
    )


# ── Email-link authorization ────────────────────────────────────────────────
# Every action link carries an HMAC token bound to (action, article_id). A
# request whose token is missing/forged/expired is refused before any state
# change — this is what stops sequential-id guessing and cross-site drive-by
# hits on these endpoints.
_UNAUTHORIZED_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Link expired or invalid</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#eef2f7;
color:#1f2937;text-align:center;padding:60px 20px}.box{max-width:520px;margin:0 auto;background:#fff;
border-radius:14px;padding:38px;box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3rem;margin:0 0 12px}
p{color:#4b5563;line-height:1.6}</style></head>
<body><div class="box"><h1>This link can no longer be used</h1>
<p>The approval link is missing its security token, has been altered, or has expired.
Please open the most recent notification email and use the link there, or contact the
platform administrator.</p></div></body></html>"""


def _link_token():
    """Pull the action token from the query string or a posted form field."""
    return request.args.get('token') or request.form.get('token') or ''


def _authorized(action: str, article_id) -> bool:
    return verify_token(_link_token(), action, article_id)


# HTML templates for response pages
SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Action Processed - Threat Intelligence</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #eef2f7;
            color: #1f2937;
            margin: 0;
            padding: 40px 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            -webkit-font-smoothing: antialiased;
        }
        .card {
            width: 100%;
            max-width: 600px;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(15, 23, 42, 0.08);
            overflow: hidden;
            border: 1px solid #e5e9f0;
        }
        .card-header {
            background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
            padding: 36px 40px 32px;
            text-align: center;
            color: #ffffff;
        }
        /* Failure variant: this template is rendered for unsuccessful actions
           too (article missing, backend error), so it must not look like a
           confirmation in those cases. */
        .card-header.failed {
            background: linear-gradient(135deg, #991b1b 0%, #dc2626 100%);
        }
        .check-badge {
            width: 64px;
            height: 64px;
            margin: 0 auto 18px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.15);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .check-badge svg { width: 34px; height: 34px; stroke: #ffffff; }
        .card-header h1 {
            margin: 0;
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: -0.01em;
        }
        .card-header p {
            margin: 8px 0 0;
            font-size: 0.9rem;
            color: rgba(255, 255, 255, 0.78);
        }
        .card-body { padding: 30px 40px 34px; text-align: center; }
        .lead {
            margin: 0 0 24px;
            font-size: 0.98rem;
            color: #374151;
            line-height: 1.55;
        }
        .section-label {
            text-transform: uppercase;
            font-size: 0.72rem;
            letter-spacing: 0.08em;
            font-weight: 600;
            color: #6b7280;
            margin: 0 0 12px;
            text-align: left;
        }
        .article-info {
            background: #f8fafc;
            border: 1px solid #e5e9f0;
            border-radius: 12px;
            padding: 18px 22px;
            margin-bottom: 24px;
            text-align: left;
        }
        .info-row {
            display: flex;
            padding: 8px 0;
            font-size: 0.92rem;
            line-height: 1.5;
            border-bottom: 1px solid #eef2f7;
        }
        .info-row:last-child { border-bottom: none; }
        .info-row .label {
            flex: 0 0 80px;
            color: #6b7280;
            font-weight: 500;
        }
        .info-row .value { color: #1f2937; font-weight: 500; }
        .status-banner {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px 18px;
            border-radius: 12px;
            margin-bottom: 24px;
            font-weight: 600;
            font-size: 0.95rem;
            text-align: left;
        }
        .status-banner svg { width: 20px; height: 20px; flex-shrink: 0; }
        .status-banner.approved {
            background: #ecfdf5;
            border: 1px solid #a7f3d0;
            color: #047857;
        }
        .status-banner.approved svg { stroke: #059669; }
        .status-banner.pending {
            background: #fffbeb;
            border: 1px solid #fde68a;
            color: #b45309;
        }
        .status-banner.pending svg { stroke: #d97706; }
        .status-banner.failed {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #b91c1c;
        }
        .status-banner.failed svg { stroke: #dc2626; }
        .btn {
            display: inline-block;
            padding: 12px 32px;
            background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
            color: #ffffff;
            text-decoration: none;
            border-radius: 10px;
            margin-top: 4px;
            font-weight: 600;
            font-size: 0.92rem;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(37, 99, 235, 0.25);
        }
        .card-footer {
            border-top: 1px solid #eef2f7;
            padding: 16px 40px;
            text-align: center;
            font-size: 0.78rem;
            color: #9ca3af;
            background: #fafbfc;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="card-header{% if not success %} failed{% endif %}">
            <div class="check-badge">
                {% if success %}
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
                {% else %}
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>
                {% endif %}
            </div>
            <h1>{% if success %}Action Processed Successfully!{% else %}Action Could Not Be Completed{% endif %}</h1>
            <p>Threat Intelligence Callback System</p>
        </div>

        <div class="card-body">
            {% if success %}
            <p class="lead">The article has been <strong>{% if action == 'rejected' %}rejected{% else %}approved{% endif %}</strong> and our system has been updated.</p>
            {% else %}
            <div class="status-banner failed">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                <span>{{ error_message or "The action could not be completed." }}</span>
            </div>
            <p class="lead">Nothing has been recorded, so this article has <strong>not</strong> moved forward in the workflow. Please retry from the most recent notification email, or contact the platform administrator.</p>
            {% endif %}

            {% if article_title %}
                <p class="section-label">Article Details</p>
                <div class="article-info">
                    <div class="info-row">
                        <span class="label">Title</span>
                        <span class="value">{{ article_title }}</span>
                    </div>
                    {% if article_source %}
                    <div class="info-row">
                        <span class="label">Source</span>
                        <span class="value">{{ article_source }}</span>
                    </div>
                    {% endif %}
                </div>
            {% endif %}

            {% if success and action == 'approved' %}
                <div class="status-banner approved">
                    <svg viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                    <span>{{ delivery_schedule or "This article will be formatted and sent to the SOC team within the next hour." }}</span>
                </div>
            {% elif success and action == 'already_approved' %}
                <div class="status-banner pending">
                    <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
                    <span>{{ special_message }}</span>
                </div>
            {% endif %}

            <a href="#" onclick="window.close()" class="btn">Close Window</a>
        </div>

        <div class="card-footer">
            Processed at: {{ timestamp }}
        </div>
    </div>

    {% if success %}
    <script>
        // Auto-close window after 10 seconds. Only on success — an error page
        // that closes itself leaves the user with no idea what went wrong.
        setTimeout(function() {
            window.close();
        }, 10000);
    </script>
    {% endif %}
</body>
</html>
"""


@app.route('/')
def index():
    """Home page for callback server"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Threat Intelligence Callback Server</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            h1 { color: #2c3e50; }
            .status { 
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Threat Intelligence Callback Server</h1>
            <div class="status">
                ✅ Server is running and ready to process approval/rejection requests.
            </div>
            <p><strong>Server Status:</strong> Active</p>
            <p><strong>Server Time:</strong> {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }}</p>
            <p><strong>Purpose:</strong> This server handles email button callbacks for the threat intelligence approval system.</p>
        </div>
    </body>
    </html>
    """, datetime=datetime)


@app.route('/approve/<int:article_id>')
def approve_article(article_id: int):
    """Handle article approval with proper validation workflow"""
    if not _authorized('approve', article_id):
        logger.warning(f"Unauthorized /approve/{article_id}: bad or missing token")
        return _UNAUTHORIZED_PAGE, 403
    try:
        logger.info(f"🎯 Processing approval for article {article_id}")
        
        # Get article details from database
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT title, source, status FROM news_articles WHERE id = ?', (article_id,))
        article_data = cursor.fetchone()
        
        if not article_data:
            logger.error(f"❌ Article {article_id} not found")
            conn.close()
            # Report the failure rather than claiming success: no decision was
            # recorded and no validation email was sent, so a success page would
            # leave the manager believing the article is in the workflow when it
            # is not. Usual cause is a link from a batch an admin refresh cleared.
            return render_template_string(SUCCESS_TEMPLATE,
                success=False,
                error_message=(
                    f"Article {article_id} no longer exists in the database, so this "
                    "approval could not be recorded. The link is from an earlier batch "
                    "that has since been cleared — please use the most recent "
                    "notification email."
                ),
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ), 404
        
        article_title, article_source, article_status = article_data
        
        # Remove numbering prefix for display (01., 02., etc.)
        display_title = article_title
        if article_title and len(article_title) > 4 and article_title[2:4] == '. ':
            display_title = article_title[4:]  # Remove "01. " prefix
        
        # Check if already approved
        cursor.execute('SELECT COUNT(*) FROM manager_approvals WHERE article_id = ? AND decision = "approved"', (article_id,))
        already_approved = cursor.fetchone()[0] > 0
        
        if not already_approved:
            # Record the approval. record_manager_decision sets
            # status='manager_approved' which is the correct intermediate state
            # until sender validation completes. Do NOT override it here.
            db.record_manager_decision(
                article_id=article_id,
                decision='approved',
                manager_email=config.MANAGER_EMAIL,
                comments='Approved via email callback'
            )
            conn.commit()

            # The validation workflow (AI report formatting + SMTP send) can
            # take a minute — run it in the background so the manager's
            # browser gets the confirmation page immediately.
            def _run_validation_workflow(aid: int):
                try:
                    from scheduler import threat_scheduler
                    threat_scheduler.handle_manager_approval(aid, 'approved')
                    logger.info(f"✅ Background validation workflow completed for article {aid}")
                except Exception as e:
                    logger.error(f"❌ Error in background validation workflow for article {aid}: {e}")
                # Notify dashboard of the approval (optional)
                try:
                    import requests
                    requests.post(
                        f'{config.INTERNAL_DASHBOARD_URL}/api/notify_approval',
                        json={
                            'article_id': aid,
                            'status': 'approved',
                            'message': f'Article {aid} approved by manager'
                        },
                        headers=internal_headers(),
                        timeout=2,
                    )
                except Exception as e:
                    # Optional UI push — never fail the approval over it, but do
                    # leave a trace instead of a bare `except: pass`.
                    logger.debug(f"Dashboard approval push failed for {aid}: {e}")

            import threading
            threading.Thread(
                target=_run_validation_workflow,
                args=(article_id,),
                name=f'approval-workflow-{article_id}',
                daemon=True,
            ).start()
            delivery_message = "✅ Article approved! The formatted report is being sent to the sender for validation."

            # Log the action
            db.log_system_event(
                'INFO',
                f'Article {article_id} approved by manager via email callback',
                'MANAGER_APPROVAL'
            )
        else:
            delivery_message = "✅ Article was already approved and is in the validation workflow."

        conn.close()

        logger.info(f"✅ Article {article_id} approval processed successfully")
        
        return render_template_string(SUCCESS_TEMPLATE,
            success=True,
            action='approved',
            article_title=display_title,
            article_source=article_source,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            delivery_schedule=delivery_message
        )
    
    except Exception as e:
        logger.error(f"Error processing approval for article {article_id}: {str(e)}")
        db.log_system_event('ERROR', f'Error approving article {article_id}: {str(e)}', 'CALLBACK_SERVER')

        # Surface the failure instead of forcing a success page. The approval may
        # not have been recorded and the sender-validation email may never have
        # gone out, so the manager has to know to retry.
        return render_template_string(SUCCESS_TEMPLATE,
            success=False,
            error_message=f"An error occurred while processing the approval: {str(e)}",
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ), 500


@app.route('/reject/<int:article_id>')
def reject_article(article_id: int):
    """Handle article rejection"""
    if not _authorized('reject', article_id):
        logger.warning(f"Unauthorized /reject/{article_id}: bad or missing token")
        return _UNAUTHORIZED_PAGE, 403
    try:
        # Get article details from database
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT title, source FROM news_articles WHERE id = ?', (article_id,))
        article_data = cursor.fetchone()
        
        if not article_data:
            conn.close()
            return render_template_string(SUCCESS_TEMPLATE,
                success=False,
                error_message="Article not found in database.",
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
        
        article_title, article_source = article_data
        
        # Record the rejection
        db.record_manager_decision(
            article_id=article_id,
            decision='rejected',
            manager_email=config.MANAGER_EMAIL,
            comments='Rejected via email callback'
        )
        
        conn.close()
        
        # Log the action
        db.log_system_event(
            'INFO',
            f'Article {article_id} rejected by manager via email callback',
            'CALLBACK_SERVER'
        )
        
        logger.info(f"Article {article_id} rejected: {article_title}")
        
        return render_template_string(SUCCESS_TEMPLATE,
            success=True,
            action='rejected',
            article_title=article_title,
            article_source=article_source,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
    
    except Exception as e:
        logger.error(f"Error rejecting article {article_id}: {str(e)}")
        db.log_system_event('ERROR', f'Error rejecting article {article_id}: {str(e)}', 'CALLBACK_SERVER')
        
        return render_template_string(SUCCESS_TEMPLATE,
            success=False,
            error_message=f"An error occurred while processing the rejection: {str(e)}",
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )


@app.route('/status')
def server_status():
    """Return server status as JSON"""
    try:
        stats = db.get_statistics()
        return jsonify({
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'database_stats': stats
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'threat-intelligence-callback-server',
        'timestamp': datetime.now().isoformat()
    })


# Instant "Processing your request" page shown the moment the sender clicks
# Approve. The real (slower) approval + scheduling work is then performed via a
# background fetch to /validate_approve_process, and its result page is swapped
# in when ready — so the sender gets immediate feedback instead of a hanging tab.
# __ARTICLE_ID__ is substituted per-request.
_APPROVE_PROCESSING_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Processing your request…</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #eef2f7; color: #1f2937; margin: 0; padding: 40px 20px;
            min-height: 100vh; display: flex; align-items: flex-start; justify-content: center;
            -webkit-font-smoothing: antialiased;
        }
        .card {
            width: 100%; max-width: 520px; background: #ffffff; border-radius: 16px;
            box-shadow: 0 10px 40px rgba(15, 23, 42, 0.08); overflow: hidden; border: 1px solid #e5e9f0;
        }
        .card-header {
            background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
            padding: 44px 40px 40px; text-align: center; color: #ffffff;
        }
        .spinner {
            width: 58px; height: 58px; margin: 0 auto 20px; border-radius: 50%;
            border: 5px solid rgba(255, 255, 255, 0.25); border-top-color: #ffffff;
            animation: spin 0.9s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .card-header h1 { margin: 0; font-size: 1.4rem; font-weight: 600; letter-spacing: -0.01em; }
        .card-header p { margin: 10px 0 0; font-size: 0.92rem; color: rgba(255, 255, 255, 0.82); }
        .dots::after { content: ''; animation: dots 1.4s steps(4, end) infinite; }
        @keyframes dots { 0% { content: ''; } 25% { content: '.'; } 50% { content: '..'; } 75% { content: '...'; } }
        .card-body { padding: 28px 40px 34px; text-align: center; }
        .card-body p { margin: 0; font-size: 0.95rem; line-height: 1.6; color: #4b5563; }
        .hint { margin-top: 16px !important; font-size: 0.82rem !important; color: #9ca3af !important; }
        .retry {
            display: none; margin-top: 22px; padding: 11px 26px; background: #2563eb; color: #fff;
            text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 0.9rem;
        }
        .noscript-box { margin-top: 20px; }
        .noscript-box button {
            padding: 11px 26px; background: #2563eb; color: #fff; border: none; border-radius: 10px;
            font-weight: 600; font-size: 0.9rem; cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="card-header">
            <div class="spinner" id="spinner"></div>
            <h1 id="title">Processing your request<span class="dots"></span></h1>
            <p>Threat Intelligence Validation System</p>
        </div>
        <div class="card-body">
            <p id="msg">Approving the report and scheduling it for delivery to the SOC team.</p>
            <p class="hint">This only takes a moment — please don't close this window.</p>
            <a href="/validate_approve/__ARTICLE_ID__?token=__TOKEN__" class="retry" id="retry">Try again</a>
            <noscript>
                <div class="noscript-box">
                    <p>JavaScript is disabled. Click below to complete the approval.</p>
                    <form method="POST" action="/validate_approve_process/__ARTICLE_ID__">
                        <input type="hidden" name="token" value="__TOKEN__">
                        <button type="submit">Continue to approve</button>
                    </form>
                </div>
            </noscript>
        </div>
    </div>
    <script>
    (function () {
        var started = Date.now();
        var MIN_MS = 700; // keep the spinner visible briefly, even when fast
        function swap(html) {
            var wait = Math.max(0, MIN_MS - (Date.now() - started));
            setTimeout(function () {
                document.open(); document.write(html); document.close();
            }, wait);
        }
        function fail() {
            var sp = document.getElementById('spinner'); if (sp) sp.style.display = 'none';
            document.getElementById('title').textContent = 'Could not complete the request';
            document.getElementById('msg').textContent = 'A network issue occurred while processing your approval.';
            document.getElementById('retry').style.display = 'inline-block';
        }
        fetch('/validate_approve_process/__ARTICLE_ID__?token=__TOKEN__', { method: 'POST', headers: { 'X-Requested-With': 'fetch' } })
            .then(function (r) { return r.text(); })
            .then(function (html) { swap(html); })
            .catch(fail);
    })();
    </script>
</body>
</html>"""


@app.route('/validate_approve/<int:article_id>')
def validate_approve(article_id):
    """Email-clicked approval link → returns the instant 'Processing…' page.

    The actual approval + SOC scheduling runs in /validate_approve_process,
    driven by JS from the processing page, so the sender sees immediate feedback
    (and email link-prefetchers cannot silently trigger an approval)."""
    if not _authorized('validate_approve', article_id):
        logger.warning(f"Unauthorized /validate_approve/{article_id}: bad or missing token")
        return _UNAUTHORIZED_PAGE, 403
    return (_APPROVE_PROCESSING_PAGE
            .replace('__ARTICLE_ID__', str(article_id))
            .replace('__TOKEN__', str(escape(_link_token()))))


@app.route('/validate_approve_process/<int:article_id>', methods=['GET', 'POST'])
def validate_approve_process(article_id):
    """Perform the sender approval + SOC scheduling and return the result page."""
    if not _authorized('validate_approve', article_id):
        logger.warning(f"Unauthorized /validate_approve_process/{article_id}: bad or missing token")
        return _UNAUTHORIZED_PAGE, 403
    try:
        from sender_validation import sender_validator
        
        # Get article details
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT title, source FROM news_articles WHERE id = ?
        ''', (article_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Article Not Found</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ Article Not Found</h1>
                    <p>The requested article could not be found.</p>
                </div>
            </body>
            </html>
            """), 404
        
        article_title, article_source = result
        
        # Handle validation approval
        success = sender_validator.handle_validation_approval(article_id)
        
        if success:
            # Log the validation
            db.log_system_event(
                'INFO',
                f'Article {article_id} validated and approved by sender',
                'SENDER_VALIDATION'
            )
            
            logger.info(f"Article {article_id} validated and approved by sender")
            
            success_message = "SOC report approved and scheduled for delivery!"
        else:
            success_message = "There was an error processing your approval."
        
        return (f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Validation Complete - Threat Intelligence</title>
            <style>
                * {{ box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                    background: #eef2f7;
                    color: #1f2937;
                    margin: 0;
                    padding: 40px 20px;
                    min-height: 100vh;
                    display: flex;
                    align-items: flex-start;
                    justify-content: center;
                    -webkit-font-smoothing: antialiased;
                }}
                .card {{
                    width: 100%;
                    max-width: 600px;
                    background: #ffffff;
                    border-radius: 16px;
                    box-shadow: 0 10px 40px rgba(15, 23, 42, 0.08);
                    overflow: hidden;
                    border: 1px solid #e5e9f0;
                }}
                .card-header {{
                    background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
                    padding: 36px 40px 32px;
                    text-align: center;
                    color: #ffffff;
                }}
                .check-badge {{
                    width: 64px;
                    height: 64px;
                    margin: 0 auto 18px;
                    border-radius: 50%;
                    background: rgba(255, 255, 255, 0.15);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .check-badge svg {{ width: 34px; height: 34px; stroke: #ffffff; }}
                .card-header h1 {{
                    margin: 0;
                    font-size: 1.5rem;
                    font-weight: 600;
                    letter-spacing: -0.01em;
                }}
                .card-header p {{
                    margin: 8px 0 0;
                    font-size: 0.9rem;
                    color: rgba(255, 255, 255, 0.78);
                }}
                .card-body {{ padding: 32px 40px 36px; }}
                .section-label {{
                    text-transform: uppercase;
                    font-size: 0.72rem;
                    letter-spacing: 0.08em;
                    font-weight: 600;
                    color: #6b7280;
                    margin: 0 0 12px;
                }}
                .article-info {{
                    background: #f8fafc;
                    border: 1px solid #e5e9f0;
                    border-radius: 12px;
                    padding: 20px 22px;
                    margin-bottom: 24px;
                }}
                .info-row {{
                    display: flex;
                    padding: 8px 0;
                    font-size: 0.92rem;
                    line-height: 1.5;
                    border-bottom: 1px solid #eef2f7;
                }}
                .info-row:last-child {{ border-bottom: none; }}
                .info-row .label {{
                    flex: 0 0 130px;
                    color: #6b7280;
                    font-weight: 500;
                }}
                .info-row .value {{ color: #1f2937; font-weight: 500; }}
                .status-banner {{
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    background: #ecfdf5;
                    border: 1px solid #a7f3d0;
                    color: #047857;
                    padding: 16px 18px;
                    border-radius: 12px;
                    margin-bottom: 28px;
                    font-weight: 600;
                    font-size: 0.95rem;
                }}
                .status-banner svg {{ width: 20px; height: 20px; stroke: #059669; flex-shrink: 0; }}
                .timeline {{ margin-bottom: 8px; }}
                .timeline-item {{
                    display: flex;
                    align-items: flex-start;
                    gap: 14px;
                    padding: 10px 0;
                }}
                .timeline-icon {{
                    flex-shrink: 0;
                    width: 30px;
                    height: 30px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .timeline-icon svg {{ width: 16px; height: 16px; }}
                .timeline-icon.completed {{ background: #d1fae5; }}
                .timeline-icon.completed svg {{ stroke: #059669; }}
                .timeline-icon.pending {{ background: #e0e7ff; }}
                .timeline-icon.pending svg {{ stroke: #4f46e5; }}
                .timeline-text {{
                    font-size: 0.92rem;
                    color: #374151;
                    line-height: 1.5;
                    padding-top: 5px;
                }}
                .card-footer {{
                    border-top: 1px solid #eef2f7;
                    padding: 18px 40px;
                    text-align: center;
                    font-size: 0.78rem;
                    color: #9ca3af;
                    background: #fafbfc;
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="card-header">
                    <div class="check-badge">
                        <svg viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
                    </div>
                    <h1>SOC Report Validation Complete</h1>
                    <p>Threat Intelligence Validation System</p>
                </div>

                <div class="card-body">
                    <p class="section-label">Validated Article</p>
                    <div class="article-info">
                        <div class="info-row">
                            <span class="label">Title</span>
                            <span class="value">{escape(article_title[:80])}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Source</span>
                            <span class="value">{escape(article_source)}</span>
                        </div>
                        <div class="info-row">
                            <span class="label">Validation Time</span>
                            <span class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                        </div>
                    </div>

                    <div class="status-banner">
                        <svg viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                        <span>{success_message}</span>
                    </div>

                    <p class="section-label">What Happens Next</p>
                    <div class="timeline">
                        <div class="timeline-item">
                            <div class="timeline-icon completed">
                                <svg viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
                            </div>
                            <div class="timeline-text">SOC report validated by sender</div>
                        </div>
                        <div class="timeline-item">
                            <div class="timeline-icon completed">
                                <svg viewBox="0 0 24 24" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
                            </div>
                            <div class="timeline-text">Article scheduled for SOC delivery</div>
                        </div>
                        <div class="timeline-item">
                            <div class="timeline-icon pending">
                                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
                            </div>
                            <div class="timeline-text">Report will be delivered on Tuesday at 11:00 AM</div>
                        </div>
                        <div class="timeline-item">
                            <div class="timeline-icon pending">
                                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>
                            </div>
                            <div class="timeline-text">SOC team will receive the formatted threat intelligence report</div>
                        </div>
                    </div>
                </div>

                <div class="card-footer">
                    Threat Intelligence Validation System &middot; {datetime.now().strftime('%B %d, %Y')}
                </div>
            </div>
        </body>
        </html>
        """)
        
    except Exception as e:
        logger.error(f"Error in validate_approve for article {article_id}: {str(e)}")
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Validation Error</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ Validation Error</h1>
                <p>There was an error processing your validation. Please try again.</p>
            </div>
        </body>
        </html>
        """), 500


@app.route('/validate_reject_form/<int:article_id>')
def validate_reject_form(article_id):
    """Show form for sender to provide rejection remarks"""
    if not _authorized('validate_reject', article_id):
        logger.warning(f"Unauthorized /validate_reject_form/{article_id}: bad or missing token")
        return _UNAUTHORIZED_PAGE, 403
    try:
        # Get article details
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT title, source FROM news_articles WHERE id = ?
        ''', (article_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Article Not Found</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ Article Not Found</h1>
                    <p>The requested article could not be found.</p>
                </div>
            </body>
            </html>
            """), 404
        
        article_title, article_source = result
        
        return (f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rejection Feedback Form - Threat Intelligence</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #faf8f5 0%, #ffffff 100%);
                    margin: 0;
                    padding: 50px;
                    min-height: 100vh;
                }}
                .container {{
                    max-width: 700px;
                    margin: 0 auto;
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 8px 32px rgba(139,115,85,0.15);
                    border: 2px solid #d4c4a8;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .reject-icon {{
                    font-size: 4rem;
                    color: #dc3545;
                    margin-bottom: 20px;
                }}
                h1 {{ color: #8b7355; margin-bottom: 30px; }}
                .article-info {{
                    background: #f7f5f0;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border-left: 4px solid #d4c4a8;
                }}
                .form-group {{
                    margin: 20px 0;
                }}
                label {{
                    display: block;
                    font-weight: 600;
                    color: #5d4e37;
                    margin-bottom: 8px;
                }}
                textarea {{
                    width: 100%;
                    min-height: 120px;
                    padding: 15px;
                    border: 2px solid #e6dcc6;
                    border-radius: 8px;
                    font-family: inherit;
                    font-size: 14px;
                    line-height: 1.5;
                    resize: vertical;
                    box-sizing: border-box;
                }}
                textarea:focus {{
                    outline: none;
                    border-color: #8b7355;
                    box-shadow: 0 0 0 3px rgba(139,115,85,0.1);
                }}
                .button-group {{
                    text-align: center;
                    margin-top: 30px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 15px 30px;
                    margin: 0 10px;
                    border: none;
                    border-radius: 25px;
                    text-decoration: none;
                    font-weight: 600;
                    font-size: 16px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                .btn-reject {{
                    background: linear-gradient(135deg, #dc3545, #c82333);
                    color: white;
                }}
                .btn-reject:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(220, 53, 69, 0.3);
                    color: white;
                    text-decoration: none;
                }}
                .btn-cancel {{
                    background: linear-gradient(135deg, #6c757d, #5a6268);
                    color: white;
                }}
                .btn-cancel:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(108, 117, 125, 0.3);
                    color: white;
                    text-decoration: none;
                }}
                .help-text {{
                    font-size: 13px;
                    color: #6b5b47;
                    margin-top: 5px;
                    line-height: 1.4;
                }}
                .warning-box {{
                    background: #fcf8e8;
                    border: 1px solid #f2e6a9;
                    color: #8b7355;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 8px;
                    border-left: 4px solid #d4c4a8;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="reject-icon">❌</div>
                    <h1>Report Rejection Feedback</h1>
                </div>
                
                <div class="article-info">
                    <h3>📄 Article Information</h3>
                    <p><strong>Title:</strong> {escape(article_title)}</p>
                    <p><strong>Source:</strong> {escape(article_source)}</p>
                </div>
                
                <div class="warning-box">
                    <strong>⚠️ Important:</strong> Please provide specific feedback about why you're rejecting this report. 
                    Your comments will help improve the re-formatting process and ensure the next version meets requirements.
                </div>
                
                <form method="POST" action="/validate_reject_with_remarks/{article_id}">
                    <input type="hidden" name="token" value="{escape(_link_token())}">
                    <div class="form-group">
                        <label for="remarks">Why are you rejecting this report? *</label>
                        <textarea 
                            id="remarks" 
                            name="remarks" 
                            placeholder="Please provide specific feedback about the report format, content, or any issues you noticed. For example:&#10;&#10;• The summary is too technical for SOC team&#10;• Missing key threat indicators&#10;• Format doesn't match required SOC template&#10;• Content needs more actionable insights&#10;• Language should be more concise"
                            required
                        ></textarea>
                        <div class="help-text">
                            Be as specific as possible. This feedback will be used to improve the re-formatted report.
                        </div>
                    </div>
                    
                    <div class="button-group">
                        <button type="submit" class="btn btn-reject">
                            🔄 Submit Rejection & Re-format
                        </button>
                        <a href="javascript:history.back()" class="btn btn-cancel">
                            ↩️ Cancel
                        </a>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """)
        
    except Exception as e:
        logger.error(f"Error showing rejection form for article {article_id}: {str(e)}")
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Form Error</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ Form Error</h1>
                <p>There was an error loading the rejection form. Please try again.</p>
            </div>
        </body>
        </html>
        """), 500


@app.route('/validate_reject_with_remarks/<int:article_id>', methods=['POST'])
def validate_reject_with_remarks(article_id):
    """Handle sender rejection with remarks"""
    if not _authorized('validate_reject', article_id):
        logger.warning(f"Unauthorized /validate_reject_with_remarks/{article_id}: bad or missing token")
        return _UNAUTHORIZED_PAGE, 403
    try:
        remarks = request.form.get('remarks', '').strip()
        
        if not remarks:
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Missing Remarks</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                    .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ Missing Remarks</h1>
                    <p>Please provide feedback about why you're rejecting this report.</p>
                    <button onclick="history.back()">Go Back</button>
                </div>
            </body>
            </html>
            """), 400
        
        from sender_validation import sender_validator
        
        # Get article details
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT title, source FROM news_articles WHERE id = ?
        ''', (article_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Article Not Found</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ Article Not Found</h1>
                    <p>The requested article could not be found.</p>
                </div>
            </body>
            </html>
            """), 404
        
        article_title, article_source = result
        
        # Handle validation rejection with remarks
        success = sender_validator.handle_validation_rejection(article_id, remarks)
        
        if success:
            # Log the rejection with remarks
            db.log_system_event(
                'INFO',
                f'Article {article_id} rejected by sender with remarks: "{remarks[:100]}..." - re-formatting initiated',
                'SENDER_VALIDATION'
            )
            
            logger.info(f"Article {article_id} rejected by sender with remarks, re-formatting initiated")
            
            status_message = "Report rejected with feedback. Re-formatting initiated based on your comments."
            status_class = "success"
        else:
            status_message = "There was an error processing your rejection with remarks."
            status_class = "error"
        
        return (f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rejection Submitted - Threat Intelligence</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #faf8f5 0%, #ffffff 100%);
                    margin: 0;
                    padding: 50px;
                    min-height: 100vh;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 8px 32px rgba(139,115,85,0.15);
                    text-align: center;
                    border: 2px solid #d4c4a8;
                }}
                .feedback-icon {{
                    font-size: 4rem;
                    color: #dc3545;
                    margin-bottom: 20px;
                }}
                h1 {{ color: #8b7355; margin-bottom: 30px; }}
                .article-info {{
                    background: #f7f5f0;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border-left: 4px solid #d4c4a8;
                }}
                .status-message.success {{
                    background: #d4edda;
                    color: #155724;
                    border: 1px solid #c3e6cb;
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    font-weight: 600;
                }}
                .status-message.error {{
                    background: #f8d7da;
                    color: #721c24;
                    border: 1px solid #f5c6cb;
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    font-weight: 600;
                }}
                .remarks-preview {{
                    background: #fcf8e8;
                    border: 1px solid #f2e6a9;
                    color: #8b7355;
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    text-align: left;
                }}
                .next-steps {{
                    background: #f7f5f0;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    text-align: left;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="feedback-icon">📝</div>
                <h1>Rejection Feedback Submitted</h1>
                
                <div class="article-info">
                    <h3>📄 Article Information</h3>
                    <p><strong>Title:</strong> {escape(article_title)}</p>
                    <p><strong>Source:</strong> {escape(article_source)}</p>
                </div>
                
                <div class="status-message {status_class}">
                    {status_message}
                </div>
                
                <div class="remarks-preview">
                    <h4>📋 Your Feedback:</h4>
                    <p><em>"{escape(remarks)}"</em></p>
                </div>
                
                <div class="next-steps">
                    <h4>🔄 What Happens Next</h4>
                    <ul>
                        <li>The system will use your feedback to improve the report formatting</li>
                        <li>A new validation email with the improved report will be sent shortly</li>
                        <li>The re-formatted report will address the issues you mentioned</li>
                        <li>Please check your inbox within the next few minutes</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """)
        
    except Exception as e:
        logger.error(f"Error processing rejection with remarks for article {article_id}: {str(e)}")
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Processing Error</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ Processing Error</h1>
                <p>There was an error processing your rejection with remarks. Please try again.</p>
            </div>
        </body>
        </html>
        """), 500


@app.route('/validate_reject/<int:article_id>')
def validate_reject(article_id):
    """Legacy endpoint - redirect to remarks form, carrying the action token."""
    from flask import redirect
    from urllib.parse import quote
    return redirect(
        f'/validate_reject_form/{article_id}?token={quote(_link_token(), safe="")}',
        code=302,
    )


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Page Not Found - Threat Intelligence</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 50px;
                background-color: #f5f5f5;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                display: inline-block;
            }
            h1 { color: #dc3545; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>404 - Page Not Found</h1>
            <p>The requested page was not found on this server.</p>
            <p><a href="/">Return to Home</a></p>
        </div>
    </body>
    </html>
    """), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Server Error - Threat Intelligence</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 50px;
                background-color: #f5f5f5;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                display: inline-block;
            }
            h1 { color: #dc3545; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>500 - Internal Server Error</h1>
            <p>An internal server error occurred. Please try again later.</p>
            <p><a href="/">Return to Home</a></p>
        </div>
    </body>
    </html>
    """), 500


def run_callback_server(debug=False):
    """Run the callback server"""
    try:
        logger.info(f"Starting callback server on {CALLBACK_BIND_HOST}:{CALLBACK_SERVER_PORT}")
        app.run(
            host=CALLBACK_BIND_HOST,
            port=CALLBACK_SERVER_PORT,
            debug=debug,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start callback server: {str(e)}")
        raise


# Reported at import time so the warnings appear under gunicorn too, not only
# when this file is run directly.
for _p in config.validate_deployment():
    logger.error(f"CONFIG: {_p}")


if __name__ == "__main__":
    # This used to be hardcoded debug=True. Werkzeug's debugger turns any
    # unhandled exception into an interactive Python console in the browser, so
    # on a network-reachable port it is remote code execution. Off unless
    # TI_CALLBACK_DEBUG is explicitly set, and never on in production.
    _debug = (
        os.environ.get("TI_CALLBACK_DEBUG", "0").strip().lower() in ("1", "true", "yes", "on")
        and not config.IS_PRODUCTION
    )
    if _debug:
        logger.warning(
            "⚠️  Werkzeug debugger ENABLED — anyone who can reach this port can "
            "run code on this machine. Never use this on a shared host."
        )

    logger.info("🚀 Starting Threat Intelligence Callback Server...")
    logger.info(f"📍 Listening on {CALLBACK_BIND_HOST}:{CALLBACK_SERVER_PORT}")
    logger.info(f"🔗 Email buttons will point at: {config.CALLBACK_BASE_URL}/approve/[ID] and /reject/[ID]")
    logger.info("💡 This server handles email button clicks for manager approvals.")

    run_callback_server(debug=_debug)
