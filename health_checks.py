#!/usr/bin/env python3
"""Health / preflight checks for the Threat Intelligence System.

Why this exists: the scraper once failed for days while every session was
logged as 'completed' with 0 articles — the RSS feed 302-redirected to
feeds.feedburner.com, which the corporate network blocks. These checks make
that whole class of failure loud and visible BEFORE (and while) the app runs.

Usage:
    python health_checks.py               # full check (includes network), human output
    python health_checks.py --fast        # skip network checks (deps/config/db only)
    python health_checks.py --preflight   # full check + fail if app ports are busy
    python health_checks.py --json        # machine-readable output
    python health_checks.py --smtp-login  # also verify SMTP credentials (no email sent)

Exit code: 0 = all pass (warnings allowed), 1 = at least one FAIL.

Design rules:
  * NEVER sends an email. The SMTP check stops at STARTTLS (and, only with
    --smtp-login, AUTH). Nothing is ever submitted for delivery.
  * No app-module imports with side effects: uses sqlite3 directly instead of
    database.py, and never imports scheduler/web_dashboard/email_system.
  * Every check returns a result dict; nothing raises out of run_all_checks().
"""

import argparse
import importlib.util
import json
import os
import shutil
import socket
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import config  # pure configuration module — safe, no side effects

PASS, WARN, FAIL = "pass", "warn", "fail"

# Tables the app cannot function without (see database.py init).
REQUIRED_TABLES = {
    "news_articles", "manager_approvals", "scraping_sessions",
    "system_logs", "sender_validations", "soc_deliveries",
}

# import-name -> (pip name, critical?) critical=False degrades a feature but
# the app still boots and scrapes.
DEPENDENCIES = {
    "requests":        ("requests", True),
    "feedparser":      ("feedparser", True),
    "bs4":             ("beautifulsoup4", True),
    "lxml":            ("lxml", True),
    "flask":           ("Flask", True),
    "flask_socketio":  ("Flask-SocketIO", True),
    "apscheduler":     ("APScheduler", True),
    "pytz":            ("pytz", True),
    "fake_useragent":  ("fake-useragent", True),
    "jwt":             ("pyjwt", True),
    "newspaper":       ("newspaper3k", False),   # scraper falls back to BeautifulSoup
    "openpyxl":        ("openpyxl", False),      # Excel export only
}

VALID_DAYS = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}


def _result(name, status, message, hint=None, started=None):
    r = {"name": name, "status": status, "message": message}
    if hint:
        r["hint"] = hint
    if started is not None:
        r["duration_ms"] = int((time.monotonic() - started) * 1000)
    return r


# ──────────────────────────────────────────────────────────────────────────
# Individual checks
# ──────────────────────────────────────────────────────────────────────────

def check_dependencies():
    t = time.monotonic()
    missing_critical, missing_optional = [], []
    for module, (pip_name, critical) in DEPENDENCIES.items():
        if importlib.util.find_spec(module) is None:
            (missing_critical if critical else missing_optional).append(pip_name)
    if missing_critical:
        return _result("dependencies", FAIL,
                       f"Missing required packages: {', '.join(missing_critical)}",
                       hint="Run: .venv/bin/pip install -r requirements.txt", started=t)
    if missing_optional:
        return _result("dependencies", WARN,
                       f"Missing optional packages: {', '.join(missing_optional)} (features degraded)",
                       hint="Run: .venv/bin/pip install -r requirements.txt", started=t)
    return _result("dependencies", PASS, f"All {len(DEPENDENCIES)} key packages installed", started=t)


def check_config():
    t = time.monotonic()
    problems, warnings = [], []

    settings_path = os.path.join(ROOT, "admin_settings.json")
    if os.path.exists(settings_path):
        try:
            with open(settings_path) as f:
                json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            problems.append(f"admin_settings.json is unreadable/corrupt: {e}")
    else:
        warnings.append("admin_settings.json missing (defaults will be used)")

    sources = getattr(config, "NEWS_SOURCES", [])
    if not sources:
        problems.append("NEWS_SOURCES is empty — nothing to scrape")
    for s in sources:
        for key in ("name", "url", "rss", "selectors"):
            if key not in s:
                problems.append(f"News source {s.get('name', '?')} missing key '{key}'")

    if not config.SENDER_EMAIL or "@" not in str(config.SENDER_EMAIL):
        problems.append("SENDER_EMAIL is not a valid address")
    if not config.SENDER_PASSWORD:
        warnings.append("SENDER_PASSWORD is empty — email delivery will fail until set in /admin")
    if not config.MANAGER_EMAIL or "@" not in str(config.MANAGER_EMAIL):
        warnings.append("MANAGER_EMAIL is not a valid address")

    if str(config.SCRAPING_DAY).lower() not in VALID_DAYS:
        problems.append(f"SCRAPING_DAY '{config.SCRAPING_DAY}' is not a weekday name")
    for day in config.SOC_DELIVERY_DAYS:
        if str(day).lower() not in VALID_DAYS:
            problems.append(f"SOC_DELIVERY_DAYS entry '{day}' is not a weekday name")
    for label, hour, minute in (("SCRAPING", config.SCRAPING_HOUR, config.SCRAPING_MINUTE),
                                ("SOC_DELIVERY", config.SOC_DELIVERY_HOUR, config.SOC_DELIVERY_MINUTE)):
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            problems.append(f"{label} time {hour}:{minute} out of range")

    if problems:
        return _result("config", FAIL, "; ".join(problems),
                       hint="Fix via the /admin panel or admin_settings.json", started=t)
    if warnings:
        return _result("config", WARN, "; ".join(warnings), started=t)
    return _result("config", PASS,
                   f"Config valid ({len(sources)} news source(s), schedule OK)", started=t)


def check_database():
    t = time.monotonic()
    db_path = os.path.join(ROOT, config.DATABASE_PATH)
    if not os.path.exists(db_path):
        return _result("database", WARN,
                       f"{config.DATABASE_PATH} does not exist yet (created on first app start)",
                       started=t)
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                return _result("database", FAIL, f"Integrity check failed: {integrity}",
                               hint="Restore from a backup of threat_intel.db", started=t)
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            missing = REQUIRED_TABLES - tables
            if missing:
                return _result("database", FAIL,
                               f"Missing tables: {', '.join(sorted(missing))}",
                               hint="Start the app once to run database migrations", started=t)
            # Verify the DB is writable without touching app data.
            conn.execute("PRAGMA user_version")  # read is fine; test write below
            conn.execute("CREATE TEMP TABLE _health_probe (x INTEGER)")
            conn.execute("DROP TABLE _health_probe")
        finally:
            conn.close()
    except sqlite3.Error as e:
        return _result("database", FAIL, f"Cannot open/query database: {e}",
                       hint="Check file permissions and that no other process holds a lock",
                       started=t)
    size_mb = os.path.getsize(db_path) / 1e6
    return _result("database", PASS,
                   f"Database OK ({len(REQUIRED_TABLES)} required tables present, {size_mb:.1f} MB)",
                   started=t)


def check_news_sources():
    """The check that would have caught the feedburner outage: fetch every
    feed end-to-end, flag off-site redirects, verify entries are fresh, and
    verify the direct-scrape fallback selector still matches the homepage."""
    t = time.monotonic()
    import requests
    import urllib3
    import feedparser
    from urllib.parse import urlparse
    from bs4 import BeautifulSoup
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    problems, warnings, details = [], [], []
    session = requests.Session()
    session.verify = False  # matches the scraper's corporate-network behavior
    session.headers.update({"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"})

    for source in getattr(config, "NEWS_SOURCES", []):
        name = source.get("name", "?")

        # 1) RSS feed reachable end-to-end (follows redirects like the scraper does)
        try:
            resp = session.get(source["rss"], timeout=15)
            resp.raise_for_status()
            final_host = urlparse(resp.url).netloc
            original_host = urlparse(source["rss"]).netloc
            if resp.history and final_host != original_host:
                warnings.append(
                    f"{name}: RSS redirects to {final_host} — if that host gets blocked "
                    f"(as feeds.feedburner.com was), scraping silently dies")
            feed = feedparser.parse(resp.content)
            if not feed.entries:
                problems.append(f"{name}: RSS returned HTTP {resp.status_code} but 0 parseable entries")
            else:
                cutoff = datetime.now(timezone.utc) - timedelta(days=7)
                recent = 0
                for e in feed.entries:
                    parsed = e.get("published_parsed") or e.get("updated_parsed")
                    if parsed and datetime(*parsed[:6], tzinfo=timezone.utc) >= cutoff:
                        recent += 1
                if recent == 0:
                    warnings.append(f"{name}: feed alive but no entries in the last 7 days "
                                    f"(scraper filters to 7 days, so it would save 0 articles)")
                else:
                    details.append(f"{name}: RSS OK ({len(feed.entries)} entries, {recent} recent)")
        except Exception as e:
            problems.append(f"{name}: RSS fetch failed — {type(e).__name__}: {e}")

        # 2) Homepage + selector (the direct-scrape fallback path)
        try:
            resp = session.get(source["url"], timeout=15)
            resp.raise_for_status()
            matches = len(BeautifulSoup(resp.content, "html.parser")
                          .select(source["selectors"]["title"]))
            if matches == 0:
                warnings.append(f"{name}: homepage loads but selector "
                                f"'{source['selectors']['title']}' matches 0 elements — "
                                f"direct-scrape fallback is broken (site layout changed?)")
            else:
                details.append(f"{name}: fallback selector matches {matches} elements")
        except Exception as e:
            warnings.append(f"{name}: homepage fetch failed (fallback path down) — "
                            f"{type(e).__name__}: {e}")

    if problems:
        return _result("news_sources", FAIL, "; ".join(problems + warnings),
                       hint="Check VPN/firewall (can this machine reach the feed host?), "
                            "then the feed URL in config.py NEWS_SOURCES", started=t)
    if warnings:
        return _result("news_sources", WARN, "; ".join(warnings), started=t)
    return _result("news_sources", PASS, "; ".join(details), started=t)


def check_smtp(try_login=False):
    """Connect + STARTTLS only. Never sends mail. AUTH only with --smtp-login."""
    t = time.monotonic()
    import smtplib
    server, port = config.SMTP_SERVER, config.SMTP_PORT
    try:
        with smtplib.SMTP(server, port, timeout=10) as smtp:
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                smtp.starttls()
                smtp.ehlo()
            if try_login:
                if not config.SENDER_PASSWORD:
                    return _result("smtp", WARN,
                                   f"Reached {server}:{port}, but SENDER_PASSWORD is empty — "
                                   f"cannot verify login", started=t)
                smtp.login(config.SENDER_EMAIL, config.SENDER_PASSWORD)
                return _result("smtp", PASS,
                               f"Connected to {server}:{port} and credentials accepted "
                               f"(no email sent)", started=t)
        return _result("smtp", PASS,
                       f"Connected to {server}:{port} with STARTTLS (credentials not tested)",
                       started=t)
    except smtplib.SMTPAuthenticationError as e:
        return _result("smtp", FAIL, f"SMTP login rejected for {config.SENDER_EMAIL}: {e.smtp_code}",
                       hint="For Gmail use an App Password (not the account password); "
                            "update it in /admin", started=t)
    except Exception as e:
        return _result("smtp", FAIL,
                       f"Cannot reach SMTP {server}:{port} — {type(e).__name__}: {e}",
                       hint="Check network/VPN; port 587 outbound may be blocked", started=t)


def check_ports(expect_free=False):
    """expect_free=True (preflight before launch): busy ports are a FAIL.
    Otherwise informational: report what's listening."""
    t = time.monotonic()
    ports = {5000: "callback server", 5001: "dashboard"}
    busy = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                busy.append(port)
    if expect_free and busy:
        names = ", ".join(f"{p} ({ports[p]})" for p in busy)
        return _result("ports", FAIL, f"Port(s) already in use: {names}",
                       hint="Is the app already running? Stop it first, or find the "
                            "process with: lsof -i :5000 -i :5001", started=t)
    if busy:
        names = ", ".join(str(p) for p in busy)
        return _result("ports", PASS, f"App appears to be running (listening on {names})", started=t)
    return _result("ports", PASS, "Ports 5000/5001 are free", started=t)


def check_disk_space(min_free_mb=500):
    t = time.monotonic()
    free_mb = shutil.disk_usage(ROOT).free / 1e6
    if free_mb < min_free_mb:
        return _result("disk_space", FAIL, f"Only {free_mb:.0f} MB free (need {min_free_mb} MB)",
                       hint="Free up disk space; the DB and AI-model cache need room to grow",
                       started=t)
    return _result("disk_space", PASS, f"{free_mb / 1000:.1f} GB free", started=t)


def check_recent_scrapes(lookback=3, as_warning=False):
    """Production tripwire: if the last scrape sessions all found 0 articles,
    something upstream broke — even if they were logged as 'completed'.

    as_warning=True (preflight): report as WARN instead of FAIL — history is
    stale by definition before a restart, and blocking boot on it would make
    recovery impossible (the app must run before a scrape can succeed).
    """
    t = time.monotonic()
    worst = WARN if as_warning else FAIL
    db_path = os.path.join(ROOT, config.DATABASE_PATH)
    if not os.path.exists(db_path):
        return _result("recent_scrapes", PASS, "No database yet — nothing to evaluate", started=t)
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            rows = conn.execute(
                "SELECT session_date, total_articles_found, status, error_log "
                "FROM scraping_sessions WHERE status != 'cancelled' "
                "ORDER BY id DESC LIMIT ?", (lookback,)).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as e:
        return _result("recent_scrapes", WARN, f"Could not read scrape history: {e}", started=t)

    if not rows:
        return _result("recent_scrapes", PASS, "No scrape sessions recorded yet", started=t)

    zero_streak = all(r[1] == 0 for r in rows)
    last_date, last_found, last_status, last_error = rows[0]
    if zero_streak and len(rows) >= 2:
        msg = (f"Last {len(rows)} scrape sessions ALL found 0 articles "
               f"(latest: {last_date}, status '{last_status}')")
        if last_error:
            msg += f" — last error: {last_error[:150]}"
        return _result("recent_scrapes", worst, msg,
                       hint="Run: python health_checks.py (news_sources check) to find "
                            "what is blocking the feeds", started=t)
    if last_found == 0:
        return _result("recent_scrapes", WARN,
                       f"Most recent scrape ({last_date}) found 0 articles", started=t)
    return _result("recent_scrapes", PASS,
                   f"Latest scrape found {last_found} article(s) ({last_date})", started=t)


# ──────────────────────────────────────────────────────────────────────────
# Runner + CLI
# ──────────────────────────────────────────────────────────────────────────

def run_all_checks(deep=True, preflight=False, smtp_login=False):
    """Returns {'status': 'pass'|'warn'|'fail', 'checks': [...], ...}.
    deep=False skips network checks (news sources + SMTP)."""
    checks = [
        check_dependencies,
        check_config,
        check_database,
        lambda: check_ports(expect_free=preflight),
        check_disk_space,
        lambda: check_recent_scrapes(as_warning=preflight),
    ]
    if deep:
        checks.append(check_news_sources)
        checks.append(lambda: check_smtp(try_login=smtp_login))

    results = []
    for fn in checks:
        try:
            results.append(fn())
        except Exception as e:  # a check must never take the runner down
            name = getattr(fn, "__name__", "check").replace("check_", "")
            results.append(_result(name, FAIL, f"Check crashed: {type(e).__name__}: {e}"))

    overall = PASS
    if any(r["status"] == WARN for r in results):
        overall = WARN
    if any(r["status"] == FAIL for r in results):
        overall = FAIL
    return {
        "status": overall,
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "deep": deep,
        "checks": results,
    }


ICONS = {PASS: "✅", WARN: "⚠️ ", FAIL: "❌"}


def print_report(report):
    print("=" * 66)
    print("🩺  THREAT INTEL SYSTEM — HEALTH CHECK")
    print("=" * 66)
    for r in report["checks"]:
        print(f"{ICONS[r['status']]} {r['name']:<16} {r['message']}")
        if r.get("hint"):
            print(f"   ↳ fix: {r['hint']}")
    print("-" * 66)
    label = {PASS: "ALL CHECKS PASSED", WARN: "PASSED WITH WARNINGS", FAIL: "CHECKS FAILED"}
    print(f"{ICONS[report['status']]} {label[report['status']]}"
          f"{'' if report['deep'] else '  (fast mode — network checks skipped)'}")
    print("=" * 66)


def main():
    parser = argparse.ArgumentParser(description="Health checks for the Threat Intel system")
    parser.add_argument("--fast", action="store_true",
                        help="skip network checks (news sources, SMTP)")
    parser.add_argument("--preflight", action="store_true",
                        help="pre-launch mode: app ports must be FREE")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--smtp-login", action="store_true",
                        help="also verify SMTP credentials (still sends NO email)")
    args = parser.parse_args()

    report = run_all_checks(deep=not args.fast, preflight=args.preflight,
                            smtp_login=args.smtp_login)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    sys.exit(1 if report["status"] == FAIL else 0)


if __name__ == "__main__":
    main()
