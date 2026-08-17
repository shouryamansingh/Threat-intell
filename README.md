# Threat Intelligence Automation System

Collects cybersecurity news from curated sources, scores it for relevance to
financial services, and runs it through a human approval workflow before it
reaches the SOC — on a fixed weekly cadence, with a web dashboard over the whole
pipeline.

Built for a small internal team (~5 users): one process, one SQLite file, no
external services beyond SMTP and Firebase sign-in.

---

## How it works

```
  Mon 10:00   scrape ──▶ score & summarise ──▶ store
                                                │
  (on scrape) │                                 ▼
              └──────────── email to manager: top N articles,
                            each with APPROVE / REJECT buttons
                                                │
                            manager clicks ─────┤ (callback server, :5000)
                                                ▼
                            approved articles ──▶ sender validation
                                                ▼
  Tue 11:00                            SOC delivery email
```

Every step is visible and re-runnable from the dashboard on `:5001`. Times are
in `TI_TIMEZONE` (default `Asia/Kolkata`); the schedule itself is editable in
the admin panel.

**Sources:** The Hacker News · Security Week · CSO Online · Krebs on
Security · Bleeping Computer — all five live in
[`NEWS_SOURCES`](config.py). RSS is the primary path for each; the per-site
CSS selectors are only the direct-scrape fallback for when a feed fails.

Bank Info Security is intentionally left out: none of its feed URLs return
dated entries, and undated items defeat the 7-day freshness filter, which
would place archive material in a digest presented as current. The reasoning
is recorded next to `NEWS_SOURCES` so it isn't re-added by accident.

`python health_checks.py` fetches every feed end-to-end and is the only
reliable way to tell "quiet news week" apart from "this source is broken".

**Scoring** favours regulatory (SEBI, RBI, NPCI), payments (UPI, RTGS, NEFT),
and infrastructure (API, cloud, Kubernetes, supply chain, CVE) keywords. See
`CYBERSECURITY_KEYWORDS` / `HIGH_PRIORITY_KEYWORDS` in [config.py](config.py).

---

## Quick start (local)

Requires Python 3.8+ and about 4 GB of disk — the dependency tree includes
`torch` and `sentence-transformers`.

```bash
# 1. Configure. Nothing runs without this step.
cp .env.example .env
$EDITOR .env

# 2. Create the virtualenv, install dependencies, and start both servers.
python run.py --setup
```

Then open **http://localhost:5001**.

On later runs `python run.py` is enough. macOS users can double-click
[run.command](run.command) instead.

| Flag | Effect |
|---|---|
| `python run.py` | preflight health checks, then start |
| `--setup` | create `.venv` + install dependencies first |
| `--install` | install dependencies into the current interpreter |
| `--fast-checks` | skip the network portion of preflight (offline dev) |
| `--skip-checks` | start even if preflight fails |

`run.py` is **for local development only** — it holds both servers as child
processes, so they die with the terminal and never restart. For a server, use
the systemd units in [deploy/](deploy/).

> The first AI summary downloads a ~1.5 GB model once, so the first scrape is
> slow. It is cached afterwards.

### Minimum configuration

The app fails closed: with an empty `.env` nobody can sign in and no mail can be
sent. The values you actually need to set are documented inline in
[.env.example](.env.example); the ones that most often get missed:

| Variable | Why it matters |
|---|---|
| `TI_PUBLIC_BASE_URL` | Written into the Approve/Reject buttons and resolved in the **recipient's** browser. Left as localhost, every button silently does nothing. |
| `TI_TIMEZONE` | Unset, APScheduler uses the machine zone — UTC on EC2 — and every job fires hours off from what the admin panel shows. |
| `TI_ALLOWED_EMAIL_DOMAINS` | Domains permitted to sign in. Defaults to a demo domain and fails closed. |
| `TI_FIREBASE_*` | Browser sign-in. Without it the login page says so instead of erroring. |
| `TI_SENDER_EMAIL` / `TI_SENDER_PASSWORD` | SMTP credentials. Without them nothing sends. |

---

## Running it

Two processes, both needed:

| Process | Port | Role |
|---|---|---|
| `web_dashboard.py` | 5001 | dashboard, admin panel, **and the scheduler** |
| `callback_server.py` | 5000 | handles Approve/Reject clicks from email |

The scheduler is created at import time inside `scheduler.py`, which the
dashboard imports — so the weekly scrape, the SOC delivery poller and the
nightly retention sweep all run inside the dashboard process. **Never run more
than one dashboard worker:** a second one runs every scheduled job twice and
sends every email twice.

> ⚠️ **This application sends real email.** Once the dashboard is up the
> delivery poller is live and will send to whatever `TI_SOC_EMAIL` names,
> including external recipients. Point it at yourself for the first full cycle.

---

## Health checks

The system self-diagnoses, so scraping and network breakage cannot pass
unnoticed.

```bash
python health_checks.py               # full: deps, config, DB, feeds, SMTP, disk
python health_checks.py --fast        # skip network checks
python health_checks.py --json        # machine-readable, for CI / cron alerting
python health_checks.py --smtp-login  # verify SMTP credentials (sends NO email)
```

It also runs automatically at startup (`run.py` refuses to launch a broken
system), then ~2 minutes after boot and every 6 hours thereafter, logging to the
dashboard's system log. Endpoints: `GET /healthz` (public liveness probe) and
`GET /api/health?deep=1` (admin only).

The `news_sources` check fetches every RSS feed end-to-end and flags off-site
redirects — a corporate network blocking one of those once silently broke all
scraping — verifies entries are fresh, and confirms the direct-scrape fallback
selectors still match each site's homepage.

---

## Deploying

Start with **[deploy/LIGHTSAIL.md](deploy/LIGHTSAIL.md)** — the recommended
deployment. One AWS Lightsail instance runs everything: dashboard, callback
server, scheduler, database and both models. It covers instance sizing, the
model-cache setup that fails silently if skipped, and hands off to:

**[deploy/DEPLOY.md](deploy/DEPLOY.md)** — the server walkthrough itself: user
and directory layout, systemd units, nginx + TLS, egress requirements, database
migration and backups. Applies to any Linux host, not just Lightsail.

**[deploy/SPLIT-DEPLOYMENT.md](deploy/SPLIT-DEPLOYMENT.md)** is the two-box
alternative — app on Lightsail, models on a separate EC2 instance. Only worth it
if you stop the model box between scrapes.

Before your first `git push`, read **[deploy/GITHUB.md](deploy/GITHUB.md)** and
run:

```bash
python check_secrets.py
```

Exit code 0 means the files git would publish carry no credentials, personal
data, internal hostnames or company branding. It checks two things `.gitignore`
cannot: whether anything sensitive is *already tracked* (an ignore rule does
nothing for a file git has committed once), and whether publishable files
contain credential-shaped strings.

It also refuses to publish this deployment's own identity. `TI_BRAND_NAME` and
`TI_BRAND_COLOR` are picked up from `.env` automatically; add anything else —
personal names, internal hostnames — to `.forbidden_terms`:

```bash
cp .forbidden_terms.example .forbidden_terms
```

Both that file and `.env` are gitignored, because listing those terms in a
committed file would leak precisely what the check exists to prevent.

### Files that must never be committed

Covered by [.gitignore](.gitignore) — do not remove these entries:

- `.env` — every real value, including SMTP credentials
- `admin_settings.json` — app password and real recipients
- `.flask_secret_key` — signs email approval links; leaking it lets anyone mint
  a valid Approve link for any article and forge internal API calls
- `.initial_admin_password` — generated bootstrap credential
- `threat_intel.db` (+ `-wal`, `-shm`) — articles, user profiles with real email
  addresses, full delivery history
- `logs/` — recipient addresses, SMTP conversations, tracebacks
- `*.xlsx` / `*.csv` — generated report attachments
- `static/brand-*` — deployment-specific company logo assets

---

## Branding

The repository ships a neutral identity: the shield mark in
[static/shield-logo.svg](static/shield-logo.svg), the name "Threat Intel", and
the accent `#2F6BFF`. Nothing in a committed file names a company.

To brand a deployment, drop your own `static/brand-logo.svg` (wide wordmark) and
`static/brand-icon.svg` (square mark and favicon) — both names are gitignored —
and set `TI_BRAND_NAME`, `TI_BRAND_LOGO`, `TI_BRAND_ICON` and `TI_BRAND_COLOR`.
Those assets are not in git, so they must be deployed alongside the code.

---

## Layout

```
run.py                          local launcher for both servers
config.py                       settings; env vars override admin_settings.json
web_dashboard.py                dashboard, admin API, hosts the scheduler
callback_server.py              Approve/Reject endpoints for email links
scheduler.py                    weekly scrape, delivery poller, retention sweep
web_scraper.py                  RSS + direct-scrape collection and scoring
email_system.py                 approval and SOC email construction
sender_validation.py            pre-delivery format validation
soc_report_formatter*.py        SOC-facing report rendering
database.py                     SQLite access layer
auth.py / rbac.py               Firebase sign-in, roles and permissions
link_tokens.py                  HMAC tokens for one-click email actions
health_checks.py                the diagnostics described above
check_secrets.py                pre-push safety net
templates/ static/              dashboard UI
deploy/                         systemd units, nginx config, deployment docs
tests/                          regression tests
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

The suite pins the two articles that once produced broken SOC reports, so those
specific failures cannot silently return.

---

## License

Proprietary — see [LICENSE](LICENSE). Internal use only.
