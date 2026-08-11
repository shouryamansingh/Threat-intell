# Deploying to an AWS / private company server

For a small internal deployment (~5 users). One EC2 instance, SQLite, nginx in
front. Roughly an hour end to end.

Everything the app needs to know now comes from environment variables, so no
source file has to be edited per environment.

---

## 0. Before you start: rotate the Gmail app password

The old app password sat in plaintext in `admin_settings.json`. Treat it as
compromised: go to the Google account's **App passwords** page, delete the old
one, generate a new one, and use the new value below. Nothing else in this guide
matters if the credential in it is already burned.

---

## 1. Server layout

Three separate directories, because they have different lifetimes and different
permissions:

| Path | Contents | Notes |
|---|---|---|
| `/opt/threatintel` | the code | read-only at runtime |
| `/var/lib/threatintel` | `threat_intel.db`, `.flask_secret_key` | **back this up** |
| `/var/log/threatintel` | rotating log files | 10 MB × 5 per component |
| `/etc/threatintel/threatintel.env` | credentials | root-owned, `0640` |

Keeping the database out of `/opt/threatintel` is the point: redeploying the
code can then never overwrite live data.

```bash
sudo useradd --system --home /opt/threatintel --shell /usr/sbin/nologin threatintel
sudo mkdir -p /opt/threatintel /var/lib/threatintel /var/log/threatintel /etc/threatintel
sudo chown -R threatintel:threatintel /opt/threatintel /var/lib/threatintel /var/log/threatintel
```

## 2. Code and dependencies

```bash
sudo -u threatintel git clone <your-repo-url> /opt/threatintel
cd /opt/threatintel
sudo -u threatintel python3 -m venv .venv
sudo -u threatintel .venv/bin/pip install -r requirements.txt
```

The dependency install pulls `torch` and `sentence-transformers`, so budget
several GB of disk and a few minutes. The first AI summary downloads a ~1.5 GB
model once — pre-warm it if you don't want the first scrape to be slow.

## 3. Configuration

```bash
sudo cp /opt/threatintel/.env.example /etc/threatintel/threatintel.env
sudo chown root:threatintel /etc/threatintel/threatintel.env
sudo chmod 640 /etc/threatintel/threatintel.env
sudo nano /etc/threatintel/threatintel.env
```

Every variable is documented in `.env.example`. The ones that will bite you if
you get them wrong:

```ini
TI_ENV=production

# THE critical one. This goes into the Approve/Reject buttons in email and is
# resolved in the RECIPIENT's browser. If it says localhost, every button in
# every email does nothing.
TI_PUBLIC_BASE_URL=https://threatintel.internal.example.com

# nginx connects locally, so the apps stay on loopback.
TI_DASHBOARD_BIND_HOST=127.0.0.1
TI_CALLBACK_BIND_HOST=127.0.0.1
TI_TRUSTED_PROXY_HOPS=1

# Off the code directory, on local disk (never EFS/NFS — SQLite locking breaks).
TI_DATABASE_PATH=/var/lib/threatintel/threat_intel.db
TI_STATE_DIR=/var/lib/threatintel
TI_LOG_DIR=/var/log/threatintel

# Scheduling. Without this, APScheduler uses the machine zone — UTC on EC2 —
# and every job fires 5h30m off from what the admin panel says.
TI_TIMEZONE=Asia/Kolkata

# Credentials, so nothing is written to disk in the project folder.
TI_SENDER_EMAIL=...
TI_SENDER_PASSWORD=<the NEW app password from step 0>
TI_MANAGER_EMAIL=...
TI_SOC_EMAIL=...

TI_ALLOWED_EMAIL_DOMAINS=example.com
TI_BOOTSTRAP_SUPER_ADMINS=you@example.com
TI_DEFAULT_ADMIN_PASSWORD=<a long random string>

# Copy these from your local .env — the app cannot do browser sign-in without them.
TI_FIREBASE_API_KEY=...
TI_FIREBASE_AUTH_DOMAIN=...
TI_FIREBASE_PROJECT_ID=...
TI_FIREBASE_STORAGE_BUCKET=...
TI_FIREBASE_MESSAGING_SENDER_ID=...
TI_FIREBASE_APP_ID=...

# Branding. Optional — unset, the dashboard uses the neutral shield mark. See
# step 3b: the SVGs these point at are NOT in git and must be copied across.
TI_BRAND_NAME=...
TI_BRAND_LOGO=/static/brand-logo.svg
TI_BRAND_ICON=/static/brand-icon.svg
TI_BRAND_COLOR=#RRGGBB
```

### 3b. Brand assets (only if you set `TI_BRAND_*`)

The company logo files are deliberately gitignored, so the repository does not
carry the employer's visual identity. `git clone` will not bring them and the
dashboard will render a broken image if `TI_BRAND_LOGO` points at a file that
was never deployed. Copy them across by hand:

```bash
# From your laptop:
scp static/brand-logo.svg static/brand-icon.svg ec2-user@server:/tmp/

# On the server:
sudo mv /tmp/brand-logo.svg /tmp/brand-icon.svg /opt/threatintel/static/
sudo chown threatintel:threatintel /opt/threatintel/static/brand-*.svg
```

Redeploying the code does not remove them (they are untracked), but a fresh
`git clone` into an empty directory will not have them — repeat this step then.
Leave `TI_BRAND_*` unset if you would rather run the neutral identity.

Sanity-check it before starting anything:

```bash
cd /opt/threatintel
sudo -u threatintel env $(grep -v '^#' /etc/threatintel/threatintel.env | xargs) \
  .venv/bin/python -c "import config; [print('PROBLEM:', p) for p in config.validate_deployment()] or print('config OK')"
```

## 4. Migrate the existing database

Copy your current `threat_intel.db` — it holds the article history, user
accounts and delivery records. Stop the app locally first so the copy is clean.

```bash
# On your laptop, with the app stopped:
sqlite3 threat_intel.db ".backup /tmp/threat_intel.db"
scp /tmp/threat_intel.db ec2-user@server:/tmp/

# On the server:
sudo mv /tmp/threat_intel.db /var/lib/threatintel/
sudo chown threatintel:threatintel /var/lib/threatintel/threat_intel.db
```

`.backup` rather than `cp`: it produces a consistent snapshot including the WAL.

Also copy `.flask_secret_key` to `/var/lib/threatintel/` if you want approval
links already sitting in people's inboxes to keep working. A new secret
invalidates every previously sent link.

## 5. Services

```bash
sudo cp /opt/threatintel/deploy/threatintel-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threatintel-callback threatintel-dashboard
systemctl status threatintel-dashboard
journalctl -u threatintel-dashboard -f
```

Two services, not three: the scheduler is created at import time inside
`scheduler.py` and the dashboard imports it, so the weekly scrape, the SOC
delivery poller and the nightly retention sweep all run in the dashboard
process. **Never scale the dashboard past `--workers 1`** — a second worker
would run every scheduled job twice and send every email twice.

## 6. nginx and TLS

```bash
sudo cp /opt/threatintel/deploy/nginx-threatintel.conf /etc/nginx/sites-available/threatintel
sudo ln -s /etc/nginx/sites-available/threatintel /etc/nginx/sites-enabled/
sudo nano /etc/nginx/sites-available/threatintel   # set server_name + cert paths
sudo nginx -t && sudo systemctl reload nginx
```

One vhost fronts both processes: `/approve/…`, `/reject/…` and `/validate_…` go
to the callback server, everything else to the dashboard. That is why a single
`TI_PUBLIC_BASE_URL` works for both.

Use a certificate from your company CA for an internal hostname, or certbot if
the name resolves publicly. HTTP-only will work but sends Firebase ID tokens and
session cookies in cleartext — and `TI_ENV=production` sets
`SESSION_COOKIE_SECURE`, so **sessions will not persist over plain HTTP**. If you
genuinely must run without TLS, that is the setting to revisit.

## 7. Firewall and outbound access

Security group inbound: 443 (and 80 for the redirect) from the office/VPN range
only. **Not** 5000 or 5001 — those stay on loopback. 22 from your admin range.

Outbound matters just as much, and a corporate egress filter is the most likely
thing to break this app silently:

| Destination | Why | Fails as |
|---|---|---|
| `smtp.gmail.com:587` | sending mail | no email at all |
| `googleapis.com:443` | Firebase token-signing certs | **nobody can log in** |
| `thehackernews.com:443` | RSS feed | that source returns 0 articles |
| `securityweek.com:443` | RSS feed | that source returns 0 articles |
| `csoonline.com:443` | RSS feed | that source returns 0 articles |
| `krebsonsecurity.com:443` | RSS feed | that source returns 0 articles |
| `bleepingcomputer.com:443` | RSS feed | that source returns 0 articles |
| `bankinfosecurity.com:443` | RSS feed | that source returns 0 articles |
| `gstatic.com`, `cdn.jsdelivr.net`, `cdnjs.cloudflare.com` | Firebase SDK + CSS, loaded by the browser | login page broken for users |

All six feeds are enabled (`NEWS_SOURCES` in `config.py`). One blocked host now
degrades the scrape instead of emptying it — but it degrades *quietly*, so let
`health_checks.py` tell you which ones resolve rather than reading the article
count. Note the scraper sets `verify = False` on its HTTP session, so a TLS
intercepting proxy will not break feed fetching the way it breaks `curl`.

Note AWS blocks outbound port 25 by default; this app uses 587, so that's fine.

Verify from the server before blaming the app:

```bash
cd /opt/threatintel && sudo -u threatintel .venv/bin/python health_checks.py
```

`health_checks.py` is read-only and stops at STARTTLS — it never sends mail.

## 8. Firebase console

Add the server's hostname to **Authentication → Settings → Authorized domains**.
Without it, sign-in fails in the browser with an unhelpful error even though the
server is configured correctly.

## 9. First login

With `TI_DEFAULT_ADMIN_PASSWORD` set, use that. If you left it blank, a random
password was generated on first start and written to a 0600 file:

```bash
sudo cat /var/lib/threatintel/.initial_admin_password
```

The password is deliberately **not** in the log — journald is readable by more
accounts than that file is, and log lines end up pasted into tickets. The log
only names the file:

```bash
journalctl -u threatintel-dashboard | grep -A3 "Bootstrap admin"
```

The one exception is if the app could not write the file at all (wrong
`TI_STATE_DIR` permissions); then it has no other channel and does log the
password once, saying so explicitly. If you see that, fix the directory
ownership and purge the journal entry.

Change the password in the admin panel, then delete the file.

## 10. Backups

One SQLite file, no replication — if the volume dies, everything is gone.

```bash
sudo tee /etc/cron.daily/threatintel-backup >/dev/null <<'EOF'
#!/bin/sh
set -e
DEST=/var/backups/threatintel
mkdir -p "$DEST"
STAMP=$(date +%Y%m%d)
sqlite3 /var/lib/threatintel/threat_intel.db ".backup $DEST/threat_intel-$STAMP.db"
gzip -f "$DEST/threat_intel-$STAMP.db"
find "$DEST" -name '*.db.gz' -mtime +30 -delete
EOF
sudo chmod +x /etc/cron.daily/threatintel-backup
```

Also take EBS snapshots, and copy `.flask_secret_key` somewhere safe — losing it
invalidates every approval link already sitting in an inbox.

---

## Careful: the app sends real email

Once `threatintel-dashboard` starts, the delivery poller is live and will send
to whatever `TI_SOC_EMAIL` says, including external recipients. For the first
run, point `TI_MANAGER_EMAIL` and `TI_SOC_EMAIL` at yourself and set
`ACCESS_REQUEST_EMAIL=0`. Switch to the real recipients once you've watched one
full cycle.

## Verifying it actually works

1. `curl -sI https://your-host/` → 200 or a login redirect.
2. Sign in from a browser on the office network.
3. Trigger a manual scrape from the dashboard; watch `journalctl -f`.
4. **Open the approval email on a different machine and click Approve.** This is
   the step that was broken before — if `TI_PUBLIC_BASE_URL` is wrong, the
   button leads nowhere. Nothing else exercises that path.
5. Check the dashboard's activity log updated in real time (proves Socket.IO is
   proxying correctly).
6. `sudo systemctl restart threatintel-dashboard` and confirm the schedule
   survives: the admin panel's next-run times should match the panel's clock.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Approve/Reject buttons do nothing | `TI_PUBLIC_BASE_URL` unset or still localhost |
| Dashboard unreachable, `curl` works on the box | bind host is 127.0.0.1 and nginx isn't proxying, or the security group blocks 443 |
| Login fails for everyone | outbound 443 to `googleapis.com` blocked, host missing from Firebase Authorized domains, or `TI_FIREBASE_*` unset |
| Logged in, immediately logged out | `TI_ENV=production` sets secure-only cookies but you're on plain HTTP |
| Jobs fire 5.5 hours late | `TI_TIMEZONE` unset |
| Empty dashboard after deploy | `TI_DATABASE_PATH` points somewhere new; a fresh empty DB was created |
| Live updates stop working | nginx missing the `/socket.io/` upgrade headers |
| `database is locked` | more than one dashboard worker, or the DB is on NFS/EFS |
| Emails send twice | two dashboard processes/workers running the scheduler |

Logs are in two places: `journalctl -u threatintel-dashboard` and
`/var/log/threatintel/*.log`.
