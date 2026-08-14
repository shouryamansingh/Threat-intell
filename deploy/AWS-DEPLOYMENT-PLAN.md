# AWS deployment plan

Working document for moving the Threat Intelligence System onto AWS. It records
*why* the architecture is what it is, covers the AWS-side steps that
`DEPLOY.md` assumes you already did, and tracks progress.

`DEPLOY.md` is still the authority for everything from "you have a server" to
"it works". This file wraps around it: §2 gets you a server, §3 covers the
model-specific setup DEPLOY.md doesn't, then you hand off. Don't duplicate
DEPLOY.md's steps here — fix them there.

---

## 1. Progress log

Newest last. Add a line whenever something changes.

| Date | What happened |
|---|---|
| 2026-08-13 | Evaluated AWS Amplify Hosting. Rejected — see D1. Chose EC2 (D2). Found the model-cache bug in §3.3 while sizing the instance; documented `HF_HOME` in `.env.example`. Nothing deployed yet. |
| 2026-08-13 | Opened the EC2 launch wizard. Recorded the wizard defaults that must be changed (§3.2). |

**Current state:** planning. No AWS resources created. Nothing running anywhere
but the developer laptop.

**Next action:** §3.2 — launch the instance.

---

## 2. Decisions

### D1 — Not AWS Amplify Hosting

Amplify Hosting serves static files and Node.js SSR (Next.js, Nuxt). It cannot
run this app, and no combination of its settings changes that:

- **No Python runtime.** There is nothing to run `gunicorn web_dashboard:app`.
  The Jinja templates in `templates/` render per request; no build step emits
  static HTML for Amplify to serve.
- **No persistent process.** `scheduler.py` builds its APScheduler singleton at
  import time and the dashboard holds it for the process lifetime. That is the
  entire delivery mechanism — Amplify has no always-on process to hold it.
- **Ephemeral filesystem.** `threat_intel.db` would be destroyed on every
  deploy.
- **No WebSockets.** Flask-SocketIO powers the dashboard's live activity log.
- **Size.** `torch` plus the summarisation model is ~4.5 GB, far past Amplify's
  build limits.

An Amplify app was configured up to the point of discovering this. If it is
still in the console, either delete it or repoint it at `docs/` as a
documentation-only site — with **password protection on**, because publishing
with output directory `/` would serve all 44 tracked files, including
`auth.py`, `link_tokens.py`, `rbac.py`, and this directory's server layout, at
a public URL.

### D2 — EC2 first, then reconsider the local models

Two phases, deliberately sequenced so we are never debugging a code change and
a new deployment at the same time.

- **Phase 1 (§2–§4):** lift-and-shift to one EC2 instance, keeping the local
  HuggingFace models. Zero code changes. `DEPLOY.md` already describes it.
- **Phase 2 (§5):** replace the local models with the Claude API, which deletes
  the heavy ML stack and makes the app small enough to containerise. Optional,
  and only after Phase 1 is stable.

The local models are what make this app expensive to host — `torch`,
`transformers`, `sentence-transformers`, and `scikit-learn` exist solely to
serve two calls in `soc_report_formatter_enhanced.py`. Phase 1 pays that cost;
Phase 2 removes it.

---

## 3. Phase 1 — launch the instance

Everything in this section happens in the AWS console or on the new box, and
ends where `DEPLOY.md` §1 begins.

### 3.1 Instance sizing — driven by the models, not the web app

The Flask app is trivial to host. The sizing is entirely about
`facebook/bart-large-cnn` sitting resident in RAM.

| | Value | Why |
|---|---|---|
| Instance type | **`m6i.large`** (2 vCPU, 8 GB) | See the note on burstable below |
| Root volume | **30 GB gp3** | torch installs to ~3 GB; models are ~1.7 GB; leave room for logs and the OS |
| AMI | Ubuntu 22.04 or 24.04 LTS | `DEPLOY.md` assumes `apt` and `/usr/sbin/nologin` |
| Architecture | x86_64 | Simplest torch wheel story; arm64 works but is not worth the variable here |

**Why 8 GB and not 4.** Only the dashboard process holds the models —
`callback_server.py` imports just Flask, `database`, `link_tokens` and `config`,
so its two gunicorn workers stay light. Measured budget:

| Process | Holds | Peak RSS |
|---|---|---|
| `threatintel-dashboard` (1 worker) | torch + BART + MiniLM | ~3.5–4.5 GB |
| `threatintel-callback` (2 workers) | Flask only, no torch | ~200 MB each |
| Ubuntu + nginx | — | ~500–700 MB |
| **Peak total** | | **~5–6 GB** |

8 GB leaves headroom; `t3.medium` (4 GB) sits under peak and the kernel will
OOM-kill the dashboard mid-scrape. Because the scheduler lives inside that
process, the weekly scrape and the delivery poller die with it.

**Family/size shortlist.** `m` is general purpose at 4 GB RAM per vCPU, and
`.large` is 2 vCPU — hence 8 GB. `m6a.large` (AMD) is the same specs for ~$7/mo
less and runs torch identically. Avoid `c6i.large`: compute-optimised means
2 GB per vCPU, so it is only 4 GB and will OOM. Avoid Graviton/ARM (`m7g`,
`t4g`) on a first deployment — `requirements.txt` pins `torch==2.9.0` and the
aarch64 wheel story is an avoidable variable.

**Why `m6i.large` over the cheaper `t3.large`:** `t3` is burstable — 30 %
baseline CPU, credits above that. Summarising a batch of articles is 10–30
minutes of sustained CPU, which is exactly what drains credits; when they run
out the instance throttles and the scrape crawls. `t3.large` with unlimited
mode enabled also works and is a little cheaper, at the cost of a variable
bill. Both are roughly $60–70/month on-demand — check current pricing for your
region.

**The free tier cannot run this.** `t2.micro`/`t3.micro` is 1 vCPU and 1 GiB
RAM — the summarisation model alone needs about four times that, so the
dashboard is OOM-killed as soon as the first summary runs. Free-tier EBS does
cover 30 GB, so the storage bump in the table below stays inside it, but the
instance itself is a paid size. If the budget is the blocker, do Phase 2 (§5)
*first* — without the local models the app fits comfortably in 2 GB.

**AMI: choose Ubuntu, not the Amazon Linux 2023 default.** `DEPLOY.md` is
written for Debian-family paths and tooling throughout — `apt`,
`/usr/sbin/nologin` in the `useradd` call, and nginx's
`sites-available`/`sites-enabled` layout. Amazon Linux uses `dnf`,
`/sbin/nologin`, and `/etc/nginx/conf.d/`, so every one of those steps needs
translating. Pick Ubuntu in the wizard's left-hand OS list and the guide works
verbatim.

### 3.2 Launch it

AWS console → **EC2 → Instances → Launch an instance**:

1. **Name:** `threatintel-prod`
2. **AMI:** Ubuntu Server 24.04 LTS (x86_64)
3. **Instance type:** `m6i.large`
4. **Key pair:** create new — name `threatintel-prod-key`, type **ED25519**,
   format **`.pem`**. ED25519 over RSA (shorter, faster, modern); `.pem` over
   `.ppk` because macOS/Linux use OpenSSH and `.ppk` is PuTTY-only.

   AWS keeps no copy of the private key — that download is the only one you get.
   Move it out of `~/Downloads` and **not** into this repo, where one
   `git add -A` would publish it:

   ```bash
   mkdir -p ~/.ssh
   mv ~/Downloads/threatintel-prod-key.pem ~/.ssh/
   chmod 400 ~/.ssh/threatintel-prod-key.pem
   ```

   Optional `~/.ssh/config` entry so `ssh threatintel` and `scp` just work —
   the latter matters for DEPLOY.md §3b (brand SVGs) and §4 (database copy):

   ```
   Host threatintel
       HostName <elastic-ip>
       User ubuntu
       IdentityFile ~/.ssh/threatintel-prod-key.pem
   ```

   > **Login user is `ubuntu`, not `ec2-user`.** DEPLOY.md's `scp`/`ssh`
   > examples say `ec2-user@server`, which is the Amazon Linux convention.
   > On the Ubuntu AMI (D2 §3.1) substitute `ubuntu@` throughout.
5. **Network settings → Edit → Create security group** named
   `threatintel-sg`, with inbound rules **only**:
   | Type | Port | Source |
   |---|---|---|
   | SSH | 22 | your admin IP/range only — not `0.0.0.0/0` |
   | HTTPS | 443 | office/VPN range |
   | HTTP | 80 | office/VPN range (for the TLS redirect) |

   Do **not** open 5000 or 5001. Both apps bind to `127.0.0.1` and nginx
   proxies to them; exposing those ports would bypass TLS entirely.
6. **Storage:** change the root volume to 30 GiB, gp3.
7. Launch.

Then **Elastic IPs → Allocate → Associate** with the instance. Without it the
public IP changes on every stop/start, which breaks `TI_PUBLIC_BASE_URL` and
every approval link already sitting in an inbox.

Point your DNS name at that Elastic IP before requesting a certificate.

### 3.3 The model cache must be redirected before first start

**This one will bite silently if skipped.** The `threatintel` service account
is created with `--home /opt/threatintel` (`DEPLOY.md` §1), so HuggingFace
defaults its cache to `/opt/threatintel/.cache/huggingface`. But both systemd
units set `ProtectSystem=strict` with
`ReadWritePaths=/var/lib/threatintel /var/log/threatintel` — so at runtime
`/opt/threatintel` is **read-only** and the model download cannot write its
cache.

The failure mode is quiet. `_get_summarizer()` catches the exception, logs a
warning, and sets `_ai_available = False` for the lifetime of the process
([soc_report_formatter_enhanced.py:64-67](../soc_report_formatter_enhanced.py#L64-L67)).
Reports keep generating with the non-AI fallback text. Nothing looks broken;
the summaries are just worse until someone restarts the service.

Fix it in two places. In `/etc/threatintel/threatintel.env`, alongside the
other `TI_*` settings:

```ini
# Model cache. Must sit inside the systemd units' ReadWritePaths — the code
# directory is read-only at runtime under ProtectSystem=strict.
HF_HOME=/var/lib/threatintel/huggingface
```

And create it before starting anything:

```bash
sudo mkdir -p /var/lib/threatintel/huggingface
sudo chown threatintel:threatintel /var/lib/threatintel/huggingface
```

### 3.4 Pre-warm the models

`DEPLOY.md` §2 says to pre-warm without saying how. Run this after the venv
exists and before enabling the services — it downloads ~1.7 GB once, so the
first scrape isn't waiting on it:

```bash
cd /opt/threatintel
sudo -u threatintel HF_HOME=/var/lib/threatintel/huggingface \
  .venv/bin/python -c "
from transformers import pipeline
from sentence_transformers import SentenceTransformer
pipeline('summarization', model='facebook/bart-large-cnn')
SentenceTransformer('all-MiniLM-L6-v2')
print('models cached OK')
"
```

The `HF_HOME` on the command line must match the one in the env file, or you
will warm a cache the service cannot read.

Verify it landed somewhere writable:

```bash
sudo du -sh /var/lib/threatintel/huggingface   # expect ~1.7G
```

### 3.5 Hand off to DEPLOY.md

From here, work through [DEPLOY.md](DEPLOY.md) start to finish. It covers the
service account, directory layout, dependency install, the env file, the
database copy, systemd, nginx and TLS, egress requirements, Firebase authorised
domains, first login, and backups.

Three things to slot in as you go.

**Before §2 — OS prerequisites.** DEPLOY.md §2 goes straight to
`python3 -m venv`, which fails on a bare Ubuntu 24.04 image because
`python3-venv` is not installed. Also grab the `sqlite3` CLI that §4 and §10
depend on, and nginx for §6:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv python3-dev build-essential \
                    sqlite3 nginx git
```

If `pip install` later tries to *build* lxml instead of using a wheel, add
`libxml2-dev libxslt1-dev`. It normally won't.

Python version is not a concern: the developer venv runs the full stack on
**Python 3.13**, and Ubuntu 24.04 ships 3.12, so every pin in
`requirements.txt` is satisfiable without change.

**Between §2 and §5:** run the pre-warm from §3.4, after the venv is built and
before `systemctl enable --now`.

**In §3 (the env file):** add the `HF_HOME` line from §3.3 above.

**Throughout:** substitute `ubuntu@` for DEPLOY.md's `ec2-user@` in every `ssh`
and `scp` example (§3.2).

### Sanity-check the instance before you start

Thirty seconds, and it catches a launch-wizard mistake before an hour of setup:

```bash
free -h            # expect ~7.6Gi total  — if ~1Gi, wrong instance type
df -h /            # expect ~29G          — if ~7G, volume size didn't take
nproc              # expect 2
lsb_release -ds    # expect Ubuntu 24.04
```

### 3.6 Before you start the services — it sends real email

Repeating `DEPLOY.md`'s warning because it is the easiest way to cause real
damage here. The moment `threatintel-dashboard` starts, the delivery poller is
live and will mail whoever `TI_SOC_EMAIL` names, external recipients included.

For the first run: point `TI_MANAGER_EMAIL` and `TI_SOC_EMAIL` at yourself, set
`ACCESS_REQUEST_EMAIL=0`, watch one full cycle, then switch to the real
recipients.

Also note `health_checks.py` is safe to run at any time — it is read-only and
stops at STARTTLS without sending anything.

### 3.7 Phase 1 checklist

- [ ] Instance launched (`m6i.large`, 30 GB gp3, Ubuntu 24.04)
- [ ] Security group: 22/443/80 only, scoped to admin and office ranges
- [ ] Elastic IP allocated and associated
- [ ] DNS name pointed at the Elastic IP
- [ ] `HF_HOME` set in the env file and the directory created (§3.3)
- [ ] Models pre-warmed and cache verified (§3.4)
- [ ] `DEPLOY.md` §1–§10 complete
- [ ] `health_checks.py` passes on the server
- [ ] Recipients pointed at yourself for the first cycle (§3.6)
- [ ] One full cycle observed: scrape → email → **Approve clicked from another
      machine** → dashboard log updated live
- [ ] Real recipients restored
- [ ] Daily backup cron installed and one restore tested

---

## 4. Things that will bite (Phase 1)

| Symptom | Cause |
|---|---|
| AI summaries silently stop, fallback text everywhere | `HF_HOME` unset — cache unwritable under `ProtectSystem=strict` (§3.3). Restart clears it until the next process start. |
| Scrape gets slower and slower over months | `t3` CPU credits exhausted. Move to `m6i.large` or enable unlimited mode. |
| Dashboard OOM-killed during a scrape | Instance smaller than 8 GB RAM. |
| First scrape after deploy hangs for minutes | Models not pre-warmed (§3.4). |
| Approval links break after a stop/start | No Elastic IP; `TI_PUBLIC_BASE_URL` now points at a dead address. |

`DEPLOY.md`'s own troubleshooting table covers the app-level failures — wrong
base URL, Firebase egress, timezone, double-send, locked database.

---

## 5. Phase 2 — replace the local models with the Claude API

Not started. Do not begin until Phase 1 has run clean for at least one full
weekly cycle.

### 5.1 Why

`torch` is never imported directly — it arrives via `transformers` and
`sentence-transformers`. `nltk` is in `requirements.txt` but imported nowhere.
`scikit-learn` appears once, at
[soc_report_formatter_enhanced.py:122](../soc_report_formatter_enhanced.py#L122),
inside the sentence-similarity helper. So replacing the two models removes
**transformers, sentence-transformers, torch, and scikit-learn** — roughly 3 GB
of dependencies and a 1.7 GB model download.

What's left is a plain Flask app: it fits a small container, deploys in
seconds, needs no warm-up, and drops the instance requirement from 8 GB to
about 2 GB. Everything in §3.1, §3.3, and §3.4 of this document stops
applying.

### 5.2 Surface area

Small and well contained:

- `_ai_summarize_article`
  ([soc_report_formatter_enhanced.py:86](../soc_report_formatter_enhanced.py#L86))
  is the only summarisation entry point, called from exactly two places
  ([317](../soc_report_formatter_enhanced.py#L317) and
  [363](../soc_report_formatter_enhanced.py#L363)).
- `_get_summarizer` and `_get_sentence_model` (lines 57–84) get deleted.
- The four consumers — `web_dashboard.py`, `scheduler.py`, `email_system.py`,
  `sender_validation.py` — all import the `enhanced_soc_formatter` singleton
  and do not change.
- `tests/test_regression.py` constructs `EnhancedSOCReportFormatter` directly,
  so it needs a stub or a recorded fixture rather than live API calls.

The existing error handling already models an API outage correctly:
`_ai_summarize_article` returns `None` on any exception and callers fall through
to the non-AI path. That is what makes this low-risk.

### 5.3 Open questions to settle first

- **Model and cost.** `claude-opus-5` is $5/$25 per million input/output
  tokens. The current call truncates input to 2000 characters (~500 tokens) and
  asks for 130–250 characters back, so roughly **$0.0075 per article**
  — about $23/month at 100 articles/day. `claude-sonnet-5` ($3/$15) and
  `claude-haiku-4-5` ($1/$5) are the cheaper tiers if volume makes that matter.
- **Bedrock or the direct API.** Bedrock keeps inference in-account with IAM
  auth and AWS billing (`anthropic.claude-opus-5` via the
  `AnthropicBedrockMantle` client); the direct API is one env var and gets
  features first. Nothing this workload needs is missing from Bedrock.
- **The sentence-similarity step.** `all-MiniLM-L6-v2` ranks sentences by
  relevance before summarising. Keeping it keeps `sentence-transformers`, which
  keeps `torch`, which forfeits the entire benefit above. The replacement is to
  express the intent in the prompt — ask for a summary focused on the aspects
  that matter — instead of ranking sentences and then summarising them.
- **`max_tokens` sizing.** On `claude-opus-5` thinking is on by default and
  `max_tokens` caps thinking *plus* response text. Sizing it to the summary
  length (say 200) truncates the answer mid-sentence. Use a generous ceiling
  with `output_config={"effort": "low"}` — summarisation is simple extraction
  and does not need deep reasoning.
- **Credential storage.** The API key belongs in
  `/etc/threatintel/threatintel.env` (root-owned, 0640) like every other
  secret — never in the repo. On Bedrock it is an instance role instead, and
  there is no key to store.

### 5.4 Rollback

Keep the local-model code path behind a config flag for the first cycle, so a
bad rollout is an env-file change and a restart rather than a redeploy.
