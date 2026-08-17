# Deploying to AWS Lightsail (single box)

Everything — dashboard, callback server, scheduler, database and both AI models
— on one Lightsail instance. This is the recommended deployment.

`DEPLOY.md` is the authority for everything from "you have a server" to "it
works". This file gets you the server, covers the model-specific setup
`DEPLOY.md` doesn't, then hands off. Don't duplicate `DEPLOY.md`'s steps here —
fix them there.

For the two-box alternative (app on Lightsail, models on a separate EC2
instance) see `SPLIT-DEPLOYMENT.md`. Read §8 of that file before choosing: it is
only cheaper if you stop the model box between scrapes.

---

## 1. Sizing — driven by the models, not the web app

The Flask app is trivial to host. The sizing is entirely about
`facebook/bart-large-cnn` sitting resident in RAM.

| | Value |
|---|---|
| Plan | **8 GB RAM / 2 vCPU / 160 GB SSD** |
| Blueprint | **Ubuntu 24.04 LTS** |
| Approx. cost | ~$44/month — *check current pricing for your region* |

**Why 8 GB and not 4.** Only the dashboard process holds the models —
`callback_server.py` imports just Flask, `database`, `link_tokens` and `config`,
so its two gunicorn workers stay light. Measured budget:

| Process | Holds | Peak RSS |
|---|---|---|
| `threatintel-dashboard` (1 worker) | torch + BART + MiniLM | ~3.5–4.5 GB |
| `threatintel-callback` (2 workers) | Flask only, no torch | ~200 MB each |
| Ubuntu + nginx | — | ~500–700 MB |
| **Peak total** | | **~5–6 GB** |

The 4 GB plan sits under peak and the kernel will OOM-kill the dashboard
mid-scrape. Because the scheduler lives inside that process, the weekly scrape
and the delivery poller die with it.

**On burstable CPU.** Lightsail vCPUs are burstable, and summarising a batch is
10–30 minutes of sustained CPU — normally an argument against burstable
instances. It is a weak argument here: the scrape is weekly, so the instance
banks burst capacity for ~6.9 days out of 7 and has a full allowance when the
job fires. Worst case it throttles and the scrape runs slow, not broken. Watch
the first full cycle; if it does throttle, the fix is §10, not a bigger plan.

**Blueprint: choose Ubuntu, not Amazon Linux.** `DEPLOY.md` is written for
Debian-family paths and tooling throughout — `apt`, `/usr/sbin/nologin` in the
`useradd` call, and nginx's `sites-available`/`sites-enabled` layout. Pick
Ubuntu 24.04 LTS under **Linux/Unix → OS Only** and the guide works verbatim.

Do **not** use Lightsail Containers: the filesystem is ephemeral, so
`threat_intel.db` would be destroyed on every deploy, and there is no persistent
process to hold the APScheduler singleton.

---

## 2. Create the instance

Lightsail console → **Create instance**:

1. **Region** — pick one near your users. Everything stays in this region.
2. **Platform** — Linux/Unix. **Blueprint** — OS Only → **Ubuntu 24.04 LTS**.
3. **Plan** — the **8 GB / 2 vCPU / 160 GB** tier.
4. **Name** — `threatintel-prod`.
5. Create.

Then two things in the **Networking** tab of the instance:

**Static IP** — *Attach static IP*. Without it the public IP changes on every
stop/start, which breaks `TI_PUBLIC_BASE_URL` and every approval link already
sitting in an inbox. It is free while attached to a running instance.

**Firewall** — Lightsail uses its own firewall, not EC2 security groups. Inbound
rules, and nothing else:

| Application | Port | Restricted to |
|---|---|---|
| SSH | 22 | your admin IP only |
| HTTPS | 443 | office/VPN range |
| HTTP | 80 | office/VPN range (for the TLS redirect) |

Do **not** open 5000 or 5001. Both apps bind to `127.0.0.1` and nginx proxies to
them; exposing those ports would bypass TLS entirely.

Point your DNS name at the static IP now — the certificate in `DEPLOY.md` §6
needs the name resolving first.

### SSH access

Download the default key from **Account → SSH keys**, then:

```bash
mkdir -p ~/.ssh
mv ~/Downloads/LightsailDefaultKey-<region>.pem ~/.ssh/threatintel-prod.pem
chmod 400 ~/.ssh/threatintel-prod.pem
```

Optional `~/.ssh/config` entry, so `ssh threatintel` and `scp` just work — the
latter matters for `DEPLOY.md` §3b (brand SVGs) and §4 (database copy):

```
Host threatintel
    HostName <your-static-ip>
    User ubuntu
    IdentityFile ~/.ssh/threatintel-prod.pem
```

> **Login user is `ubuntu`, not `ec2-user`.** `DEPLOY.md`'s `scp`/`ssh` examples
> say `ec2-user@server`, which is the Amazon Linux convention. Substitute
> `ubuntu@` throughout.

### Sanity-check the instance before you start

Thirty seconds, and it catches a console mistake before an hour of setup:

```bash
free -h            # expect ~7.7Gi total  — if ~1.9Gi, wrong plan
df -h /            # expect ~155G         — if ~19G, wrong plan
nproc              # expect 2
lsb_release -ds    # expect Ubuntu 24.04
```

---

## 3. OS prerequisites

`DEPLOY.md` §2 goes straight to `python3 -m venv`, which fails on a bare Ubuntu
24.04 image because `python3-venv` is not installed. Also grab the `sqlite3` CLI
that §4 and §10 depend on, and nginx for §6:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv python3-dev build-essential \
                    sqlite3 nginx git
```

If `pip install` later tries to *build* lxml instead of using a wheel, add
`libxml2-dev libxslt1-dev`. It normally won't.

Python version is not a concern: the developer venv runs the full stack on
**Python 3.13**, and Ubuntu 24.04 ships 3.12, so every pin in `requirements.txt`
is satisfiable without change.

---

## 4. Cloning a private repository

The repository carries no credentials by design (see `GITHUB.md`), so it should
be **private** regardless. Give the server a **deploy key** — read-only, scoped
to this one repository, revocable — rather than putting a personal access token
on a server.

After creating the `threatintel` service account (`DEPLOY.md` §1) and before
cloning, generate the key **in `/etc/threatintel`, not in the service account's
home**. `git clone` refuses to write into a non-empty directory, so a `.ssh`
directory sitting inside `/opt/threatintel` would break the clone that follows.

```bash
sudo ssh-keygen -t ed25519 -N "" -C "threatintel-deploy" \
  -f /etc/threatintel/deploy_key
sudo chown threatintel:threatintel /etc/threatintel/deploy_key*
sudo chmod 600 /etc/threatintel/deploy_key
sudo cat /etc/threatintel/deploy_key.pub
```

Copy that public key into the GitHub repository → **Settings → Deploy keys →
Add deploy key**. Leave **Allow write access unchecked**.

Then clone over SSH instead of HTTPS in `DEPLOY.md` §2. Take the SSH URL from the
repository's green **Code** button → **SSH** tab (it begins `git@`, not
`https://`) and use it in place of that step's `<your-repo-url>`:

```bash
sudo -u threatintel env \
  GIT_SSH_COMMAND="ssh -i /etc/threatintel/deploy_key -o StrictHostKeyChecking=accept-new" \
  git clone <paste-the-SSH-url-here> /opt/threatintel
```

`StrictHostKeyChecking=accept-new` matters: without it the first connection stops
to ask whether to trust GitHub's host key, and under `sudo -u` there is no
terminal to answer on — the clone appears to hang.

Then pin the key into the repository's own config, so later `git pull`s (§10) do
not need the environment variable:

```bash
sudo -u threatintel git -C /opt/threatintel config \
  core.sshCommand "ssh -i /etc/threatintel/deploy_key"
```

> The SSH URL is described rather than spelled out because `check_secrets.py`
> reads `git@<host>` as an email address and blocks the push. It is a false
> positive, but the scanner is the gate.

---

## 5. The model cache must be redirected before first start

**This one will bite silently if skipped.** The `threatintel` service account is
created with `--home /opt/threatintel` (`DEPLOY.md` §1), so HuggingFace defaults
its cache to `/opt/threatintel/.cache/huggingface`. But both systemd units set
`ProtectSystem=strict` with
`ReadWritePaths=/var/lib/threatintel /var/log/threatintel` — so at runtime
`/opt/threatintel` is **read-only** and the model download cannot write its
cache.

The failure mode is quiet. `_get_summarizer()` catches the exception, logs a
warning, and sets `_ai_available = False` for the lifetime of the process
([soc_report_formatter_enhanced.py:64-67](../soc_report_formatter_enhanced.py#L64-L67)).
Reports keep generating with the non-AI fallback text. Nothing looks broken; the
summaries are just worse until someone restarts the service.

Fix it in two places. In `/etc/threatintel/threatintel.env`, alongside the other
`TI_*` settings:

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

---

## 6. Pre-warm the models

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

---

## 7. Hand off to DEPLOY.md

From here, work through [DEPLOY.md](DEPLOY.md) start to finish. It covers the
service account, directory layout, dependency install, the env file, the
database copy, systemd, nginx and TLS, egress requirements, Firebase authorised
domains, first login, and backups.

Install `requirements.txt` — **not** `requirements-app.txt`, which is for the
split deployment and omits the models.

Four Lightsail-specific substitutions as you go:

| `DEPLOY.md` says | On Lightsail |
|---|---|
| `ec2-user@server` | `ubuntu@server` |
| "security group inbound" (§7) | the Lightsail **Networking → Firewall** tab (§2 above) |
| "EBS snapshots" (§10) | Lightsail **Snapshots** tab — enable automatic daily |
| clone `<your-repo-url>` (§2) | the SSH URL + deploy key from §4 above |

And three insertions:

- **Before §2** — the OS prerequisites in §3 above.
- **In §3 (the env file)** — add the `HF_HOME` line from §5 above.
- **Between §2 and §5** — the pre-warm in §6 above, after the venv is built and
  before `systemctl enable --now`.

---

## 8. Before you start the services — it sends real email

Repeating `DEPLOY.md`'s warning because it is the easiest way to cause real
damage here. The moment `threatintel-dashboard` starts, the delivery poller is
live and will mail whoever `TI_SOC_EMAIL` names, external recipients included.

For the first run: point `TI_MANAGER_EMAIL` and `TI_SOC_EMAIL` at yourself, set
`ACCESS_REQUEST_EMAIL=0`, watch one full cycle, then switch to the real
recipients.

`health_checks.py` is safe to run at any time — it is read-only and stops at
STARTTLS without sending anything.

---

## 9. Checklist

- [ ] Instance created (8 GB plan, Ubuntu 24.04 LTS)
- [ ] Static IP attached
- [ ] Firewall: 22/443/80 only, scoped to admin and office ranges
- [ ] DNS name pointed at the static IP
- [ ] OS prerequisites installed (§3)
- [ ] Repository private; deploy key added, clone over SSH (§4)
- [ ] `HF_HOME` set in the env file **and** the directory created (§5)
- [ ] Models pre-warmed and cache verified at ~1.7 G (§6)
- [ ] `DEPLOY.md` §1–§10 complete
- [ ] `health_checks.py` passes on the server
- [ ] Recipients pointed at yourself for the first cycle (§8)
- [ ] One full cycle observed: scrape → email → **Approve clicked from another
      machine** → dashboard log updated live
- [ ] Real recipients restored
- [ ] Daily backup cron installed and one restore tested
- [ ] Lightsail automatic snapshots enabled

---

## 10. Deploying updates

The services run gunicorn without `--reload`, so **a `git pull` alone changes
nothing** — the old code keeps serving until you restart. Forgetting the restart
after editing email-link code is how tokenless approval links get sent.

```bash
sudo -u threatintel git -C /opt/threatintel pull
sudo -u threatintel /opt/threatintel/.venv/bin/pip install -r /opt/threatintel/requirements.txt
sudo systemctl restart threatintel-dashboard threatintel-callback
journalctl -u threatintel-dashboard -f
```

Restarting the dashboard restarts the scheduler with it. Confirm the next-run
times in the admin panel still match the panel's clock afterwards.

---

## 11. Things that will bite

| Symptom | Cause |
|---|---|
| AI summaries silently stop, fallback text everywhere | `HF_HOME` unset — cache unwritable under `ProtectSystem=strict` (§5). Restart clears it until the next process start. |
| First scrape after deploy hangs for minutes | Models not pre-warmed (§6). |
| Dashboard OOM-killed during a scrape | 4 GB plan instead of 8 GB (§1). |
| Approval links break after a stop/start | No static IP; `TI_PUBLIC_BASE_URL` now points at a dead address (§2). |
| Scrape gets progressively slower over months | Burst capacity exhausted (§1). Consider §12. |
| Code change deployed but nothing changed | `git pull` without a service restart (§10). |
| `git clone` fails with a permission error | Deploy key missing, or cloning the HTTPS URL instead of SSH (§4). |

`DEPLOY.md`'s own troubleshooting table covers the app-level failures — wrong
base URL, Firebase egress, timezone, double-send, locked database.

---

## 12. Later: shrinking to a 2 GB box

Not started. Do not begin until this deployment has run clean for at least one
full weekly cycle.

`torch` is never imported directly — it arrives via `transformers` and
`sentence-transformers`. `scikit-learn` appears once, at
[soc_report_formatter_enhanced.py:122](../soc_report_formatter_enhanced.py#L122),
inside the sentence-similarity helper. Replacing the two local models with a
hosted API removes **transformers, sentence-transformers, torch and
scikit-learn** — roughly 3 GB of dependencies and a 1.7 GB model download.

What's left is a plain Flask app: it fits the **2 GB Lightsail plan (~$12/month)**,
deploys in seconds, needs no warm-up, and §1, §5, §6 and the burst-capacity
concern all stop applying.

### Surface area

Small and well contained:

- `_ai_summarize_article`
  ([soc_report_formatter_enhanced.py:86](../soc_report_formatter_enhanced.py#L86))
  is the only summarisation entry point, called from exactly two places
  ([317](../soc_report_formatter_enhanced.py#L317) and
  [363](../soc_report_formatter_enhanced.py#L363)).
- `_get_summarizer` and `_get_sentence_model` (lines 57–84) get deleted.
- The four consumers — `web_dashboard.py`, `scheduler.py`, `email_system.py`,
  `sender_validation.py` — all import the `enhanced_soc_formatter` singleton and
  do not change.
- `soc_report_formatter.py` stays. It is not dead code: `scheduler.py` falls
  back to it at [scheduler.py:978](../scheduler.py#L978) when the enhanced
  formatter rejects low-quality content, and it uses no models.
- `tests/test_regression.py` constructs `EnhancedSOCReportFormatter` directly,
  so it needs a stub or a recorded fixture rather than live API calls.

The existing error handling already models an API outage correctly:
`_ai_summarize_article` returns `None` on any exception and callers fall through
to the non-AI path. That is what makes this low-risk.

### Open questions to settle first

- **Model and cost.** The current call truncates input to 2000 characters
  (~500 tokens) and asks for 130–250 characters back. At Claude Opus 5 rates
  ($5/$25 per million input/output tokens) that is roughly **$0.0075 per
  article** — about $23/month at 100 articles/day. Claude Sonnet 5 ($3/$15) and
  Claude Haiku 4.5 ($1/$5) are the cheaper tiers if volume makes that matter.
- **Which endpoint.** Three options, all Anthropic models: **Amazon Bedrock**
  keeps inference in-account with IAM auth and AWS billing (`anthropic.claude-opus-5`
  via the `AnthropicBedrockMantle` client); **Claude Platform on AWS** is
  Anthropic-operated with same-day API parity, SigV4 auth and Marketplace
  billing (bare `claude-opus-5` via `AnthropicAWS`); the **direct API** is one
  env var. Nothing this workload needs is missing from any of them.
- **The sentence-similarity step.** `all-MiniLM-L6-v2` ranks sentences by
  relevance before summarising. Keeping it keeps `sentence-transformers`, which
  keeps `torch`, which forfeits the entire benefit above. The replacement is to
  express the intent in the prompt — ask for a summary focused on the aspects
  that matter — instead of ranking sentences and then summarising them.
- **Credential storage.** The API key belongs in
  `/etc/threatintel/threatintel.env` (root-owned, 0640) like every other secret
  — never in the repo. On Bedrock or Claude Platform on AWS it is an instance
  role instead, and there is no key to store.

### Rollback

Keep the local-model code path behind a config flag for the first cycle, so a
bad rollout is an env-file change and a restart rather than a redeploy.
