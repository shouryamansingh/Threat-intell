# Split deployment: app on Lightsail, models on EC2

Runs the dashboard, callback server, scheduler and database on a small Lightsail
instance, and the two HuggingFace models on a separate EC2 instance. They talk
over a private AWS network link.

`DEPLOY.md` remains the authority for everything about the application box
itself — users, nginx, TLS, database migration, backups, Firebase. This file
covers only what is *different* when the models live elsewhere. Read §1–§2 here,
then do `DEPLOY.md` for the app box, then come back for §5–§7.

For the single-box alternative — which is the recommended deployment — see
`LIGHTSAIL.md`. Read §8 of this file before choosing: the split is not
automatically cheaper.

---

## 1. What runs where

```
   ┌─────────────────────────────┐         ┌──────────────────────────────┐
   │ Lightsail  2 GB             │         │ EC2  m6i.large  8 GB         │
   │ ───────────────────────     │         │ ────────────────────────     │
   │ nginx + TLS                 │         │ inference_server.py          │
   │ threatintel-dashboard       │ ──HTTP─▶│   POST /summarize            │
   │ threatintel-callback        │  :5002  │   POST /rank                 │
   │ APScheduler (weekly scrape) │ private │   GET  /health               │
   │ threat_intel.db  (SQLite)   │◀────────│                              │
   │ SMTP, Firebase, secrets     │         │ bart-large-cnn   ~1.6 GB     │
   │                             │         │ all-MiniLM-L6-v2 ~0.1 GB     │
   │ NO torch                    │         │ NO database, NO credentials  │
   └─────────────────────────────┘         └──────────────────────────────┘
        public: 443 only                        public: nothing
```

Two properties worth keeping true as this evolves:

**The inference box holds no secrets and no data.** `inference_server.py` imports
neither `config.py` nor `database.py`. Its environment file contains a bearer
token, a bind address and `HF_HOME` — no SMTP password, no Firebase key, no
database path. A compromise there yields a news-article summariser.

**Article parsing stays on the app box.** `clean_article_content` and
`extract_meaningful_sentences` are BeautifulSoup and regex; they need no models
and they carry the report-quality tuning. Only already-cleaned text and candidate
sentence lists cross the wire. Changing summarisation *logic* therefore never
means redeploying the model box.

---

## 2. Why these sizes

**EC2 — 8 GB, and not burstable.** `LIGHTSAIL.md` §1 measured the
model-holding process at 3.5–4.5 GB peak RSS. Removing the Flask app from that
process saves a few hundred MB, not gigabytes: the weights dominate. With OS
overhead that is ~5 GB, so `t3.medium` (4 GB) still OOM-kills mid-scrape.

The plan's argument against burstable instances now applies to *this* box: a
batch of summaries is 10–30 minutes of sustained CPU, which is exactly what
drains T-family credits. Use `m6i.large`, or `m6a.large` (AMD, same specs,
slightly cheaper, runs torch identically).

**Lightsail — 2 GB is enough, and burstable is now fine.** Without torch the app
box runs the dashboard (~300–500 MB), two lean callback workers (~200 MB each)
and the OS (~500–700 MB) — about 1.2 GB. The 2 GB plan fits; the 4 GB plan buys
headroom for SQLite page cache if the database grows.

This is the real structural win of the split: the sustained-CPU work that made
Lightsail's burst model risky has moved to EC2. What remains on Lightsail is
request/response work and a scheduler that mostly sleeps.

---

## 3. Network: Lightsail VPC peering

Lightsail instances live in their own AWS-managed VPC, separate from EC2. Peering
joins the two so they can reach each other by private IP, with nothing exposed
publicly.

1. Lightsail console → **Account** (top right) → **Advanced** tab.
2. Find your region → tick **Enable VPC peering**.
3. Note the Lightsail VPC CIDR it reports (commonly `172.26.0.0/16`, but read the
   actual value — you need it for the security group in §4).

**Two constraints that decide whether this works for you:**

- Peering attaches to the **default VPC** of that region only. If your EC2
  instance is in a custom VPC, peering will not reach it — either launch the
  model box in the default VPC, or use the fallback in §9.
- Both must be in the **same region**. Put the Lightsail instance and the EC2
  instance in the same region as each other (and ideally near your users).

---

## 4. Build the model box (EC2)

EC2 console → **Launch an instance**: name `threatintel-models`, AMI **Ubuntu
24.04 LTS x86_64**, type **`m6i.large`** (or `m6a.large` — AMD, same specs,
slightly cheaper, runs torch identically), **30 GB gp3** root volume, **in the
region's default VPC** (§3 explains why), and an ED25519 `.pem` key pair. No
public HTTP/HTTPS rules — the security group below is the whole ingress story.

Avoid `c6i.large`: compute-optimised means 2 GB per vCPU, so it is only 4 GB and
will OOM. Avoid Graviton/ARM (`m7g`, `t4g`) here — `requirements-inference.txt`
pins `torch==2.9.0` and the aarch64 wheel story is an avoidable variable.

**Security group — the only inbound rule:**

| Type | Protocol | Port | Source |
|---|---|---|---|
| Custom TCP | TCP | 5002 | the Lightsail VPC CIDR from §3 |
| SSH | TCP | 22 | your admin IP only |

Do not open 5002 to `0.0.0.0/0`. The bearer token is the only authentication the
service has.

Then on the box:

```bash
# Service account and directories, matching DEPLOY.md's layout
sudo useradd --system --home /opt/threatintel --shell /usr/sbin/nologin threatintel
sudo mkdir -p /opt/threatintel /var/lib/threatintel /etc/threatintel
sudo chown threatintel:threatintel /opt/threatintel /var/lib/threatintel

# Code. The whole repo is fine — only inference_server.py is used here.
sudo -u threatintel git clone https://github.com/<you>/Threat-INTEL.git /opt/threatintel
cd /opt/threatintel
sudo -u threatintel python3 -m venv .venv

# NOTE: requirements-inference.txt, not requirements.txt. ~2.5 GB of wheels.
sudo -u threatintel .venv/bin/pip install -r requirements-inference.txt
```

**Environment file.** Generate the token here and keep it — the app box needs the
same value in §5.

```bash
openssl rand -hex 32          # copy this

sudo tee /etc/threatintel/inference.env >/dev/null <<'EOF'
TI_INFERENCE_TOKEN=<paste the token>
TI_INFERENCE_BIND_HOST=0.0.0.0
TI_INFERENCE_PORT=5002
HF_HOME=/var/lib/threatintel/huggingface
EOF
sudo chown root:threatintel /etc/threatintel/inference.env
sudo chmod 0640 /etc/threatintel/inference.env
```

`TI_INFERENCE_BIND_HOST=0.0.0.0` is correct here — unlike the app box, nothing
proxies this service, so the security group is the boundary.

**Pre-warm the model cache before first start.** `HF_HOME` must be populated as
the service account with the same value set. Skipping this means the first start
downloads 1.7 GB while systemd waits, which looks like a hang; and if `HF_HOME`
is wrong, `ProtectSystem=strict` makes the download fail silently and the service
comes up permanently degraded.

```bash
sudo -u threatintel HF_HOME=/var/lib/threatintel/huggingface \
  /opt/threatintel/.venv/bin/python -c "
from transformers import pipeline
from sentence_transformers import SentenceTransformer
pipeline('summarization', model='facebook/bart-large-cnn')
SentenceTransformer('all-MiniLM-L6-v2')
print('cache warm')
"
```

**Start it:**

```bash
sudo cp /opt/threatintel/deploy/threatintel-inference.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threatintel-inference
journalctl -u threatintel-inference -f      # expect "summarizer ready", "ranker ready"
```

**Verify locally before involving the app box:**

```bash
TOKEN=$(sudo grep TI_INFERENCE_TOKEN /etc/threatintel/inference.env | cut -d= -f2)

curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5002/health
# {"models":{"ranker":true,"summarizer":true},"status":"ok"}

curl -s http://127.0.0.1:5002/health
# {"error":"unauthorized"}   <-- confirms the token is enforced
```

A `status: degraded` with `summarizer: false` means the model did not load — read
the journal, and check `HF_HOME` against the unit's `ReadWritePaths`.

Record the instance's **private IPv4 address** (`ip -4 addr show` or the console).

---

## 5. Build the app box (Lightsail)

Create the instance: **Linux/Unix → Ubuntu 24.04 LTS → 2 GB plan**, same region,
and attach a **static IP** (Networking tab) so the address survives a restart.

Firewall (Lightsail Networking tab): allow 22 from your IP, 80 and 443 from
anywhere. Nothing else.

Now follow **`DEPLOY.md` from §1 to the end** — it is unchanged and complete for
this box — with exactly two deviations:

**(a) Install the slim requirements:**

```bash
sudo -u threatintel .venv/bin/pip install -r requirements-app.txt
```

Not `requirements.txt`. This omits torch, transformers, sentence-transformers and
scikit-learn — the four packages the split exists to relocate.

**(b) Add the inference settings** to `/etc/threatintel/threatintel.env`, using
the EC2 **private** IP and the token from §4:

```bash
TI_INFERENCE_URL=http://<ec2-private-ip>:5002
TI_INFERENCE_TOKEN=<the same token as the model box>
```

Leave `HF_HOME` out of this file — this box no longer downloads models.

Plain HTTP is deliberate: over the peering connection the traffic stays inside
AWS's network, and issuing certificates for an RFC1918 address buys little. The
startup check enforces the distinction — a non-private host without HTTPS is a
fatal misconfiguration in production, because the token would otherwise cross
the internet in clear text.

---

## 6. Verify the link

From the **app box**:

```bash
# 1. Peering works at all
ping -c2 <ec2-private-ip>

# 2. The service answers, with auth
source /etc/threatintel/threatintel.env
curl -s -H "Authorization: Bearer $TI_INFERENCE_TOKEN" \
     "$TI_INFERENCE_URL/health"
# expect {"models":{"ranker":true,"summarizer":true},"status":"ok"}

# 3. A real summary, end to end through the application's own code path
sudo -u threatintel /opt/threatintel/.venv/bin/python -c "
import os; os.chdir('/opt/threatintel')
from soc_report_formatter_enhanced import enhanced_soc_formatter as f
text = ('A critical flaw tracked as CVE-2026-0001 lets unauthenticated attackers '
        'run code on Acme VPN appliances. Acme shipped firmware 9.2.1 to fix it. '
        'Administrators should patch now and review session logs for anomalies.')
print(repr(f._ai_summarize_article(text)))
print(f._extract_relevant_sentences(text, 'how do I remediate this', top_k=2))
"
```

Step 3 returning a real sentence proves the whole chain. `None` means the call
failed and fell back — check `journalctl -u threatintel-inference` on the model
box and the security group source CIDR.

Then run the app's own preflight and start the services per `DEPLOY.md` §5:

```bash
sudo -u threatintel /opt/threatintel/.venv/bin/python health_checks.py
```

---

## 7. How failure behaves

The two model calls fail soft, by design, and that behaviour is load-bearing here
because the network can now fail where previously only a model load could.

- One failed call → that article gets a non-AI summary. The scrape continues.
- Three consecutive failures (`TI_INFERENCE_FAILURE_LIMIT`) → the app stops
  calling the service for 5 minutes (`TI_INFERENCE_COOLDOWN`), logs a WARNING to
  `system_logs`, then retries. Without this breaker a dead model box would turn a
  50-article scrape into 50 sequential 120-second timeouts — 100 minutes of
  waiting to produce exactly the output the fallback gives instantly.
- A success resets the counter.

So an inference box that is down degrades report quality and does not stop
delivery. Watch for it: `SELECT * FROM system_logs WHERE component='AI_FORMATTER'
AND level='WARNING'`, or grep the dashboard's activity log for "Inference service
unreachable".

Note that `_ai_available` is deliberately *not* flipped by a network error. That
flag means "models could not be loaded in this process" and is sticky for the
process lifetime — correct for a failed import, wrong for a transient blip that
would otherwise disable AI summaries until someone restarts the dashboard.

---

## 8. Cost: read this before committing

Approximate monthly, on-demand — **check current pricing for your region**:

| | 24/7 | Notes |
|---|---:|---|
| Lightsail 2 GB | ~$12 | includes static IP and bundled transfer |
| EC2 `m6i.large` | ~$70 | the models |
| 30 GB gp3 on EC2 | ~$2.40 | persists while the instance is stopped |
| **Split total** | **~$84** | |
| Single Lightsail 8 GB | ~$44 | `LIGHTSAIL.md` — one box, everything on it |

**Run both boxes 24/7 and the split costs more than the single box, for more
moving parts.** There is no way around that: the expensive component is the
8 GB instance, and the split does not remove it.

The split pays off only if the model box is not always on. The scrape is weekly,
so the models are idle ~99% of the time. Stop the EC2 instance between runs and
the compute bill tracks actual use:

| | approx. monthly |
|---|---:|
| Lightsail 2 GB, always on | ~$12 |
| EC2 `m6i.large`, ~4 h/week | ~$1.60 |
| 30 GB gp3, always allocated | ~$2.40 |
| **Total** | **~$16** |

Ways to schedule that, cheapest-effort first:

1. **Manually** — start the instance before a scrape, stop it after. Fine while
   you are still validating the setup.
2. **EventBridge Scheduler** — two cron rules calling `StartInstances` and
   `StopInstances`, aligned to the scrape window in your APScheduler config, with
   enough lead time for boot plus model load (allow 5 minutes).
3. **From the app** — `boto3` `start_instances` before the scrape, waiting on
   `/health`. Most precise, and the most code; needs an IAM role on the Lightsail
   box scoped to `ec2:StartInstances`/`StopInstances` on that one instance ARN.

Either way the circuit breaker in §7 is what keeps a not-yet-booted model box
from stalling a scrape.

**Worth knowing before you build any of this:** replacing these two local models
with a hosted API (`LIGHTSAIL.md` §12) removes the 8 GB instance entirely rather
than scheduling around it — the app then fits the same 2 GB Lightsail box for
~$12/month plus a few dollars of API usage, with one box to operate instead of
two. This split is the right build if you need the models to stay on
infrastructure you control. If you don't, do §12 of that guide instead.

---

## 9. Fallback: no VPC peering

If the model box cannot be in the region's default VPC, or must be in another
region, replace §3 with a public endpoint — and harden it, because it is then
reachable from the internet:

1. Security group inbound 5002 restricted to the Lightsail **static IP** as a
   `/32`. This is the primary control; do not skip it.
2. Terminate TLS in front of the service — nginx with a real certificate on the
   model box, proxying to `127.0.0.1:5002`. Set
   `TI_INFERENCE_BIND_HOST=127.0.0.1` so gunicorn stops listening publicly.
3. `TI_INFERENCE_URL=https://<hostname>:443`. The startup check requires HTTPS
   for any non-private host, so a plain-HTTP public URL refuses to start in
   production.
4. Rotate `TI_INFERENCE_TOKEN` on a schedule — update both boxes and restart both
   services.

Cross-region additionally means paying inter-region data transfer and adding
latency to every summary. Prefer same-region peering.
