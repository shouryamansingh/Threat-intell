# UAT Execution Prompt — Weekly Cyber Watch (Threat Intel)

> Copy everything below the line into a fresh agent session that has browser
> control (Claude in Chrome / cloud browser extension) plus shell and file access
> to this repository.

---

## ROLE

You are a **senior UAT engineer and application QA analyst**. You are performing a
complete User Acceptance Test of the *Weekly Cyber Watch* threat-intelligence
platform, driving the real application in a real browser.

You are validating **whether the business workflow works for the people who use
it** — a SOC analyst, an approving manager, and an administrator. "The page
returned 200" is not a test result. A test passes only when you have observed the
user-visible outcome **and** confirmed the underlying state change (database row,
log line, email received, scheduler job).

---

## 1. SYSTEM UNDER TEST

Two Flask processes, one SQLite database, one SMTP account, Firebase for sign-in.

| Process | Port | Role |
|---|---|---|
| `web_dashboard.py` | 5001 | dashboard, admin panel, users & access, **and the APScheduler instance** |
| `callback_server.py` | 5000 | Approve / Reject / Validate endpoints clicked from email links |

**Business workflow being validated end to end:**

```
scrape sources → score & summarise → store (status=pending)
      → approval email to MANAGER_EMAIL (APPROVE / REJECT buttons)
      → manager clicks (callback :5000, HMAC token required)
      → sender validation step (validate_approve / validate_reject_form)
      → row queued in soc_deliveries (status=pending)
      → delivery poller claims it atomically every 30s → SOC email sent
```

**Pages (port 5001):** `/login` · `/setup-profile` · `/` (dashboard: Overview,
News, Scraping History, Schedule, Reports, Analytics tabs) · `/admin` (settings)
· `/admin/users` (Users & access, audit log) · `/settings` (My account) ·
`/healthz` (public) · `/api/health?deep=1` (admin only)

**Callback endpoints (port 5000):** `/` · `/approve/<article_id>?token=` ·
`/reject/<article_id>?token=` · `/validate_approve/<id>?token=` ·
`/validate_approve_process/<id>` · `/validate_reject_form/<id>?token=` ·
`/validate_reject_with_remarks/<id>` · `/status` · `/health`

**Roles** (`rbac.py`, lowest → highest):

| Role | Label | Can |
|---|---|---|
| `viewer` | Dashboard Viewer | view dashboard, news, reports, analytics — **no actions** |
| `analyst_admin` | Analyst + Admin | all operations (scrape, curate, send, deliveries) **+ `/admin` settings**; **cannot** manage users |
| `admin` | Admin | everything, including users, roles, and full project reset |

`config.BOOTSTRAP_SUPER_ADMINS` is always treated as `admin` and must never be
demotable. Unknown/legacy roles must fail **safe** to `viewer`.

**Identity paths that all must be tested:** Google sign-in (Firebase) · local
email+password accounts created by an admin · self-service *request access* for
non-allowlisted addresses · allow-listed domain auto-onboarding to `viewer` ·
optional password set from *My Account* after approval.

**Config precedence:** `TI_*` environment variables in `.env` **override**
`admin_settings.json`. A field pinned by an env var must render in `/admin` as
**locked** with a reason, not silently accept an edit. Secret settings are
encrypted at rest in `admin_settings.json`.

---

## 2. HARD GUARDRAILS — READ BEFORE TOUCHING ANYTHING

1. **This application sends real email to real people.** The delivery poller goes
   live the moment the dashboard starts, and `MANAGER_EMAIL` / `SOC_EMAIL` /
   `SOC_EMAIL_CC` currently resolve from `admin_settings.json`. **Before you start
   the app**, repoint every recipient field to mailboxes you control, and show me
   the before/after values for confirmation. Do not send a single message to an
   address you have not confirmed with me.
2. **Ask me before the first action that transmits email** — `/api/send_to_manager`,
   `/api/admin/test-email`, `/api/trigger-delivery`, `/api/delivery/<id>/send-now`,
   any scrape that auto-mails. State exactly who will receive what.
3. **Never run two dashboard workers.** A second one duplicates every scheduled
   job and every email. Verify only one process is bound to 5001 before and after
   any restart.
4. **`/api/admin/refresh-everything` wipes articles and workflow state.** Treat it
   as the final destructive test, run only with my explicit approval, after
   backing up `threat_intel.db` (+ `-wal`, `-shm`).
5. **Deletions must be reversible.** Use `trash` (macOS Trash), never `rm`. This
   applies to DB copies, logs, and generated reports.
6. **Do not commit, push, or stage anything.** `.env`, `admin_settings.json`,
   `.flask_secret_key` and `threat_intel.db` carry live credentials and personal
   data. Never paste their contents into your report — reference key names only.
7. **The dashboard does not auto-reload.** `callback_server.py` reloads on edit;
   `web_dashboard.py` does not. If you change any email-link or template code,
   restart 5001 or you will test stale behaviour (tokenless links being the
   classic symptom).
8. **Network caveat:** this machine's VPN blocks `feeds.feedburner.com` (errno 49).
   A feed failure is not automatically a defect — run `python health_checks.py`
   first and classify feed errors against its output.
9. Redact tokens, session cookies, app passwords and real recipient addresses in
   every screenshot and log excerpt you attach.

---

## 3. PRE-FLIGHT (do this first, report before testing)

```bash
python health_checks.py --json          # deps, config, DB, feeds, SMTP, disk
python health_checks.py --smtp-login    # credential check, sends NO email
python -m pytest tests/ -q              # existing regression baseline
python check_secrets.py                 # publishability guard
cp threat_intel.db "<scratch>/threat_intel.db.uat-baseline"
```

Then:

- Record baseline row counts: articles by status, `soc_deliveries` by status,
  users, access requests, audit entries. Every later assertion is a **delta**
  against this baseline.
- Confirm `TI_TIMEZONE` (`Asia/Kolkata`) and that displayed schedule times match
  it, not UTC.
- Confirm `TI_PUBLIC_BASE_URL` — if it points at localhost, email buttons will
  resolve in *your* browser only; note this as an environment condition affecting
  UAT-E realism.
- Start the app (`python run.py`) and confirm exactly one listener each on 5001
  and 5000.
- Prepare your account matrix and tell me which accounts you need me to create or
  approve:

| Test account | Purpose |
|---|---|
| A1 | `admin` (bootstrap) — full control |
| A2 | `analyst_admin` — operations + settings, no user management |
| A3 | `viewer` — read-only |
| A4 | local email+password account created by A1 |
| A5 | fresh Google identity on an **allow-listed** domain (auto-onboard path) |
| A6 | fresh Google identity on a **non-allow-listed** domain (request-access path) |

If any account cannot be created, say so and mark the dependent tests **BLOCKED**
— never simulate or assume the result.

---

## 4. HOW TO TEST (execution rules)

- Drive the UI as a user would: click, type, tab, wait for the real response.
  Use the API directly **only** to test authorization (a `viewer` session hitting
  a privileged endpoint must be refused) or to verify a response body.
- For every test case capture: **URL**, the action, a **screenshot** of the
  outcome, relevant **network status codes**, **browser console errors**, and the
  corroborating **DB row / log line / received email**.
- Keep the browser console and `logs/` open throughout. A silent JS error on a
  page that "looks fine" is a defect.
- Check **both light and dark theme** (there is a theme toggle) and three
  viewports: 390×844 (mobile), 820×1180 (tablet), 1440×900 (desktop).
- Test the **unhappy path** for every form: empty, whitespace-only, over-length,
  wrong type, duplicate, injection-shaped input (`<script>`, `' OR 1=1--`,
  `{{7*7}}`), and Unicode/emoji. Assert the app rejects with a **clear
  user-facing message** — not a 500, not a silent no-op.
- After each state-changing action, reload the page and confirm the change
  **persisted** (not just optimistic UI).
- Concurrency matters here: verify the send-once guarantee by racing two
  send-now / two approve clicks and confirming exactly one email.
- If something is ambiguous (intended behaviour unclear), record it as an
  **OBSERVATION / question for the product owner**, not a pass and not a bug.

---

## 5. TEST SUITES

Execute all of them. Give every case an ID, a verdict
(**PASS / FAIL / BLOCKED / N-A**), and evidence.

### UAT-A · Authentication & onboarding
A1 Google sign-in happy path → lands on dashboard, session persists across reload.
A2 Non-allow-listed Google identity → *request access* filed, no access granted,
admin notified in-app + by email, pending count increments.
A3 Allow-listed domain first sign-in → onboarded as `viewer` only (never a
privileged role), admin notified.
A4 `/setup-profile` enforcement — an unfinished profile cannot bypass it by
deep-linking to `/`.
A5 Local email+password login (admin-created account) succeeds.
A6 Wrong password → clear message, no user enumeration difference between
"unknown email" and "wrong password" beyond what the product intends (flag if it
leaks account existence).
A7 Email with no password set → the guidance message about signing in with
Google first is shown, not a generic failure.
A8 Rate limiting / lockout: `TI_LOGIN_FAIL_MAX=8` in a 900s window → lockout for
900s. Verify the counter, the lockout, the message, and that it clears.
A9 Logout clears the session; back-button and cached page do not expose data;
protected deep link redirects to `/login` and returns you to the target after
sign-in.
A10 Session cookie attributes (HttpOnly, Secure where applicable, SameSite) and
behaviour after a server restart.
A11 Disabled account (`active=0`) cannot sign in; a deleted account's live
session is refused on next request.

### UAT-B · RBAC / authorization
B1 Build the full **role × capability matrix** and verify it against
`rbac.ROLE_CAPABILITIES` as the *Users & access* page renders it — the page must
not claim a permission the routes don't enforce.
B2 As `viewer`: every action control hidden or disabled, and — critically —
direct calls to `/api/fresh_scraping`, `/api/send_to_manager`,
`/api/trigger-delivery`, `/api/admin/settings` (POST),
`/api/admin/refresh-everything`, `/api/admin/users` are **refused server-side**.
B3 As `analyst_admin`: operations and `/admin` settings work; `/admin/users` and
every `/api/admin/users*` route is refused.
B4 Role change takes effect **immediately, without sign-out** (the page claims
this) — verify with an open session in a second browser profile.
B5 Bootstrap super-admin cannot be demoted, disabled, or deleted.
B6 Self-service guards: cannot delete your own account; cannot escalate your own
role.
B7 Audit log is gated on the Admin role **and** a Google-verified identity — a
local password account with `admin` must not see it.

### UAT-C · Dashboard data integrity
C1 Every tab renders: Overview, News, Scraping History, Schedule, Reports,
Analytics. No console errors, no `undefined`/`NaN`/`null` in the UI.
C2 Overview counters equal the DB (`SELECT status, COUNT(*) ...`).
C3 News filters (All / Pending / Approved / Rejected) return exactly the matching
sets; counts sum to the total.
C4 Article detail view: title, source, score, summary, link — the external link
opens the real article; long titles and missing fields degrade gracefully.
C5 Analytics figures reconcile with the article and delivery tables.
C6 Activity log / system log ordering, timezone (Asia/Kolkata), pagination.
C7 Empty states: with zero articles, every tab shows a purposeful empty state,
not a broken table.
C8 Live updates (Socket.IO): trigger an event in one browser, confirm the other
updates without a manual refresh.

### UAT-D · Scraping
D1 Fresh scrape from the UI: progress is visible, the button state changes, the
session appears in Scraping History.
D2 **Stop** mid-scrape actually halts it (both the ✕ and the Stop button), and
leaves consistent state — no half-written session.
D3 Per-source outcomes surface individually; a blocked feed (see the feedburner
caveat) is reported as a source failure, not a silent zero.
D4 7-day freshness filter: no undated or stale articles enter the set.
D5 Deduplication across a second consecutive scrape.
D6 Scoring: high-priority regulatory/payments keywords (SEBI, RBI, NPCI, UPI,
RTGS, NEFT, CVE…) rank above generic items; ordering in the UI matches the score.
D7 Delete a scraping session → gone from UI and DB, with no orphaned articles or
deliveries left behind.
D8 Concurrency: two scrape starts in quick succession must not run two scrapes.

### UAT-E · Approval email → callback (the core workflow)
E1 *Send to manager*: email arrives at the confirmed test mailbox, renders in a
real mail client, respects `MAX_NEWS_TO_MANAGER`, and carries the configured
subject and company name.
E2 Every article row's APPROVE and REJECT buttons carry an absolute URL built
from `TI_PUBLIC_BASE_URL` and a token; no localhost leakage when the base URL is
set.
E3 Click APPROVE → success page, DB decision recorded, dashboard status flips to
approved, audit/log entry written.
E4 Click REJECT → rejection recorded, article does not proceed downstream.
E5 **Token security** (each must be refused with the "link expired or invalid"
page and a warning logged, with **no** state change):
  E5a token removed · E5b token altered by one character · E5c token from a
  *different* article replayed on this one · E5d token minted for `reject` used on
  `/approve` · E5e a tampered `article_id` with a valid-looking token.
E6 Idempotency / replay: clicking a valid APPROVE link twice must not double-count,
double-queue, or send two emails.
E7 A nonexistent or deleted article id → graceful message, no traceback, no 500.
E8 The whole flow works in a **different browser profile with no dashboard
session** — email recipients are not logged in.

### UAT-F · Sender validation
F1 `/validate_approve/<id>` renders and its confirm action completes; the
"Try again" path works after a simulated failure.
F2 `/validate_reject_form/<id>`: remarks required where the UI says so, remarks
persist to the DB, and are visible afterwards in the dashboard.
F3 Remarks are **HTML-escaped** on every surface they are re-rendered (page,
dashboard, report, email) — test with `<img src=x onerror=alert(1)>`.
F4 Legacy `/validate_reject/<id>` still redirects to the remarks form **carrying
the token**.
F5 An article approved by the manager but not sender-validated must **not** reach
the SOC.

### UAT-G · SOC delivery & scheduling
G1 Schedule a delivery from the UI → row created with the right time in
`TI_TIMEZONE`, shown correctly in the Schedule tab and in `/api/schedule-info`.
G2 The 30s poller claims a due row and sends exactly once; watch the atomic-claim
log lines.
G3 **Send now** on a pending delivery sends once; a second click (or a
simultaneous poller tick) is refused as already claimed. This is the single most
important defect class in this app — prove it.
G4 Cancel a scheduled delivery → no email is ever sent.
G5 Reschedule → old time no longer fires, new time does; the job list reflects it.
G6 SOC email content: `MAX_NEWS_PER_SOC_EMAIL` respected, report formatting
intact (headings, links, severities), attachments open, CC list honoured, subject
per config.
G7 A send failure (e.g. temporarily wrong SMTP password) → the claim is released
back to `pending`, the error is visible in the UI/log, and a retry succeeds. Restore
the credential afterwards and confirm.
G8 Delivery history and report list reflect what was actually sent.

### UAT-H · Admin settings panel (`/admin`)
H1 Every field type round-trips: email, email list (one per row), text, int,
weekday, weekday list, password.
H2 Env-pinned fields render **locked** with the reason, cannot be edited, and
show the live effective value.
H3 Saving with the password box **blank leaves the stored password unchanged**;
typing a new one replaces it; the hint says so; the value is never echoed back to
the browser in `/api/admin/settings` (inspect the JSON).
H4 *Reveal* requires the proper role and returns the real value only to it.
H5 Secrets are **encrypted at rest** — read `admin_settings.json` and confirm no
plaintext app password; confirm the app still decrypts them on load.
H6 Invalid inputs rejected with a message: port `abc` / `70000`, hour `25`,
minute `-1`, malformed email, unknown weekday, empty required field.
H7 Changing the scraping or delivery schedule updates the **next run time**
shown by the scheduler (cross-check `/api/scheduled-jobs`).
H8 Gmail app password pasted as `xxxx xxxx xxxx xxxx` is accepted (whitespace
stripped).
H9 *Test email*: success path; then deliberately wrong password → the panel
reports an SMTP **auth** failure with a useful message, not a stack trace; then
unreachable SMTP host → **connect** error; then bad recipient → **recipient**
error. Restore working values and re-verify.
H10 A crash-safe save: `admin_settings.json` is written atomically (temp+rename)
with `0600` perms — confirm perms after a save.
H11 Storage & cache panel: stats are accurate; *clear cache* works and the app
still functions afterwards.

### UAT-I · Users & access (`/admin/users`)
I1 Roster shows every account with correct role chip, active state, and provider.
I2 Add a local account → it can sign in; password reset by admin works.
I3 Disable / enable an account, with the effect on an active session.
I4 Delete an account → removed everywhere; own-account delete blocked.
I5 Access request **approve** → the requester can sign in with the granted role,
and is notified; **reject** with a note → still no access, note recorded.
I6 Pending-request count and its alert styling track reality.
I7 Audit log: Activity and Decisions views, correct attribution, timestamps in
`TI_TIMEZONE`, and the verified-identity gate from B7.
I8 Role permission table on the page matches actual enforcement (ties back to B1).

### UAT-J · My Account (`/settings`)
J1 Update display name, department, phone, notification email → persists, and the
display name propagates to the header/sidebar.
J2 Sign-in email is read-only and enforced server-side (attempt to change it via
the API must fail).
J3 *Discard changes* restores the form; the save button's dirty-state logic is
correct.
J4 Set a password as a Google-approved user, then sign in with it; change it with
the correct current password; wrong current password is refused; mismatched
confirmation is refused; weak/short password handling.
J5 Self-service password reset path.
J6 Sign out from this page ends the session everywhere it should.

### UAT-K · Health & observability
K1 `/healthz` is public and cheap; `/api/health?deep=1` requires admin and
returns the full picture.
K2 The startup health check and its ~6-hourly repeat appear in the dashboard
system log.
K3 Callback server `/health` and `/status` are accurate.
K4 Logs land in `TI_LOG_DIR`, rotate per `TI_LOG_MAX_MB`/`TI_LOG_BACKUPS`, and
contain no plaintext credentials.
K5 Every failure you induced during UAT produced a **diagnosable** log line.

### UAT-L · Non-functional
**L-SEC** Secrets absent from HTML/JS/network payloads (Firebase web config is
expected — confirm nothing else). IDOR on `/api/scraping-session/<id>`,
`/api/delivery/<id>/*`, `/api/admin/users/<uid>/*` using a lower-privileged
session. Stored/reflected XSS via display name, remarks, article titles, settings
strings. Missing-auth checks on every `/api/*` route (enumerate them from
`web_dashboard.py` and confirm each has a decorator). Session fixation after
privilege change. Sensitive data in URLs and in browser history.
**L-UX** Keyboard-only traversal of each page, visible focus, `aria-label`
correctness, modal focus trapping and Esc, screen-reader labelling of icon
buttons, colour contrast in both themes, no layout shift, error messages that say
what to do next.
**L-RESP** All three viewports: sidebar collapse, tables scroll rather than
overflow, no clipped controls, touch target sizes.
**L-PERF** Page load and API latency for dashboard, News with a large set,
Analytics; note anything over ~2s and whether the UI shows a loading state.
**L-RESIL** Restart the dashboard mid-workflow → no lost or duplicated delivery.
Kill the callback server and click an email link → sane browser-level failure.
Take the network down mid-scrape → clean error surface and recoverable state.
Malformed/oversized request bodies to a few POST endpoints → 4xx, not 500.

### UAT-M · Regression & teardown
M1 Re-run `pytest tests/ -q` and `check_secrets.py` after your changes — both
must be as green as the baseline.
M2 Restore every setting you altered (recipients, SMTP, schedule) and prove the
restored config is live.
M3 Report your DB deltas against the baseline snapshot.
M4 Only if I approve: full-reset test via *Refresh Project*, then verify the app
comes back to a clean, usable state. Otherwise mark **NOT EXECUTED**.

---

## 6. DEFECT REPORTING FORMAT

One entry per defect, in the report and nowhere else duplicated:

```
DEF-001 · <one-line title>
Severity   : Critical | High | Medium | Low | Cosmetic
Suite/Case : UAT-G3
Role       : analyst_admin
Environment: dashboard :5001 / callback :5000 / Chrome 1440×900 / dark theme
Steps      : 1. … 2. … 3. …
Expected   : <the business behaviour a user would expect>
Actual     : <what happened, verbatim message / status code>
Evidence   : screenshot(s), log excerpt, DB query + result, network response
Impact     : <who is harmed and how — e.g. "SOC receives the digest twice">
Suspected  : file.py:line (only if you actually traced it)
Workaround : <if any>
Reproduced : n of m attempts
```

**Severity definitions for this app:**
- **Critical** — data loss, duplicate or wrong-recipient email, auth bypass,
  privilege escalation, a forged token accepted, the workflow unable to complete.
- **High** — a core step unusable, a state change silently lost, a role able to do
  what its label forbids, secrets exposed.
- **Medium** — workaround exists; misleading message; wrong count or timezone.
- **Low / Cosmetic** — layout, wording, polish.

---

## 7. EXIT CRITERIA & SIGN-OFF

Recommend **GO** only if all of the following hold:
- 100% of UAT-A, UAT-B, UAT-E, UAT-G cases executed, zero Critical, zero High.
- The full workflow completed at least once end to end — scrape → approval email
  → manager click → sender validation → SOC delivery — with the SOC email
  received and correct.
- Every token-security case in E5 refused.
- Send-once proven under a race (G3).
- No secret exposed in any response, log, or screenshot.
- Regression suite and `check_secrets.py` green.

Otherwise recommend **NO-GO** or **CONDITIONAL GO**, and state precisely which
defects gate release.

---

## 8. DELIVERABLES

1. **Executive summary** — go / no-go, one paragraph a non-engineer can act on,
   the top 3 risks.
2. **Traceability matrix** — every case ID → verdict → evidence reference.
   BLOCKED and NOT EXECUTED must be listed explicitly with the reason; never
   omit a case to make the sheet look complete.
3. **Defect register** — sorted by severity, in the format above.
4. **Observations / product questions** — behaviour that may be intentional but
   reads wrong to a user.
5. **Evidence folder** — screenshots named `<case-id>-<short>.png`, with secrets
   redacted, plus the log excerpts you cite.
6. **Environment record** — commit hash, config values (names + non-secret
   values only), test accounts used, what you changed and what you restored.
7. **Coverage honesty statement** — what you could not test and why.

---

## 9. RULES OF ENGAGEMENT

- **Stop and ask me** before: any email-sending action, any user deletion, the
  project reset, any change to `.env`, and anything you judge irreversible.
- Report progress after each suite — do not go dark for the whole run.
- Never mark a case PASS you did not actually observe. "Could not verify" is a
  perfectly acceptable, and far more valuable, result.
- If you fix something while testing, say so explicitly and separately from the
  test results — a UAT report must reflect the build as delivered.
