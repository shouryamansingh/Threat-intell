# Publishing this repository safely

What was in the code before, and what protects it now.

## Run this before every push

```bash
python check_secrets.py
```

Exit code 0 means the files git would publish are clean. It checks two things
that `.gitignore` alone cannot:

1. **Is anything sensitive already tracked?** A `.gitignore` rule does nothing
   for a file git has already committed once — it keeps tracking it forever.
2. **Do the publishable files contain credential-shaped strings?** Google/AWS
   keys, private key blocks, password assignments, real email addresses.

Plus a third check that no generic scanner would do: **does anything name this
company or its people?** Branding is not a credential, so nothing else flags it,
but it is the part that makes a public repository identify your employer. The
terms come from `TI_BRAND_NAME` / `TI_BRAND_COLOR` in `.env` and from
`.forbidden_terms` (copy `.forbidden_terms.example`) — both gitignored, since
writing those terms into a committed file is the exact thing being prevented.

## What was removed from the code

Values are described, not repeated — this file is committed too, so spelling out
the old addresses here would undo the very change it documents. The real values
are in the gitignored `.env`.

| Was | Where | Now |
|---|---|---|
| Gmail app password, in plaintext | `admin_settings.json` | file is gitignored; `admin_settings.example.json` is the committed template |
| 3 real recipient addresses | `admin_settings.json` | same |
| The owner's work email | `config.py` (`BOOTSTRAP_SUPER_ADMINS`) | `TI_BOOTSTRAP_SUPER_ADMINS` in `.env` |
| Two company domains | `config.py` (`ALLOWED_EMAIL_DOMAINS`) | `TI_ALLOWED_EMAIL_DOMAINS` in `.env` |
| A real admin address | `config.py` (`DEFAULT_ADMIN_EMAIL`) | `TI_DEFAULT_ADMIN_EMAIL` in `.env` |
| A guessable literal admin password | `config.py` (`DEFAULT_ADMIN_PASSWORD`) | generated per-install in production |
| Firebase config × 3 copies | `login.html`, `setup_profile.html`, `settings.html` | server-injected from `TI_FIREBASE_*` |
| Company-domain form placeholders | `users.html`, `login.html` | `name@example.com`, `you@example.com` |
| Company logo, wordmark and favicon | 6 templates + 2 files in `static/` | server-injected `brand.*` from `TI_BRAND_*`; assets gitignored as `static/brand-*` |
| Signature brand colour, ×6 | `email_system.py` | `config.BRAND_COLOR` |
| The owner's real name, as a form placeholder | `settings.html`, `setup_profile.html` | a generic example name |

## Files that must never be committed

`.gitignore` covers these. Do not remove the entries.

- `admin_settings.json` — app password, real recipients
- `.env` — every real value, including credentials
- `.flask_secret_key` — signs email approval links; leaking it lets anyone mint
  a valid Approve link for any article, and forge internal API calls
- `.initial_admin_password` — generated bootstrap credential
- `threat_intel.db` (+ `-wal`, `-shm`) — scraped articles, **user profiles with
  real email addresses**, full delivery history
- `logs/` — recipient addresses, SMTP conversations, tracebacks
- `*.xlsx` / `*.csv` — generated report attachments
- `static/brand-*` — the company logo and wordmark. Not a credential, but it
  names the employer in a way no secret scanner would flag. Deploy them out of
  band; see `deploy/DEPLOY.md` step 3b.

## Before the first push

1. **Rotate the Gmail app password.** It existed in plaintext on disk. Assume it
   is compromised: delete it in the Google account's App passwords page and
   generate a new one.
2. Confirm the ignore rules actually bite:
   ```bash
   git init
   git add -A
   git status --short | grep -E 'admin_settings\.json|\.env$|\.flask_secret_key|\.db$'
   ```
   That should print **nothing**. If it prints a file, do not commit.
3. `python check_secrets.py`
4. Make the GitHub repo **private** if it is company code, regardless of the
   above. These measures keep credentials out of the history; they don't make
   internal source code public-safe.

## If a secret was already pushed

Removing it in a later commit is not enough — it stays in the history and in any
fork or clone. You must both:

1. Rotate the credential. This is the part that actually matters.
2. Purge it from history with [`git filter-repo`](https://github.com/newren/git-filter-repo),
   then force-push and have every collaborator re-clone.

Order matters: rotate first, because the purge takes time and the old value is
live until you do.

## A note on the Firebase values

`TI_FIREBASE_API_KEY` and friends are web client identifiers. Google ships them
to every browser by design, so they are not secrets — access is controlled by
Firebase's Authorized Domains list plus this app's own domain allowlist and
RBAC. They were still moved into `.env` so a published copy of the repo does not
name your Firebase project, but a leak of these alone is not a breach. Do not
confuse them with a Firebase *service account* key, which would be one.

## What a fresh clone gets

Someone cloning this repo gets working code and no access:

- No credentials, so no email can be sent.
- No `TI_FIREBASE_*`, so the login page says sign-in is not configured (rather
  than throwing a JavaScript error).
- `TI_BOOTSTRAP_SUPER_ADMINS` defaults to empty, so the repo grants nobody
  standing admin rights.
- `TI_ALLOWED_EMAIL_DOMAINS` defaults to a demo domain and fails closed.

They set up their own by copying `.env.example` to `.env`.
