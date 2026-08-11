#!/usr/bin/env python3
"""Pre-push safety net: refuse to publish credentials or personal data.

Run this before every `git push`:

    python check_secrets.py

Exit code 0 means the files git would publish look clean. Non-zero means
something must be fixed first — the output says exactly what and where.

Two independent checks, because .gitignore alone is not enough:

  1. Are the sensitive files actually ignored? A .gitignore rule does nothing
     for a file that was already committed once — git keeps tracking it.
  2. Do the files git WOULD publish contain anything that looks like a
     credential, a real email address, or an internal hostname?

Deliberately dependency-free so it works on a fresh clone.
"""

import os
import re
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))

# Files that must never be tracked by git.
MUST_BE_IGNORED = [
    "admin_settings.json",      # Gmail app password + real recipients
    ".flask_secret_key",        # signs email action links and sessions
    ".initial_admin_password",  # generated bootstrap credential
    ".env",                     # every TI_* value including secrets
    "threat_intel.db",          # articles, user profiles, delivery history
    ".forbidden_terms",         # the brand/personal terms this scan looks for
]

# Directory / suffix patterns that must not be tracked.
IGNORED_PATTERNS = [
    (re.compile(r"^logs/"), "log files contain recipient addresses and tracebacks"),
    (re.compile(r"\.db(-wal|-shm)?$"), "database files contain personal data"),
    (re.compile(r"\.(xlsx|xls|csv)$"), "report exports contain threat data"),
    (re.compile(r"^\.venv/"), "virtualenv should not be committed"),
    (re.compile(r"__pycache__/"), "compiled bytecode should not be committed"),
]

# Content patterns scanned in the files git would publish.
# Each entry: (label, regex, allowlist regex or None, remediation hint)
CONTENT_RULES = [
    (
        "Gmail app password (16 lowercase letters assigned to a password field)",
        # `["']?` after the key so this matches JSON ("SENDER_PASSWORD": "…")
        # as well as Python (SENDER_PASSWORD = "…").
        re.compile(
            r"""(?i)(sender_password|app_password|smtp_password)["']?\s*[:=]\s*["']([a-z]{16})["']"""
        ),
        None,
        "Move it to .env (gitignored) and read it via os.environ.",
    ),
    (
        "Google/Firebase API key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        None,
        "Move it to .env (gitignored) and read it via os.environ.",
    ),
    (
        "AWS access key id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        None,
        "Use an IAM role or .env — never a literal key in source.",
    ),
    (
        "Private key block",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        None,
        "Keep private keys out of the tree entirely; reference them by path.",
    ),
    (
        "Hardcoded non-empty password assignment",
        # `\w*` on BOTH sides of the keyword so DEFAULT_ADMIN_PASSWORD and
        # SECRET_KEY match (a prefix or suffix otherwise defeats \b(password)),
        # and an optional `"]` so subscript form is caught too:
        #     app.config["SECRET_KEY"] = "…"
        re.compile(
            r"""(?i)\b[\w.]*(password|passwd|secret|token)\w*["']?\]?\s*[:=]\s*["']([^"'\s]{6,})["']"""
        ),
        # Placeholders and env lookups are fine. "password" itself is NOT
        # allowlisted — shipping it as a real default is exactly the bug this
        # scan should catch.
        re.compile(r"(?i)(example|changeme|your[-_ ]?|placeholder|xxx|\.\.\.|os\.environ|getenv|redacted)"),
        "Move it to .env (gitignored) and read it via os.environ.",
    ),
    (
        "Real email address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        # Documentation/demo domains and Google's own service addresses.
        re.compile(
            r"(?i)(@example\.(com|org|net)$|sentinel-demo\.io$|@your-|noreply@|"
            r"@system\.gserviceaccount\.com$|gserviceaccount\.com$|"
            r"@localhost$|@sentry\.io$)"
        ),
        "Use an @example.com address in committed files; real ones go in .env.",
    ),
]


def _brand_rule():
    """A rule that refuses to publish this deployment's own branding.

    The company name, signature colour and the owner's surname were removed from
    the templates and the email builder in favour of TI_BRAND_*. Nothing enforces
    that but a scan — a copy-pasted snippet or a restored backup puts the
    employer's identity straight back into a public repository, and no credential
    scanner would object, because none of it is a credential.

    The terms are read from the gitignored .env and .forbidden_terms rather than
    written here. Spelling them out in this committed file would leak the very
    identity the rule exists to protect. A fresh clone has no .env, so it gets no
    rule — correct, since it has no branding to leak either.

    Returns None when there is nothing to guard.
    """
    terms = set()

    # Whatever this deployment brands itself as, it must not reach a commit.
    env_path = os.path.join(HERE, ".env")
    try:
        with open(env_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key.strip() in ("TI_BRAND_NAME", "TI_BRAND_COLOR"):
                    value = value.strip().strip("'\"")
                    if len(value) >= 3:
                        terms.add(value)
    except OSError:
        pass

    # Anything else that must never be published — personal names, internal
    # hostnames, project codenames. One per line, # for comments.
    try:
        with open(os.path.join(HERE, ".forbidden_terms"), "r",
                  encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    terms.add(line)
    except OSError:
        pass

    if not terms:
        return None

    # Longest first so the reported match is the most specific one.
    pattern = "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
    return (
        "Company-identifying branding or personal data",
        re.compile(f"(?i)({pattern})"),
        None,
        "Render it from config.BRAND / TI_BRAND_* instead of hardcoding it.",
    )


_brand = _brand_rule()
if _brand:
    CONTENT_RULES.append(_brand)


# Only scan text we could plausibly publish.
SCAN_SUFFIXES = (
    ".py", ".json", ".html", ".js", ".css", ".md", ".txt", ".sh", ".bat",
    ".command", ".yml", ".yaml", ".conf", ".service", ".ini", ".cfg",
)

# Files exempt from the *content* scan, by exact repo-relative path.
# .env.example and this scanner both legitimately contain example patterns.
CONTENT_EXEMPT = {
    ".env.example",
    "check_secrets.py",
    "admin_settings.example.json",
    ".gitignore",
}


def run_git(*args):
    """Return git stdout, or None if git is unavailable / not a repo."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=HERE, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def tracked_files():
    """Files git currently tracks, or None if this is not a git repo yet."""
    out = run_git("ls-files")
    if out is None:
        return None
    return [line for line in out.splitlines() if line.strip()]


def check_tracked(files, problems, notes):
    """Verify nothing sensitive is tracked."""
    tracked = set(files)

    for name in MUST_BE_IGNORED:
        if name in tracked:
            problems.append(
                f"TRACKED SECRET: {name} is tracked by git.\n"
                f"    .gitignore does not untrack an already-committed file. Fix with:\n"
                f"        git rm --cached {name}\n"
                f"    If it was ever pushed, treat its contents as compromised and rotate."
            )

    for path in sorted(tracked):
        for pattern, why in IGNORED_PATTERNS:
            if pattern.search(path):
                problems.append(f"TRACKED DATA: {path} — {why}")
                break

    if not tracked:
        notes.append("git tracks no files yet — nothing has been committed so far.")


def scan_content(files, problems):
    """Scan publishable file contents for credential-shaped strings."""
    for rel in sorted(files):
        if rel in CONTENT_EXEMPT or not rel.endswith(SCAN_SUFFIXES):
            continue
        full = os.path.join(HERE, rel)
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue

        for lineno, line in enumerate(lines, 1):
            if "check-secrets: allow" in line:
                continue
            for label, pattern, allow, hint in CONTENT_RULES:
                for match in pattern.finditer(line):
                    hit = match.group(0)
                    if allow and allow.search(hit):
                        continue
                    problems.append(
                        f"{rel}:{lineno} — {label}\n"
                        f"    found: {hit[:90]}\n"
                        f"    {hint}"
                    )
                    break


def check_untracked_secrets_exist(problems, notes):
    """Warn if a secret file is missing entirely — likely a broken setup."""
    for name in (".env", "admin_settings.json"):
        if not os.path.exists(os.path.join(HERE, name)):
            notes.append(
                f"{name} is absent. Copy the .example file and fill it in, "
                f"or supply the values as environment variables."
            )


def main():
    problems, notes = [], []

    files = tracked_files()
    if files is None:
        notes.append(
            "Not a git repository yet (or git unavailable). Skipped the tracked-file "
            "check; scanning the working directory instead."
        )
        # Fall back to scanning everything that is not obviously excluded.
        files = []
        for root, dirs, filenames in os.walk(HERE):
            dirs[:] = [
                d for d in dirs
                if d not in {".venv", "__pycache__", ".git", "logs", "node_modules",
                             ".claude", ".demo-backup", ".pytest_cache", ".ruff_cache"}
            ]
            for name in filenames:
                rel = os.path.relpath(os.path.join(root, name), HERE)
                # Do not scan the gitignored secret files themselves — they are
                # SUPPOSED to contain secrets.
                if rel in MUST_BE_IGNORED or rel.startswith(".env"):
                    continue
                files.append(rel)
    else:
        check_tracked(files, problems, notes)

    scan_content(files, problems)
    check_untracked_secrets_exist(problems, notes)

    print("=" * 72)
    print("  Pre-push secret scan")
    print("=" * 72)

    for note in notes:
        print(f"\n  note: {note}")

    if problems:
        print(f"\n  {len(problems)} problem(s) found — DO NOT PUSH:\n")
        for i, problem in enumerate(problems, 1):
            print(f"  {i}. {problem}\n")
        print("=" * 72)
        return 1

    print("\n  No credentials, personal data or internal hostnames found in the")
    print("  files git would publish. Safe to push.\n")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
