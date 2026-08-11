#!/bin/bash
# check_and_run.sh — verify the project is healthy, then start it.
#
# Runs every preflight check in one pass, refuses to launch a broken system,
# and warns before a boot that would send real email. Lives in the project
# root so the trailing space in the folder name is never an issue.
#
# Usage:
#   ./check_and_run.sh              # full checks, then start
#   ./check_and_run.sh --fast       # skip network checks (VPN/offline)
#   ./check_and_run.sh --check-only # verify everything, don't start
#   ./check_and_run.sh --yes        # don't prompt if a delivery is due
#   ./check_and_run.sh --setup      # create .venv + install deps first

set -uo pipefail
cd "$(dirname "$0")" || exit 1

FAST=0; CHECK_ONLY=0; ASSUME_YES=0; SETUP=0
for a in "$@"; do
  case "$a" in
    --fast)       FAST=1 ;;
    --check-only) CHECK_ONLY=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --setup)      SETUP=1 ;;
    -h|--help)    sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Unknown option: $a (try --help)"; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; N=""
fi
ok()   { echo "  ${G}✅${N} $1"; }
warn() { echo "  ${Y}⚠️ ${N} $1"; }
die()  { echo "  ${R}❌ $1${N}"; echo; echo "${R}Aborted — system not started.${N}"; exit 1; }
step() { echo; echo "${B}▶ $1${N}"; }

echo "=================================================================="
echo "${B}🛡️  THREAT INTEL — CHECK & RUN${N}"
echo "=================================================================="
echo "  Project: $(pwd)"

# ── 1. Interpreter ────────────────────────────────────────────────────
step "1/6  Python environment"
if [ "$SETUP" = 1 ] && [ ! -x ".venv/bin/python" ]; then
  echo "  Creating .venv ..."
  python3 -m venv .venv || die "Could not create .venv"
fi

if [ -x ".venv/bin/python" ]; then
  PY="./.venv/bin/python"; ok "venv: $("$PY" -V 2>&1)"
else
  PY="python3"
  command -v python3 >/dev/null || die "No .venv and no python3 on PATH. Run: ./check_and_run.sh --setup"
  warn "No .venv — falling back to system $($PY -V 2>&1). Create one with --setup"
fi

[ "$SETUP" = 1 ] && { echo "  Installing dependencies ..."; "$PY" -m pip install -q -r requirements.txt || die "pip install failed"; }

# ── 2. Dependencies ───────────────────────────────────────────────────
step "2/6  Dependencies"
MISSING=$("$PY" - <<'EOF' 2>&1
import importlib.util
miss = [m for m in ("flask","flask_socketio","apscheduler","feedparser","pytz","bs4","requests")
        if importlib.util.find_spec(m) is None]
print(" ".join(miss))
EOF
)
if [ -n "$MISSING" ]; then
  die "Missing packages:$MISSING
     Fix with:  $PY -m pip install -r requirements.txt   (or ./check_and_run.sh --setup)"
fi
ok "all core packages importable"

# ── 3. Syntax ─────────────────────────────────────────────────────────
step "3/6  Module compile check"
if "$PY" -m compileall -q . -x '(\.venv|__pycache__)' >/tmp/ti_compile.$$ 2>&1; then
  ok "every module compiles"
else
  head -20 /tmp/ti_compile.$$; rm -f /tmp/ti_compile.$$
  die "Syntax errors above."
fi
rm -f /tmp/ti_compile.$$

# ── 4. Ports ──────────────────────────────────────────────────────────
step "4/6  Ports 5000 / 5001"
BUSY=0
for p in 5000 5001; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    warn "port $p in use by: $(lsof -nP -iTCP:"$p" -sTCP:LISTEN -Fc 2>/dev/null | grep '^c' | head -1 | cut -c2-)"
    BUSY=1
  else
    ok "port $p free"
  fi
done
if [ "$BUSY" = 1 ]; then
  echo "     An old instance is probably still running. Stop it with:"
  echo "       pkill -f 'web_dashboard.py|callback_server.py'"
  [ "$CHECK_ONLY" = 0 ] && die "Ports busy — the servers cannot bind."
fi

# ── 5. Email safety gate ──────────────────────────────────────────────
# Booting starts a poller that sends a REAL SOC email within ~15s for any
# pending row already past its scheduled time. Surface that before launch.
step "5/6  Email safety (pending deliveries)"
DUE=$("$PY" - <<'EOF'
import sqlite3, datetime, os
try:
    if not os.path.exists("threat_intel.db"):
        print("NODB"); raise SystemExit
    c = sqlite3.connect("file:threat_intel.db?mode=ro", uri=True)
    now = datetime.datetime.now().isoformat()
    print(c.execute(
        "SELECT COUNT(*) FROM soc_deliveries WHERE status='pending' AND scheduled_for<=?",
        (now,)).fetchone()[0])
except Exception as e:
    print(f"ERR:{e}")
EOF
)
case "$DUE" in
  0)     ok "no deliveries due — nothing will be emailed on boot" ;;
  NODB)  warn "threat_intel.db not found (first run?)" ;;
  ERR:*) warn "could not read delivery queue: ${DUE#ERR:}" ;;
  *)
    echo "  ${R}${B}⚠️  $DUE delivery(s) are DUE NOW.${N}"
    echo "     Starting the system WILL send real email to the SOC list within ~15s."
    if [ "$ASSUME_YES" = 0 ] && [ "$CHECK_ONLY" = 0 ]; then
      printf "     Continue and send? [y/N] "
      read -r reply </dev/tty
      [[ "$reply" =~ ^[Yy]$ ]] || die "Cancelled by user."
    fi
    ;;
esac

# ── 6. Health checks ──────────────────────────────────────────────────
step "6/6  Health checks$([ "$FAST" = 1 ] && echo ' (fast — no network)')"
HC=(health_checks.py --preflight); [ "$FAST" = 1 ] && HC+=(--fast)
if "$PY" "${HC[@]}"; then
  ok "preflight passed"
else
  echo
  die "Preflight failed (see above).
     Retry offline:  ./check_and_run.sh --fast
     Force start:    $PY run.py --skip-checks"
fi

# ── Launch ────────────────────────────────────────────────────────────
if [ "$CHECK_ONLY" = 1 ]; then
  echo; echo "${G}${B}✅ All checks passed — system NOT started (--check-only).${N}"; exit 0
fi

echo
echo "=================================================================="
echo "${G}${B}✅ All checks passed — starting servers${N}"
echo "   Dashboard → ${B}http://localhost:5001${N}"
echo "   Callback  → http://localhost:5000"
echo "   ${Y}Keep this window open. Ctrl+C stops both.${N}"
echo "=================================================================="
echo

exec "$PY" run.py --skip-checks   # checks already done above
