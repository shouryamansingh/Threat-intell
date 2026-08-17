#!/bin/bash
#
# Deploy the latest committed code to this server.
#
#   sudo /opt/threatintel/deploy/update.sh
#
# Does the three things a deploy needs, in the right order, so the restart
# cannot be forgotten: pull, install any new dependencies, restart both
# services. See UPDATING.md for what to do when something goes wrong.

set -euo pipefail

APP_DIR=/opt/threatintel
SERVICE_USER=threatintel
SERVICES="threatintel-dashboard threatintel-callback"

if [ "$(id -u)" -ne 0 ]; then
    echo "This needs root (it restarts services). Run:" >&2
    echo "  sudo $0" >&2
    exit 1
fi

run_as_app() { sudo -u "$SERVICE_USER" "$@"; }

echo "==> Currently deployed:"
run_as_app git -C "$APP_DIR" log --oneline -1

# --ff-only: refuse to deploy if the server has drifted from the remote (a
# stray edit made directly on the box). A silent merge commit here would be
# worse than a failed deploy — you would be running code that exists nowhere
# else. If this errors, read UPDATING.md → "The server has local changes".
echo
echo "==> Fetching latest..."
run_as_app git -C "$APP_DIR" pull --ff-only

echo
echo "==> Now deploying:"
run_as_app git -C "$APP_DIR" log --oneline -1

echo
echo "==> Installing dependencies (quiet unless something changed)..."
run_as_app "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo
echo "==> Restarting services..."
# shellcheck disable=SC2086
systemctl restart $SERVICES

sleep 3
echo
echo "==> Status:"
for s in $SERVICES; do
    printf '    %-28s %s\n' "$s" "$(systemctl is-active "$s")"
done

echo
echo "Both should say 'active'. If either says 'failed', see what happened:"
echo "    journalctl -u threatintel-dashboard -n 50 --no-pager"
echo
echo "To watch it run:"
echo "    journalctl -u threatintel-dashboard -f"
