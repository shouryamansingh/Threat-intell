#!/bin/bash
# Double-click this file on a Mac to start the Threat Intelligence System.
# It opens in Terminal, then closes the servers when you press Ctrl+C.
cd "$(dirname "$0")" || exit 1

# Prefer the project's virtualenv python; fall back to system python3.
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

# First run with no venv? Set everything up automatically.
if [ ! -x ".venv/bin/python" ]; then
  exec "$PY" run.py --setup
else
  exec "$PY" run.py
fi
