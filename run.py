#!/usr/bin/env python3
"""
run.py — One-command launcher for the Threat Intelligence System.

Starts BOTH servers in one go (the background scheduler starts automatically
with the dashboard, so there's nothing else to launch):

    • Callback server  -> http://localhost:5000   (catches email Approve/Reject clicks)
    • Dashboard        -> http://localhost:5001   (the web page you open in a browser)

Usage:
    python run.py                 # preflight health checks, then start
    python run.py --install       # install dependencies first, then start
    python run.py --setup         # create a .venv + install deps, then start
    python run.py --skip-checks   # start even if preflight checks fail
    python run.py --fast-checks   # preflight without network checks (offline dev)

Press Ctrl+C in this window to stop everything cleanly.

FOR LOCAL DEVELOPMENT ONLY. This launcher holds both servers as child
processes, so everything dies when this terminal closes and nothing restarts
after a crash or reboot. On a server use the systemd units in deploy/ instead —
see deploy/DEPLOY.md.
"""

import os
import sys
import time
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Ports come from config so this launcher can't disagree with what the servers
# actually bind to (both are overridable via TI_*_PORT).
sys.path.insert(0, str(ROOT))
try:
    import config as _config
    _CALLBACK_PORT = _config.CALLBACK_SERVER_PORT
    _DASHBOARD_PORT = _config.DASHBOARD_PORT
except Exception:
    _CALLBACK_PORT, _DASHBOARD_PORT = 5000, 5001

# name, script file, the URL it serves, seconds to wait before starting the next one
SERVERS = [
    ("CALLBACK ", "callback_server.py", f"http://localhost:{_CALLBACK_PORT}", 2),
    ("DASHBOARD", "web_dashboard.py",   f"http://localhost:{_DASHBOARD_PORT}", 0),
]


def venv_python():
    """Path to the project's virtualenv interpreter for this OS (may not exist)."""
    if os.name == "nt":
        return ROOT / ".venv" / "Scripts" / "python.exe"
    return ROOT / ".venv" / "bin" / "python"


def pick_python():
    """Use the project's .venv if present, otherwise whatever Python is running this."""
    vp = venv_python()
    return str(vp) if vp.exists() else sys.executable


def deps_ok(py):
    """Quick check that the essential libraries are importable."""
    probe = "import flask, flask_socketio, apscheduler"
    return subprocess.run([py, "-c", probe], capture_output=True).returncode == 0


def create_venv():
    print("🧱 Creating a virtual environment in .venv ...")
    subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True)


def install(py):
    print("📦 Installing dependencies (first time can take several minutes)...")
    subprocess.run([py, "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([py, "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")], check=True)


def main():
    print("=" * 62)
    print("🛡️   THREAT INTELLIGENCE SYSTEM  —  launcher")
    print("=" * 62)

    # --setup builds the venv from scratch; --install just installs into the chosen python
    if "--setup" in sys.argv and not venv_python().exists():
        create_venv()

    py = pick_python()
    print(f"🐍 Python: {py}")

    if "--install" in sys.argv or "--setup" in sys.argv:
        install(py)

    if not deps_ok(py):
        print("\n❌ Required packages are missing in this environment.")
        print("   Set it up once (creates .venv + installs everything), then it starts automatically:\n")
        print(f"     {sys.executable} run.py --setup\n")
        print("   ...or, if you manage your own environment:\n")
        print(f"     {py} -m pip install -r requirements.txt\n")
        sys.exit(1)

    # Preflight: catch broken feeds / DB / ports / SMTP BEFORE the servers
    # start, so failures are loud here instead of silent in production.
    if "--skip-checks" not in sys.argv:
        print("\n🩺 Running preflight health checks (use --skip-checks to bypass)...")
        preflight_args = [py, str(ROOT / "health_checks.py"), "--preflight"]
        if "--fast-checks" in sys.argv:
            preflight_args.append("--fast")
        preflight = subprocess.run(preflight_args, cwd=str(ROOT))
        if preflight.returncode != 0:
            print("\n❌ Preflight checks FAILED — not starting the system.")
            print("   Fix the issues above, or start anyway with:")
            print(f"     {py} run.py --skip-checks\n")
            sys.exit(1)
        print()

    procs = []
    try:
        for name, script, url, wait in SERVERS:
            print(f"▶️   Starting {name}  {url}")
            p = subprocess.Popen([py, str(ROOT / script)], cwd=str(ROOT))
            procs.append((name.strip(), p))
            if wait:
                time.sleep(wait)  # small stagger so the boot logs don't collide

        print("\n" + "-" * 62)
        print("✅  System is running.")
        print(f"   👉  Open the dashboard in your browser:  http://localhost:{_DASHBOARD_PORT}")
        print(f"       (the callback server on :{_CALLBACK_PORT} handles the email buttons)")
        print("\n   ℹ️  The very first AI summary downloads the ~1.5 GB model once,")
        print("       so the first run may be slow. After that it's cached.")
        print("\n   🛑  Press Ctrl+C here to stop everything.")
        print("-" * 62 + "\n")

        # Babysit: if either server dies on its own, tear the rest down.
        while True:
            for name, p in procs:
                if p.poll() is not None:
                    print(f"\n⚠️   {name} exited (code {p.returncode}). Shutting the rest down...")
                    raise KeyboardInterrupt
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Stopping servers...")
    finally:
        for _, p in procs:
            if p.poll() is None:
                p.terminate()
        time.sleep(2)
        for _, p in procs:          # hard-kill anything that ignored terminate
            if p.poll() is None:
                p.kill()
        print("👋 All stopped.")


if __name__ == "__main__":
    main()
