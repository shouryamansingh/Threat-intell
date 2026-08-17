"""Shared logging configuration for every entry point in the project.

Before this module existed, each entry point called a bare
`logging.basicConfig(level=logging.INFO)`. That prints to the terminal and
nothing else: no timestamps, no module names, and — critically — no file. On a
server, every traceback vanished with the terminal that produced it, so a 2am
scrape failure left no evidence behind.

`setup_logging()` replaces those four copies. It keeps console output (systemd
and Docker both capture stdout, so that stays useful) and adds a rotating file
handler so history survives restarts without growing without bound.

Usage — first thing in an entry point, before other project imports log anything:

    from log_setup import setup_logging
    setup_logging("dashboard")

Environment:
    TI_LOG_DIR    directory for log files      (default: <project>/logs)
    TI_LOG_LEVEL  DEBUG/INFO/WARNING/ERROR     (default: INFO)
    TI_LOG_MAX_MB size per file before rotating (default: 5)
    TI_LOG_BACKUPS  rotated files to keep       (default: 3)

Worst-case disk is (MAX_MB × (BACKUPS + 1)) per component, so the defaults cap
each component at 20 MB and the whole logs/ directory at well under 100 MB —
sized for a small cloud volume rather than a workstation. Raise TI_LOG_BACKUPS
where the disk is cheap and the history matters more.
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler

_ROOT = os.path.dirname(os.path.abspath(__file__))

# Guards against double-configuration. web_dashboard imports scheduler, which
# imports enhanced_scheduler — without this, a single process could stack three
# sets of handlers and write every line three times.
_configured = set()

_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def log_dir() -> str:
    """Directory that holds log files, created on first use."""
    path = os.environ.get("TI_LOG_DIR") or os.path.join(_ROOT, "logs")
    os.makedirs(path, exist_ok=True)
    return path


def _level() -> int:
    name = (os.environ.get("TI_LOG_LEVEL") or "INFO").strip().upper()
    return getattr(logging, name, logging.INFO)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def setup_logging(component: str) -> logging.Logger:
    """Configure root logging for `component` and return its logger.

    Safe to call more than once per process; later calls for the same component
    are no-ops rather than adding duplicate handlers.
    """
    if component in _configured:
        return logging.getLogger(component)

    root = logging.getLogger()
    root.setLevel(_level())

    # Drop handlers installed by an earlier basicConfig (ours or a library's),
    # otherwise records get emitted twice with two different formats.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    # A logging failure must never take down a delivery, so a bad log dir
    # (read-only volume, wrong owner after deploy) degrades to console-only.
    try:
        path = os.path.join(log_dir(), f"{component}.log")
        file_handler = RotatingFileHandler(
            path,
            maxBytes=_int_env("TI_LOG_MAX_MB", 5) * 1024 * 1024,
            backupCount=_int_env("TI_LOG_BACKUPS", 3),
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as e:
        root.warning(f"File logging disabled — could not open log file: {e}")

    # These libraries log a line per HTTP request/poll at INFO. Left alone they
    # bury the application's own messages and churn through log rotation.
    for noisy in ("werkzeug", "urllib3", "apscheduler.executors.default",
                  "engineio", "socketio", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured.add(component)

    logger = logging.getLogger(component)
    logger.info(f"Logging initialized for {component!r} → {log_dir()}")
    return logger
