"""
utils/logger.py — Logging Setup
=================================
Configures structured logging with:
  - Console output (colored if colorlog is available)
  - Rotating file handler for audit logs
  - Separate audit log for analysis results
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", log_dir: str = "logs") -> None:
    """
    Configure application-wide logging.

    Args:
        level:   Root log level string (DEBUG/INFO/WARNING/ERROR).
        log_dir: Directory to write rotating log files.
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # ── Formatters ────────────────────────────────────────────────────────────
    detailed_fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    simple_fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Try to use colorlog for prettier console output
    try:
        import colorlog
        console_fmt = colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s %(levelname)-8s%(reset)s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "red,bg_white",
            },
        )
    except ImportError:
        console_fmt = simple_fmt

    # ── Handlers ──────────────────────────────────────────────────────────────

    # Console
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(console_fmt)
    console.setLevel(numeric_level)

    # Rotating main log file
    main_file = logging.handlers.RotatingFileHandler(
        filename=os.path.join(log_dir, "vectraforge.log"),
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    main_file.setFormatter(detailed_fmt)
    main_file.setLevel(logging.DEBUG)  # Always write debug to file

    # Dedicated audit log
    audit_file = logging.handlers.RotatingFileHandler(
        filename=os.path.join(log_dir, "audit.log"),
        maxBytes=50 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    audit_file.setFormatter(detailed_fmt)
    audit_file.setLevel(logging.INFO)

    # ── Root logger ───────────────────────────────────────────────────────────
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    root.addHandler(console)
    root.addHandler(main_file)

    # ── Audit logger ──────────────────────────────────────────────────────────
    audit_logger = logging.getLogger("vectraforge.audit")
    audit_logger.addHandler(audit_file)
    audit_logger.propagate = False  # Don't double-log to root

    # ── Quieten noisy third-party loggers ────────────────────────────────────
    for noisy in ("httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
