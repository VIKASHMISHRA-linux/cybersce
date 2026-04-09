"""
backend/logger_setup.py
Configures root logger: rotating file + colored console.
Import this once at application startup.
"""
import logging
import logging.handlers
import os
import sys

from backend.config import Config

_COLORS = {
    "DEBUG":    "\033[36m",   # cyan
    "INFO":     "\033[32m",   # green
    "WARNING":  "\033[33m",   # yellow
    "ERROR":    "\033[31m",   # red
    "CRITICAL": "\033[35m",   # magenta
    "RESET":    "\033[0m",
}


class _ColorFormatter(logging.Formatter):
    FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        color = _COLORS.get(record.levelname, "")
        reset = _COLORS["RESET"]
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


def setup() -> None:
    level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)

    # Ensure log directory exists
    os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(_ColorFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                                    datefmt="%H:%M:%S"))

    # Rotating file handler (10 MB × 5 backups)
    fh = logging.handlers.RotatingFileHandler(
        Config.LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))

    root.addHandler(ch)
    root.addHandler(fh)

    # Silence noisy third-party loggers
    for noisy in ("websockets", "aiohttp", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# Auto-setup on import
setup()
