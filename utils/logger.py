"""
utils/logger.py
================
Centralized application logging.

Supports INFO / DEBUG / WARNING / ERROR levels, writes rotating log files to
``data/logs`` and mirrors output to stdout for developers running the tool
from a terminal. A single shared logger instance ("HeaderAnalyzer") is used
throughout the codebase.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path

APP_LOGGER_NAME = "HeaderAnalyzer"

_LOG_DIR = Path(__file__).resolve().parent.parent / "data" / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)
_LOG_FILE = _LOG_DIR / "header_analyzer.log"


def get_logger(name: str = APP_LOGGER_NAME, level: int = logging.DEBUG) -> logging.Logger:
    """Return a configured logger. Safe to call multiple times."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        _LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False
    return logger


def log_file_path() -> str:
    return str(_LOG_FILE)
