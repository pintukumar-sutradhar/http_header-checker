"""
gui/scan_worker.py
====================
QThread-based worker that runs a security scan without blocking the Qt
event loop. Emits signals for progress updates (per ``ScanStage``),
completion, and errors. Supports cooperative cancellation via a shared
threading.Event.
"""
from __future__ import annotations

import threading
from typing import Optional

from PySide6.QtCore import QThread, Signal

from scanner.scan_engine import run_scan
from utils.models import ScanOptions, ScanResult, ScanStage
from utils.logger import get_logger

logger = get_logger()


class ScanWorker(QThread):
    """Runs a single scan in a background thread."""

    progress = Signal(str, str)          # stage name, message
    finished_scan = Signal(object)       # ScanResult
    failed = Signal(str)                 # error message

    def __init__(self, url: str, options: ScanOptions, analyst: str = "Unknown Analyst", parent=None):
        super().__init__(parent)
        self.url = url
        self.options = options
        self.analyst = analyst
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        try:
            def progress_cb(stage: ScanStage, message: str):
                self.progress.emit(stage.value, message)

            def cancel_check() -> bool:
                return self._cancel_event.is_set()

            result: ScanResult = run_scan(
                self.url,
                options=self.options,
                progress_cb=progress_cb,
                cancel_check=cancel_check,
                analyst=self.analyst,
            )
            self.finished_scan.emit(result)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("ScanWorker crashed")
            self.failed.emit(str(exc))
