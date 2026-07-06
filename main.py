#!/usr/bin/env python3
"""
main.py
========
Application entry point for HeaderAnalyzer Pro.

Usage:
    python main.py

Launches the PySide6 GUI. All scanning/reporting logic is decoupled from
the GUI (see scanner/ and report/) so it can also be reused headlessly if
desired (e.g. for CI pipelines or CLI tooling built on top of this codebase).
"""
from __future__ import annotations

import sys
import os

# Ensure the project root is importable regardless of the current working
# directory the script is launched from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon

from utils.constants import APP_NAME, APP_VERSION
from utils.logger import get_logger
from gui.main_window import MainWindow

logger = get_logger()


def main() -> int:
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("HeaderAnalyzer Security Labs")

    window = MainWindow()
    window.show()

    exit_code = app.exec()
    logger.info(f"{APP_NAME} exiting with code {exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
