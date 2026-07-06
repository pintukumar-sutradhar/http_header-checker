"""
gui/main_window.py
=====================
The main application window: toolbar, target input, live scan progress,
and a tabbed dashboard (Overview, Headers, CSP, Cookies, Redirects, TLS,
Fingerprint, Findings).

This module contains ONLY GUI/orchestration logic; all actual scanning
logic lives in ``scanner/``.
"""
from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QAction, QKeySequence, QColor
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QToolBar, QStatusBar, QProgressBar, QMessageBox,
    QGridLayout, QScrollArea, QFrame, QTextEdit, QComboBox,
    QInputDialog, QApplication,
)

from utils.constants import (
    APP_NAME, APP_VERSION, COLOR_BACKGROUND, COLOR_PANEL, COLOR_CARD, COLOR_BORDER,
    COLOR_TEXT, COLOR_TEXT_MUTED, COLOR_GREEN, COLOR_ORANGE, COLOR_RED, COLOR_BLUE,
)
from utils.models import ScanOptions, ScanResult
from utils.network import normalize_url, is_valid_url
from utils.logger import get_logger, log_file_path

from scanner.scan_engine import run_scan  # noqa: F401 (used indirectly via worker)

from gui.scan_worker import ScanWorker
from gui.widgets import StatCard, Badge, ScoreGauge, StageProgressBar, make_table, SEVERITY_COLORS, STATUS_COLORS
from gui.dialogs import ScanOptionsDialog, HeaderDetailDialog

logger = get_logger()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1400, 940)

        self.current_result: Optional[ScanResult] = None
        self.current_data: Optional[dict] = None
        self.scan_worker: Optional[ScanWorker] = None
        self.scan_options = ScanOptions()
        self.analyst_name = "Security Analyst"

        self._build_ui()
        self._apply_theme()

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        self._build_toolbar()
        self._build_menu()

        # --- Target input row ---
        target_row = QHBoxLayout()
        target_label = QLabel("Target URL:")
        target_label.setStyleSheet("font-weight:600;")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.returnPressed.connect(self.start_scan)
        self.method_badge = QComboBox()
        self.method_badge.addItems(["GET", "HEAD", "OPTIONS"])
        self.scan_btn = QPushButton("🔍  Check Headers")
        self.scan_btn.setObjectName("PrimaryButton")
        self.scan_btn.clicked.connect(self.start_scan)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("DangerButton")
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.cancel_btn.setEnabled(False)

        target_row.addWidget(target_label)
        target_row.addWidget(self.url_input, stretch=1)
        target_row.addWidget(self.method_badge)
        target_row.addWidget(self.scan_btn)
        target_row.addWidget(self.cancel_btn)
        root_layout.addLayout(target_row)

        # --- Stage progress ---
        self.stage_bar = StageProgressBar()
        root_layout.addWidget(self.stage_bar)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setVisible(False)
        root_layout.addWidget(self.progress_bar)

        # --- Main tabbed dashboard ---
        root_layout.addWidget(self._build_tabs(), stretch=1)

        # --- Status bar ---
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready.")
        self.status_bar.addWidget(self.status_label)
        self.log_path_label = QLabel(f"Log: {log_file_path()}")
        self.log_path_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        self.status_bar.addPermanentWidget(self.log_path_label)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))
        self.addToolBar(toolbar)

        new_scan_action = QAction("New Scan", self)
        new_scan_action.setShortcut(QKeySequence("Ctrl+N"))
        new_scan_action.triggered.connect(self.start_scan)
        toolbar.addAction(new_scan_action)

        options_action = QAction("Advanced Options", self)
        options_action.setShortcut(QKeySequence("Ctrl+O"))
        options_action.triggered.connect(self.open_options_dialog)
        toolbar.addAction(options_action)

        toolbar.addSeparator()

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)

    def _build_menu(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")
        new_scan = QAction("New Scan\tCtrl+N", self)
        new_scan.triggered.connect(self.start_scan)
        file_menu.addAction(new_scan)
        file_menu.addSeparator()
        quit_action = QAction("Quit\tCtrl+Q", self)
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        tools_menu = menu_bar.addMenu("&Tools")
        options_action = QAction("Advanced Scan Options...\tCtrl+O", self)
        options_action.triggered.connect(self.open_options_dialog)
        tools_menu.addAction(options_action)
        analyst_action = QAction("Set Analyst Name...", self)
        analyst_action.triggered.connect(self.set_analyst_name)
        tools_menu.addAction(analyst_action)

        help_menu = menu_bar.addMenu("&Help")
        about_action = QAction(f"About {APP_NAME}", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def _build_tabs(self) -> QWidget:
        self.tabs = QTabWidget()

        self.dashboard_tab = self._build_dashboard_tab()
        self.tabs.addTab(self.dashboard_tab, "📊 Dashboard")

        self.headers_tab = self._build_headers_tab()
        self.tabs.addTab(self.headers_tab, "🛡️ Headers")

        self.csp_tab = self._build_csp_tab()
        self.tabs.addTab(self.csp_tab, "🧩 CSP Analyzer")

        self.cookies_tab = self._build_cookies_tab()
        self.tabs.addTab(self.cookies_tab, "🍪 Cookies")

        self.redirects_tab = self._build_redirects_tab()
        self.tabs.addTab(self.redirects_tab, "↪️ Redirects")

        self.tls_tab = self._build_tls_tab()
        self.tabs.addTab(self.tls_tab, "🔐 TLS / Certificate")

        self.fingerprint_tab = self._build_fingerprint_tab()
        self.tabs.addTab(self.fingerprint_tab, "🖥️ Fingerprint")

        self.findings_tab = self._build_findings_tab()
        self.tabs.addTab(self.findings_tab, "⚠️ Findings & Risk")

        return self.tabs

    # ------------------------------------------------------------------ #
    # Dashboard tab
    # ------------------------------------------------------------------ #
    def _build_dashboard_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        scroll.setWidget(content)
        layout = QVBoxLayout(content)

        top_row = QHBoxLayout()
        self.score_gauge = ScoreGauge()
        top_row.addWidget(self.score_gauge)

        self.exec_summary_label = QLabel(
            "Run a scan to populate the dashboard with target, network, TLS, and fingerprint information."
        )
        self.exec_summary_label.setWordWrap(True)
        self.exec_summary_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size: 13px; padding: 10px;")
        top_row.addWidget(self.exec_summary_label, stretch=1)
        layout.addLayout(top_row)

        # Stat card grids, grouped by section
        self.dashboard_cards: dict[str, StatCard] = {}

        def add_section(title: str, keys: list[str]) -> None:
            section_label = QLabel(title)
            section_label.setStyleSheet("font-weight:700; font-size:14px; margin-top:14px;")
            layout.addWidget(section_label)
            grid = QGridLayout()
            grid.setSpacing(8)
            for i, key in enumerate(keys):
                card = StatCard(key)
                self.dashboard_cards[key] = card
                grid.addWidget(card, i // 4, i % 4)
            layout.addLayout(grid)

        add_section("🌐 Network & Host", [
            "Target URL", "Final URL", "Resolved IP", "IPv6", "Reverse DNS",
            "Country", "Hosting Provider", "ASN", "Protocol", "HTTP Version",
            "Response Time", "Redirect Count", "Total Headers",
        ])

        add_section("🔐 TLS / Certificate", [
            "TLS Version", "Cipher Suite", "Certificate Status", "Certificate Expiry",
            "Days Until Expiry", "Certificate Issuer", "Certificate Subject",
            "Public Key", "SHA-256 Fingerprint", "HSTS Preload Eligible",
        ])

        add_section("🖥️ Server & Technology", [
            "Server Banner", "Powered By", "Web Server", "Reverse Proxy",
            "CDN", "Framework", "CMS", "Operating System", "Technologies",
        ])

        layout.addStretch()
        return scroll

    # ------------------------------------------------------------------ #
    # Headers tab
    # ------------------------------------------------------------------ #
    def _build_headers_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        legend = QHBoxLayout()
        for status, color in STATUS_COLORS.items():
            b = Badge(status, color)
            legend.addWidget(b)
        legend.addStretch()
        layout.addLayout(legend)

        self.headers_table = make_table(["Header", "Status", "Severity", "Current Value", "Recommended Value"])
        self.headers_table.itemDoubleClicked.connect(self._show_header_detail)
        self.headers_table.setColumnWidth(0, 220)
        self.headers_table.setColumnWidth(1, 110)
        self.headers_table.setColumnWidth(2, 100)
        layout.addWidget(self.headers_table)

        hint = QLabel("Double-click any row for full OWASP / Mozilla / Microsoft guidance and secure example configuration.")
        hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px;")
        layout.addWidget(hint)

        self._header_dicts: list[dict] = []
        return widget

    def _show_header_detail(self, item: QTableWidgetItem) -> None:
        row = item.row()
        if 0 <= row < len(self._header_dicts):
            dlg = HeaderDetailDialog(self._header_dicts[row], self)
            dlg.exec()

    # ------------------------------------------------------------------ #
    # CSP tab
    # ------------------------------------------------------------------ #
    def _build_csp_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        layout.addWidget(QLabel("Raw Content-Security-Policy:"))
        self.csp_raw_view = QTextEdit()
        self.csp_raw_view.setReadOnly(True)
        self.csp_raw_view.setFixedHeight(90)
        self.csp_raw_view.setStyleSheet("font-family: Consolas, monospace;")
        layout.addWidget(self.csp_raw_view)

        self.csp_directives_table = make_table(["Directive", "Values", "Issues"])
        layout.addWidget(self.csp_directives_table)

        layout.addWidget(QLabel("Dangerous / Missing Directive Findings:"))
        self.csp_issues_view = QTextEdit()
        self.csp_issues_view.setReadOnly(True)
        layout.addWidget(self.csp_issues_view)

        return widget

    # ------------------------------------------------------------------ #
    # Cookies tab
    # ------------------------------------------------------------------ #
    def _build_cookies_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.cookies_table = make_table([
            "Name", "Secure", "HttpOnly", "SameSite", "Path", "Domain",
            "Persistent", "Priority", "Partitioned", "Issues",
        ])
        layout.addWidget(self.cookies_table)
        return widget

    # ------------------------------------------------------------------ #
    # Redirects tab
    # ------------------------------------------------------------------ #
    def _build_redirects_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.redirect_summary_label = QLabel("No redirects analyzed yet.")
        self.redirect_summary_label.setWordWrap(True)
        layout.addWidget(self.redirect_summary_label)

        self.redirects_table = make_table(["#", "URL", "Status", "Location", "Scheme", "Permanent"])
        layout.addWidget(self.redirects_table)
        return widget

    # ------------------------------------------------------------------ #
    # TLS tab
    # ------------------------------------------------------------------ #
    def _build_tls_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        scroll.setWidget(content)
        layout = QVBoxLayout(content)

        self.tls_cards: dict[str, StatCard] = {}
        keys = [
            "TLS Version", "Cipher Suite", "Cipher Bits", "Public Key Type", "Public Key Size",
            "Certificate Subject", "Certificate Issuer", "Certificate Not Before",
            "Certificate Expiry", "Days Until Expiry", "SHA-256 Fingerprint",
            "Self-Signed", "Hostname Mismatch", "Weak Protocol", "Weak Cipher",
            "HSTS Preload Eligible", "OCSP URLs", "SAN List",
        ]
        grid = QGridLayout()
        for i, key in enumerate(keys):
            card = StatCard(key)
            self.tls_cards[key] = card
            grid.addWidget(card, i // 3, i % 3)
        layout.addLayout(grid)

        layout.addWidget(QLabel("TLS Issues:"))
        self.tls_issues_view = QTextEdit()
        self.tls_issues_view.setReadOnly(True)
        layout.addWidget(self.tls_issues_view)

        return scroll

    # ------------------------------------------------------------------ #
    # Fingerprint tab
    # ------------------------------------------------------------------ #
    def _build_fingerprint_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.fingerprint_cards: dict[str, StatCard] = {}
        keys = ["Server Banner", "Powered By", "Web Server", "Reverse Proxy", "CDN",
                "Framework", "CMS", "Operating System"]
        grid = QGridLayout()
        for i, key in enumerate(keys):
            card = StatCard(key)
            self.fingerprint_cards[key] = card
            grid.addWidget(card, i // 3, i % 3)
        layout.addLayout(grid)

        layout.addWidget(QLabel("Detected Technologies:"))
        self.technologies_view = QTextEdit()
        self.technologies_view.setReadOnly(True)
        self.technologies_view.setFixedHeight(100)
        layout.addWidget(self.technologies_view)
        layout.addStretch()
        return widget

    # ------------------------------------------------------------------ #
    # Findings tab
    # ------------------------------------------------------------------ #
    def _build_findings_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        summary_row = QHBoxLayout()
        self.risk_chips: dict[str, QLabel] = {}
        for sev, color in SEVERITY_COLORS.items():
            chip = QLabel(f"{sev}: 0")
            chip.setStyleSheet(f"background:{color}22; color:{color}; border:1px solid {color}; "
                                f"border-radius:8px; padding:6px 14px; font-weight:700;")
            self.risk_chips[sev] = chip
            summary_row.addWidget(chip)
        summary_row.addStretch()
        layout.addLayout(summary_row)

        self.findings_table = make_table(["Severity", "Finding", "Category", "Description", "Remediation"])
        self.findings_table.setColumnWidth(0, 100)
        self.findings_table.setColumnWidth(1, 220)
        layout.addWidget(self.findings_table)

        return widget

    # ------------------------------------------------------------------ #
    # Theme
    # ------------------------------------------------------------------ #
    def _apply_theme(self) -> None:
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
                font-family: 'Segoe UI', 'Consolas', sans-serif;
                font-size: 13px;
            }}
            QToolBar {{
                background-color: {COLOR_PANEL};
                border: none;
                spacing: 6px;
                padding: 6px;
            }}
            QToolBar QToolButton {{
                background-color: {COLOR_CARD};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                padding: 6px 10px;
                color: {COLOR_TEXT};
            }}
            QToolBar QToolButton:hover {{
                background-color: {COLOR_BLUE}33;
                border-color: {COLOR_BLUE};
            }}
            QMenuBar {{
                background-color: {COLOR_PANEL};
                color: {COLOR_TEXT};
            }}
            QMenuBar::item:selected {{
                background-color: {COLOR_BLUE}44;
            }}
            QMenu {{
                background-color: {COLOR_CARD};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
            }}
            QMenu::item:selected {{
                background-color: {COLOR_BLUE}44;
            }}
            QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
                background-color: {COLOR_PANEL};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                padding: 7px;
                color: {COLOR_TEXT};
            }}
            QLineEdit:focus, QComboBox:focus {{
                border: 1px solid {COLOR_BLUE};
            }}
            QPushButton {{
                background-color: {COLOR_CARD};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                padding: 8px 16px;
                font-weight: 600;
                color: {COLOR_TEXT};
            }}
            QPushButton:hover {{
                border-color: {COLOR_BLUE};
                background-color: {COLOR_BLUE}22;
            }}
            #PrimaryButton {{
                background-color: {COLOR_GREEN};
                color: #06210F;
                border: none;
            }}
            #PrimaryButton:hover {{
                background-color: #16A34A;
            }}
            #DangerButton {{
                background-color: transparent;
                border: 1px solid {COLOR_RED};
                color: {COLOR_RED};
            }}
            #DangerButton:hover {{
                background-color: {COLOR_RED}22;
            }}
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 10px;
                background-color: {COLOR_PANEL};
                top: -1px;
            }}
            QTabBar::tab {{
                background-color: {COLOR_PANEL};
                color: {COLOR_TEXT_MUTED};
                padding: 9px 16px;
                border: 1px solid {COLOR_BORDER};
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_CARD};
                color: {COLOR_TEXT};
                font-weight: 700;
                border-color: {COLOR_BLUE};
            }}
            QTableWidget {{
                background-color: {COLOR_PANEL};
                gridline-color: {COLOR_BORDER};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                alternate-background-color: {COLOR_CARD};
            }}
            QHeaderView::section {{
                background-color: {COLOR_CARD};
                color: {COLOR_TEXT_MUTED};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {COLOR_BORDER};
                font-weight: 700;
                text-transform: uppercase;
                font-size: 10px;
            }}
            QScrollArea {{
                border: none;
            }}
            QStatusBar {{
                background-color: {COLOR_PANEL};
                color: {COLOR_TEXT_MUTED};
            }}
            QProgressBar {{
                background-color: {COLOR_CARD};
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {COLOR_BLUE};
                border-radius: 3px;
            }}
        """)

    # ------------------------------------------------------------------ #
    # Scan lifecycle
    # ------------------------------------------------------------------ #
    def start_scan(self) -> None:
        raw_url = self.url_input.text().strip()
        if not raw_url:
            QMessageBox.warning(self, "Missing Target", "Please enter a target URL to scan.")
            return
        url = normalize_url(raw_url)
        if not is_valid_url(url):
            QMessageBox.warning(self, "Invalid URL", f"'{raw_url}' does not look like a valid URL.")
            return

        self.scan_options.method = self.method_badge.currentText()

        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.stage_bar.reset()
        self.status_label.setText(f"Scanning {url} ...")

        self.scan_worker = ScanWorker(url, self.scan_options, analyst=self.analyst_name)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished_scan.connect(self._on_scan_finished)
        self.scan_worker.failed.connect(self._on_scan_failed)
        self.scan_worker.start()

    def cancel_scan(self) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.status_label.setText("Cancelling scan...")

    def _on_scan_progress(self, stage: str, message: str) -> None:
        self.stage_bar.set_stage(stage)
        self.status_label.setText(message)

    def _on_scan_finished(self, result: ScanResult) -> None:
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        if result.error:
            self.status_label.setText(f"Scan failed: {result.error}")
            QMessageBox.critical(self, "Scan Failed", result.error)
            return

        self.current_result = result
        self.current_data = result.to_dict()
        self._populate_all_tabs(self.current_data)
        self.status_label.setText(
            f"Scan completed for {result.network.final_url} — Score {result.score.score}/100 ({result.score.grade})"
        )

    def _on_scan_failed(self, message: str) -> None:
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Scan crashed: {message}")
        QMessageBox.critical(self, "Scan Error", message)

    # ------------------------------------------------------------------ #
    # Populate tabs from scan result dict
    # ------------------------------------------------------------------ #
    def _populate_all_tabs(self, data: dict) -> None:
        self._populate_dashboard(data)
        self._populate_headers(data)
        self._populate_csp(data)
        self._populate_cookies(data)
        self._populate_redirects(data)
        self._populate_tls(data)
        self._populate_fingerprint(data)
        self._populate_findings(data)

    def _populate_dashboard(self, data: dict) -> None:
        network = data["network"]
        tls = data["tls"]
        fingerprint = data["fingerprint"]
        score = data["score"]

        self.score_gauge.set_score(score["score"], score["grade"], score["color"])

        findings = data["findings"]
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        self.exec_summary_label.setText(
            f"<b>{network.get('target_url','')}</b> was scanned on {data.get('timestamp','')} by "
            f"{data.get('analyst','')}.<br><br>"
            f"Total findings: <b>{len(findings)}</b> — "
            f"Critical: {counts['Critical']}, High: {counts['High']}, Medium: {counts['Medium']}, "
            f"Low: {counts['Low']}, Info: {counts['Informational']}."
        )

        mapping = {
            "Target URL": network.get("target_url"),
            "Final URL": network.get("final_url"),
            "Resolved IP": network.get("resolved_ip"),
            "IPv6": network.get("resolved_ipv6"),
            "Reverse DNS": network.get("reverse_dns"),
            "Country": network.get("country"),
            "Hosting Provider": network.get("hosting_provider"),
            "ASN": network.get("asn"),
            "Protocol": network.get("protocol"),
            "HTTP Version": network.get("http_version"),
            "Response Time": f"{network.get('response_time_ms')} ms" if network.get("response_time_ms") else None,
            "Redirect Count": network.get("redirect_count"),
            "Total Headers": network.get("total_headers"),

            "TLS Version": tls.get("tls_version"),
            "Cipher Suite": tls.get("cipher_suite"),
            "Certificate Status": "EXPIRED" if tls.get("is_expired") else ("Self-Signed" if tls.get("is_self_signed") else ("Valid" if tls.get("supported") else "N/A")),
            "Certificate Expiry": tls.get("certificate_expiry"),
            "Days Until Expiry": tls.get("days_until_expiry"),
            "Certificate Issuer": tls.get("certificate_issuer"),
            "Certificate Subject": tls.get("certificate_subject"),
            "Public Key": f"{tls.get('public_key_type')} {tls.get('public_key_size')} bits" if tls.get("public_key_type") else None,
            "SHA-256 Fingerprint": tls.get("sha256_fingerprint"),
            "HSTS Preload Eligible": "Yes" if tls.get("hsts_preload_eligible") else "No",

            "Server Banner": fingerprint.get("server_banner"),
            "Powered By": fingerprint.get("powered_by"),
            "Web Server": fingerprint.get("web_server"),
            "Reverse Proxy": fingerprint.get("reverse_proxy"),
            "CDN": fingerprint.get("cdn"),
            "Framework": fingerprint.get("framework"),
            "CMS": fingerprint.get("cms"),
            "Operating System": fingerprint.get("operating_system"),
            "Technologies": ", ".join(fingerprint.get("technologies", [])) or "None detected",
        }
        for key, value in mapping.items():
            if key in self.dashboard_cards:
                accent = COLOR_RED if key == "Certificate Status" and value == "EXPIRED" else COLOR_TEXT
                self.dashboard_cards[key].set_value(str(value) if value not in (None, "") else "—", accent)

    def _populate_headers(self, data: dict) -> None:
        headers = data["headers"]
        self._header_dicts = headers
        table = self.headers_table
        table.setRowCount(len(headers))
        for row, h in enumerate(headers):
            table.setItem(row, 0, QTableWidgetItem(h["name"]))
            status_item = QTableWidgetItem(h["status"])
            status_item.setForeground(QColor(STATUS_COLORS.get(h["status"], COLOR_TEXT)))
            table.setItem(row, 1, status_item)
            sev_item = QTableWidgetItem(h["severity"])
            sev_item.setForeground(QColor(SEVERITY_COLORS.get(h["severity"], COLOR_TEXT)))
            table.setItem(row, 2, sev_item)
            table.setItem(row, 3, QTableWidgetItem(h.get("current_value") or "—"))
            table.setItem(row, 4, QTableWidgetItem(h.get("recommended_value") or "—"))
        table.resizeRowsToContents()

    def _populate_csp(self, data: dict) -> None:
        csp = data["csp"]
        self.csp_raw_view.setPlainText(csp.get("raw") or "(No Content-Security-Policy header present)")

        directives = csp.get("directives", [])
        table = self.csp_directives_table
        table.setRowCount(len(directives))
        for row, d in enumerate(directives):
            table.setItem(row, 0, QTableWidgetItem(d["name"]))
            table.setItem(row, 1, QTableWidgetItem(" ".join(d.get("values", []))))
            issues_text = "; ".join(d.get("issues", [])) or "None"
            issue_item = QTableWidgetItem(issues_text)
            if d.get("issues"):
                issue_item.setForeground(QColor(COLOR_RED))
            table.setItem(row, 2, issue_item)
        table.resizeRowsToContents()

        issues = csp.get("dangerous_findings", [])
        self.csp_issues_view.setPlainText("\n".join(f"• {i}" for i in issues) or "No CSP issues detected.")

    def _populate_cookies(self, data: dict) -> None:
        cookies = data["cookies"]
        table = self.cookies_table
        table.setRowCount(len(cookies))
        for row, c in enumerate(cookies):
            table.setItem(row, 0, QTableWidgetItem(c["name"]))
            table.setItem(row, 1, self._bool_item(c["secure"]))
            table.setItem(row, 2, self._bool_item(c["http_only"]))
            table.setItem(row, 3, QTableWidgetItem(c.get("same_site") or "—"))
            table.setItem(row, 4, QTableWidgetItem(c.get("path") or "—"))
            table.setItem(row, 5, QTableWidgetItem(c.get("domain") or "—"))
            table.setItem(row, 6, self._bool_item(c["persistent"]))
            table.setItem(row, 7, QTableWidgetItem(c.get("priority") or "—"))
            table.setItem(row, 8, self._bool_item(c["partitioned"]))
            issues_item = QTableWidgetItem("; ".join(c.get("issues", [])) or "None")
            if c.get("issues"):
                issues_item.setForeground(QColor(COLOR_RED))
            table.setItem(row, 9, issues_item)
        table.resizeRowsToContents()

    def _bool_item(self, value: bool) -> QTableWidgetItem:
        item = QTableWidgetItem("Yes" if value else "No")
        item.setForeground(QColor(COLOR_GREEN if value else COLOR_RED))
        return item

    def _populate_redirects(self, data: dict) -> None:
        redirects = data["redirects"]
        hops = redirects.get("hops", [])
        table = self.redirects_table
        table.setRowCount(len(hops))
        for row, h in enumerate(hops):
            table.setItem(row, 0, QTableWidgetItem(str(h["order"])))
            table.setItem(row, 1, QTableWidgetItem(h["url"]))
            table.setItem(row, 2, QTableWidgetItem(str(h["status_code"])))
            table.setItem(row, 3, QTableWidgetItem(h.get("location") or "—"))
            table.setItem(row, 4, QTableWidgetItem("HTTPS" if h["is_https"] else "HTTP"))
            table.setItem(row, 5, self._bool_item(h["permanent"]))
        table.resizeRowsToContents()

        issues = redirects.get("issues", [])
        summary = (
            f"Total redirects: {redirects.get('total_redirects', 0)}  |  "
            f"HTTPS downgrade: {'Yes' if redirects.get('https_downgrade') else 'No'}  |  "
            f"Mixed protocols: {'Yes' if redirects.get('mixed_redirects') else 'No'}  |  "
            f"Loop detected: {'Yes' if redirects.get('redirect_loop_detected') else 'No'}"
        )
        if issues:
            summary += "\n\nIssues:\n" + "\n".join(f"• {i}" for i in issues)
        self.redirect_summary_label.setText(summary)

    def _populate_tls(self, data: dict) -> None:
        tls = data["tls"]
        mapping = {
            "TLS Version": tls.get("tls_version"),
            "Cipher Suite": tls.get("cipher_suite"),
            "Cipher Bits": tls.get("cipher_bits"),
            "Public Key Type": tls.get("public_key_type"),
            "Public Key Size": f"{tls.get('public_key_size')} bits" if tls.get("public_key_size") else None,
            "Certificate Subject": tls.get("certificate_subject"),
            "Certificate Issuer": tls.get("certificate_issuer"),
            "Certificate Not Before": tls.get("certificate_not_before"),
            "Certificate Expiry": tls.get("certificate_expiry"),
            "Days Until Expiry": tls.get("days_until_expiry"),
            "SHA-256 Fingerprint": tls.get("sha256_fingerprint"),
            "Self-Signed": "Yes" if tls.get("is_self_signed") else "No",
            "Hostname Mismatch": "Yes" if tls.get("hostname_mismatch") else "No",
            "Weak Protocol": "Yes" if tls.get("weak_protocol") else "No",
            "Weak Cipher": "Yes" if tls.get("weak_cipher") else "No",
            "HSTS Preload Eligible": "Yes" if tls.get("hsts_preload_eligible") else "No",
            "OCSP URLs": ", ".join(tls.get("ocsp_urls", [])) or "None",
            "SAN List": ", ".join(tls.get("san_list", [])) or "None",
        }
        for key, value in mapping.items():
            if key in self.tls_cards:
                accent = COLOR_RED if key in ("Weak Protocol", "Weak Cipher", "Hostname Mismatch") and value == "Yes" else COLOR_TEXT
                self.tls_cards[key].set_value(str(value) if value not in (None, "") else "—", accent)

        issues = tls.get("issues", [])
        self.tls_issues_view.setPlainText("\n".join(f"• {i}" for i in issues) or "No TLS issues detected.")

    def _populate_fingerprint(self, data: dict) -> None:
        fp = data["fingerprint"]
        mapping = {
            "Server Banner": fp.get("server_banner"),
            "Powered By": fp.get("powered_by"),
            "Web Server": fp.get("web_server"),
            "Reverse Proxy": fp.get("reverse_proxy"),
            "CDN": fp.get("cdn"),
            "Framework": fp.get("framework"),
            "CMS": fp.get("cms"),
            "Operating System": fp.get("operating_system"),
        }
        for key, value in mapping.items():
            if key in self.fingerprint_cards:
                self.fingerprint_cards[key].set_value(str(value) if value else "Not detected")

        techs = fp.get("technologies", [])
        self.technologies_view.setPlainText(", ".join(techs) if techs else "No specific technologies fingerprinted.")

    def _populate_findings(self, data: dict) -> None:
        findings = data["findings"]
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        for sev, chip in self.risk_chips.items():
            chip.setText(f"{sev}: {counts.get(sev, 0)}")

        table = self.findings_table
        table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            sev_item = QTableWidgetItem(f["severity"])
            sev_item.setForeground(QColor(SEVERITY_COLORS.get(f["severity"], COLOR_TEXT)))
            table.setItem(row, 0, sev_item)
            table.setItem(row, 1, QTableWidgetItem(f["title"]))
            table.setItem(row, 2, QTableWidgetItem(f.get("category", "")))
            table.setItem(row, 3, QTableWidgetItem(f.get("description", "")))
            table.setItem(row, 4, QTableWidgetItem(f.get("remediation", "")))
        table.resizeRowsToContents()

    # ------------------------------------------------------------------ #
    # Options / about
    # ------------------------------------------------------------------ #
    def open_options_dialog(self) -> None:
        dlg = ScanOptionsDialog(self.scan_options, self)
        if dlg.exec() == dlg.Accepted:
            self.scan_options = dlg.get_options()
            self.status_label.setText("Advanced scan options updated.")

    def set_analyst_name(self) -> None:
        name, ok = QInputDialog.getText(self, "Analyst Name", "Enter analyst name:", text=self.analyst_name)
        if ok and name.strip():
            self.analyst_name = name.strip()

    def show_about(self) -> None:
        QMessageBox.about(
            self, f"About {APP_NAME}",
            f"<h3>{APP_NAME} v{APP_VERSION}</h3>"
            "<p>A professional HTTP security header, TLS, cookie and fingerprint analyzer "
            "for penetration testers, red teamers, and security auditors.</p>"
            "<p>Built with PySide6, requests, urllib3, and cryptography.</p>"
            "<p>For authorized security assessment use only.</p>"
        )

    # ------------------------------------------------------------------ #
    def closeEvent(self, event) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.scan_worker.wait(2000)
        event.accept()
