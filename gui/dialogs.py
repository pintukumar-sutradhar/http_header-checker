"""
gui/dialogs.py
================
Modal dialogs used by the main window:

- ScanOptionsDialog: advanced request configuration (method, headers, auth,
  proxy, timeouts, retries, redirects, SSL verification, User-Agent, IP mode).
- HeaderDetailDialog: deep-dive view for a single header result showing all
  OWASP/Mozilla/Microsoft guidance and secure example config.
"""
from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit,
    QComboBox, QSpinBox, QCheckBox, QPushButton, QPlainTextEdit, QTabWidget,
    QWidget, QTextEdit,
)

from utils.models import ScanOptions


class ScanOptionsDialog(QDialog):
    """Advanced scan configuration dialog."""

    def __init__(self, options: ScanOptions, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Advanced Scan Options")
        self.resize(560, 620)
        self.options = options
        self._build_ui()
        self._load_options()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # --- Request tab ---
        request_tab = QWidget()
        form = QFormLayout(request_tab)

        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "HEAD", "OPTIONS"])
        form.addRow("HTTP Method:", self.method_combo)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setSuffix(" sec")
        form.addRow("Timeout:", self.timeout_spin)

        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        form.addRow("Retries:", self.retries_spin)

        self.follow_redirects_chk = QCheckBox("Follow redirects")
        form.addRow(self.follow_redirects_chk)

        self.verify_ssl_chk = QCheckBox("Verify SSL certificates (strict)")
        form.addRow(self.verify_ssl_chk)

        self.ipv4_chk = QCheckBox("Force IPv4")
        self.ipv6_chk = QCheckBox("Also resolve IPv6")
        form.addRow(self.ipv4_chk)
        form.addRow(self.ipv6_chk)

        tabs.addTab(request_tab, "Request")

        # --- Auth / Headers tab ---
        auth_tab = QWidget()
        auth_layout = QFormLayout(auth_tab)

        self.bearer_edit = QLineEdit()
        self.bearer_edit.setPlaceholderText("Bearer token (optional)")
        auth_layout.addRow("Bearer Token:", self.bearer_edit)

        self.cookies_edit = QLineEdit()
        self.cookies_edit.setPlaceholderText("name1=value1; name2=value2")
        auth_layout.addRow("Cookies:", self.cookies_edit)

        self.custom_headers_edit = QPlainTextEdit()
        self.custom_headers_edit.setPlaceholderText("X-Custom-Header: value\nAnother-Header: value2")
        self.custom_headers_edit.setFixedHeight(100)
        auth_layout.addRow("Custom Headers:", self.custom_headers_edit)

        tabs.addTab(auth_tab, "Auth && Headers")

        # --- Network tab ---
        net_tab = QWidget()
        net_layout = QFormLayout(net_tab)

        self.proxy_edit = QLineEdit()
        self.proxy_edit.setPlaceholderText("http://127.0.0.1:8080")
        net_layout.addRow("HTTP(S) Proxy:", self.proxy_edit)

        self.socks_edit = QLineEdit()
        self.socks_edit.setPlaceholderText("socks5://127.0.0.1:9050")
        net_layout.addRow("SOCKS Proxy:", self.socks_edit)

        self.ua_mode_combo = QComboBox()
        self.ua_mode_combo.addItems(["default", "random", "custom"])
        net_layout.addRow("User-Agent Mode:", self.ua_mode_combo)

        self.custom_ua_edit = QLineEdit()
        self.custom_ua_edit.setPlaceholderText("Custom User-Agent string")
        net_layout.addRow("Custom User-Agent:", self.custom_ua_edit)

        tabs.addTab(net_tab, "Network")

        # --- Buttons ---
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        save_btn = QPushButton("Save Options")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        layout.addLayout(btn_row)

    def _load_options(self) -> None:
        o = self.options
        self.method_combo.setCurrentText(o.method)
        self.timeout_spin.setValue(o.timeout)
        self.retries_spin.setValue(o.retries)
        self.follow_redirects_chk.setChecked(o.follow_redirects)
        self.verify_ssl_chk.setChecked(o.verify_ssl)
        self.ipv4_chk.setChecked(o.force_ipv4)
        self.ipv6_chk.setChecked(o.force_ipv6)
        self.bearer_edit.setText(o.bearer_token)
        self.cookies_edit.setText("; ".join(f"{k}={v}" for k, v in o.cookies.items()))
        self.custom_headers_edit.setPlainText(
            "\n".join(f"{k}: {v}" for k, v in o.custom_headers.items())
        )
        self.proxy_edit.setText(o.proxy_url)
        self.socks_edit.setText(o.socks_proxy_url)
        self.ua_mode_combo.setCurrentText(o.user_agent_mode)
        self.custom_ua_edit.setText(o.custom_user_agent)

    def get_options(self) -> ScanOptions:
        custom_headers = {}
        for line in self.custom_headers_edit.toPlainText().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                custom_headers[k.strip()] = v.strip()

        cookies = {}
        cookie_text = self.cookies_edit.text().strip()
        if cookie_text:
            for part in cookie_text.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()

        return ScanOptions(
            method=self.method_combo.currentText(),
            custom_headers=custom_headers,
            bearer_token=self.bearer_edit.text().strip(),
            cookies=cookies,
            proxy_url=self.proxy_edit.text().strip(),
            socks_proxy_url=self.socks_edit.text().strip(),
            timeout=self.timeout_spin.value(),
            retries=self.retries_spin.value(),
            follow_redirects=self.follow_redirects_chk.isChecked(),
            verify_ssl=self.verify_ssl_chk.isChecked(),
            user_agent_mode=self.ua_mode_combo.currentText(),
            custom_user_agent=self.custom_ua_edit.text().strip(),
            force_ipv4=self.ipv4_chk.isChecked(),
            force_ipv6=self.ipv6_chk.isChecked(),
        )


class HeaderDetailDialog(QDialog):
    """Deep-dive detail view for a single HeaderResult (as dict)."""

    def __init__(self, header: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Header Detail — {header.get('name','')}")
        self.resize(620, 520)
        layout = QVBoxLayout(self)

        text = QTextEdit()
        text.setReadOnly(True)
        content = f"""
        <h2>{header.get('name','')}</h2>
        <p><b>Status:</b> {header.get('status','')}<br>
        <b>Severity:</b> {header.get('severity','')}</p>
        <p><b>Current Value:</b><br><code>{header.get('current_value') or '(not present)'}</code></p>
        <p><b>Recommended Value:</b><br><code>{header.get('recommended_value','')}</code></p>
        <p><b>Description:</b><br>{header.get('description','')}</p>
        <p><b>Why It Matters:</b><br>{header.get('why_it_matters','')}</p>
        <p><b>OWASP Reference:</b><br>{header.get('owasp_reference') or 'N/A'}</p>
        <p><b>Mozilla Recommendation:</b><br>{header.get('mozilla_recommendation') or 'N/A'}</p>
        <p><b>Microsoft Recommendation:</b><br>{header.get('microsoft_recommendation') or 'N/A'}</p>
        <p><b>Example Secure Configuration:</b><br><code>{header.get('example_secure_config') or 'N/A'}</code></p>
        """
        text.setHtml(content)
        layout.addWidget(text)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
