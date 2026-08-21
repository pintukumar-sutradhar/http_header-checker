"""
header_checker.utils.models
============================
Central data model definitions used across the entire application.

Keeping all dataclasses in one module avoids circular imports between the
scan engine, the reporting layer, the CLI and the web dashboard, and gives
a single authoritative schema for a scan result.

Design principles (v2):
* Header verdicts use four plain-language statuses: Pass / Warning /
  Fail / Info -- no jargon, no numeric scores or grades.
* Informational observations never appear as findings; the findings
  register only contains actionable issues.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .constants import APP_VERSION


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    """
    Risk severity for actionable findings.

    ``INFO`` never appears in the findings register -- it is only used by
    the header knowledge base to mark observations that are not actionable.
    """
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "#DC2626",
            Severity.HIGH: "#EA580C",
            Severity.MEDIUM: "#D97706",
            Severity.LOW: "#2563EB",
            Severity.INFO: "#64748B",
        }[self]

    @property
    def weight(self) -> int:
        """Numeric weight used for sorting / CI gates (higher = worse)."""
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 12,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }[self]


class HeaderStatus(str, Enum):
    """Plain-language verdict for a single HTTP header."""
    PASS = "Pass"
    WARN = "Warning"
    FAIL = "Fail"
    INFO = "Info"

    @property
    def color(self) -> str:
        return {
            HeaderStatus.PASS: "#16A34A",
            HeaderStatus.WARN: "#D97706",
            HeaderStatus.FAIL: "#DC2626",
            HeaderStatus.INFO: "#64748B",
        }[self]


class ScanStage(str, Enum):
    QUEUED = "Queued"
    RESOLVING_DNS = "Resolving DNS"
    CONNECTING = "Connecting"
    TLS_HANDSHAKE = "TLS Handshake"
    SENDING_REQUEST = "Sending Request"
    RECEIVING_HEADERS = "Receiving Headers"
    PARSING = "Parsing"
    ANALYZING = "Analyzing"
    GENERATING_REPORT = "Generating Report"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


# --------------------------------------------------------------------------- #
# Findings & header analysis
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A single actionable security issue."""
    title: str
    severity: Severity
    description: str = ""
    business_impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    category: str = "General"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class HeaderResult:
    """Evaluation of a single HTTP header against best practice."""
    name: str
    status: HeaderStatus
    current_value: str | None = None
    recommended_value: str = ""
    summary: str = ""            # one-line plain-language explanation of the verdict
    description: str = ""        # what the header does
    why_it_matters: str = ""
    example_secure_config: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# --------------------------------------------------------------------------- #
# CSP
# --------------------------------------------------------------------------- #
@dataclass
class CSPDirective:
    name: str
    values: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


@dataclass
class CSPAnalysis:
    raw: str = ""
    present: bool = False
    directives: list[CSPDirective] = field(default_factory=list)
    dangerous_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "present": self.present,
            "directives": [asdict(d) for d in self.directives],
            "dangerous_findings": self.dangerous_findings,
        }


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #
@dataclass
class CookieResult:
    name: str
    value_preview: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    path: str | None = None
    domain: str | None = None
    expires: str | None = None
    persistent: bool = False
    session_cookie: bool = True
    partitioned: bool = False
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Redirects
# --------------------------------------------------------------------------- #
@dataclass
class RedirectHop:
    order: int
    url: str
    status_code: int
    location: str | None
    is_https: bool
    permanent: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RedirectAnalysis:
    hops: list[RedirectHop] = field(default_factory=list)
    total_redirects: int = 0
    https_downgrade: bool = False
    mixed_redirects: bool = False
    redirect_loop_detected: bool = False
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hops": [h.to_dict() for h in self.hops],
            "total_redirects": self.total_redirects,
            "https_downgrade": self.https_downgrade,
            "mixed_redirects": self.mixed_redirects,
            "redirect_loop_detected": self.redirect_loop_detected,
            "issues": self.issues,
        }


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #
@dataclass
class TLSAnalysis:
    supported: bool = False
    tls_version: str | None = None
    cipher_suite: str | None = None
    cipher_bits: int | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_expiry: str | None = None
    days_until_expiry: int | None = None
    is_expired: bool = False
    is_self_signed: bool = False
    hostname_mismatch: bool = False
    san_list: list[str] = field(default_factory=list)
    sha256_fingerprint: str | None = None
    public_key_size: int | None = None
    public_key_type: str | None = None
    weak_cipher: bool = False
    weak_protocol: bool = False
    issues: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Fingerprint
# --------------------------------------------------------------------------- #
@dataclass
class FingerprintResult:
    server_banner: str | None = None
    powered_by: str | None = None
    web_server: str | None = None
    reverse_proxy: str | None = None
    cdn: str | None = None
    framework: str | None = None
    operating_system: str | None = None
    cms: str | None = None
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Network / host info
# --------------------------------------------------------------------------- #
@dataclass
class NetworkInfo:
    target_url: str = ""
    final_url: str = ""
    resolved_ip: str | None = None
    resolved_ipv6: str | None = None
    country: str | None = None
    hosting_provider: str | None = None
    protocol: str | None = None
    http_version: str | None = None
    response_time_ms: float | None = None
    redirect_count: int = 0
    total_headers: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Scan options (request configuration)
# --------------------------------------------------------------------------- #
@dataclass
class ScanOptions:
    method: str = "GET"
    custom_headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    proxy_url: str = ""
    socks_proxy_url: str = ""
    timeout: int = 15
    retries: int = 1
    follow_redirects: bool = True
    verify_ssl: bool = False
    user_agent_mode: str = "default"  # default | random | custom
    custom_user_agent: str = ""
    force_ipv4: bool = False
    force_ipv6: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Top level scan result
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    analyst: str = "Unknown Analyst"
    tool_version: str = APP_VERSION

    network: NetworkInfo = field(default_factory=NetworkInfo)
    tls: TLSAnalysis = field(default_factory=TLSAnalysis)
    fingerprint: FingerprintResult = field(default_factory=FingerprintResult)
    headers: list[HeaderResult] = field(default_factory=list)
    csp: CSPAnalysis = field(default_factory=CSPAnalysis)
    cookies: list[CookieResult] = field(default_factory=list)
    redirects: RedirectAnalysis = field(default_factory=RedirectAnalysis)
    findings: list[Finding] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    options: ScanOptions = field(default_factory=ScanOptions)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "analyst": self.analyst,
            "tool_version": self.tool_version,
            "network": self.network.to_dict(),
            "tls": self.tls.to_dict(),
            "fingerprint": self.fingerprint.to_dict(),
            "headers": [h.to_dict() for h in self.headers],
            "csp": self.csp.to_dict(),
            "cookies": [c.to_dict() for c in self.cookies],
            "redirects": self.redirects.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "raw_headers": self.raw_headers,
            "options": self.options.to_dict(),
            "error": self.error,
        }
