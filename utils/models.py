"""
utils/models.py
================
Central data model definitions used across the entire application.

Keeping all dataclasses in one module avoids circular imports between the
scanner engine, the reporting engine and the GUI layer, and gives a single
authoritative schema for a "scan result" that can be serialized to
JSON/CSV/PDF/HTML or persisted in the scan history database.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    """Risk severity classification, aligned with common VA/PT report styles."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "#EF4444",
            Severity.HIGH: "#F97316",
            Severity.MEDIUM: "#F59E0B",
            Severity.LOW: "#3B82F6",
            Severity.INFO: "#94A3B8",
        }[self]

    @property
    def weight(self) -> int:
        """Numeric weight used for scoring / sorting (higher = worse)."""
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 12,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }[self]


class HeaderStatus(str, Enum):
    PRESENT = "Present"
    MISSING = "Missing"
    WEAK = "Weak"
    MISCONFIGURED = "Misconfigured"
    DEPRECATED = "Deprecated"

    @property
    def color(self) -> str:
        return {
            HeaderStatus.PRESENT: "#22C55E",
            HeaderStatus.MISSING: "#EF4444",
            HeaderStatus.WEAK: "#F59E0B",
            HeaderStatus.MISCONFIGURED: "#F97316",
            HeaderStatus.DEPRECATED: "#94A3B8",
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
    """A single discrete security finding / issue."""
    title: str
    severity: Severity
    description: str = ""
    business_impact: str = ""
    remediation: str = ""
    cvss_like_score: float = 0.0
    references: list[str] = field(default_factory=list)
    category: str = "General"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class HeaderResult:
    """Full evaluation of a single HTTP header."""
    name: str
    status: HeaderStatus
    severity: Severity
    current_value: Optional[str] = None
    recommended_value: str = ""
    description: str = ""
    why_it_matters: str = ""
    owasp_reference: str = ""
    mozilla_recommendation: str = ""
    microsoft_recommendation: str = ""
    example_secure_config: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
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
    score_penalty: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "present": self.present,
            "directives": [asdict(d) for d in self.directives],
            "dangerous_findings": self.dangerous_findings,
            "score_penalty": self.score_penalty,
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
    same_site: Optional[str] = None
    path: Optional[str] = None
    domain: Optional[str] = None
    expires: Optional[str] = None
    persistent: bool = False
    session_cookie: bool = True
    priority: Optional[str] = None
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
    location: Optional[str]
    headers: dict[str, str]
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
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_bits: Optional[int] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[str] = None
    certificate_not_before: Optional[str] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    hostname_mismatch: bool = False
    san_list: list[str] = field(default_factory=list)
    sha256_fingerprint: Optional[str] = None
    public_key_size: Optional[int] = None
    public_key_type: Optional[str] = None
    weak_cipher: bool = False
    weak_protocol: bool = False
    hsts_preload_eligible: bool = False
    ocsp_urls: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Fingerprint
# --------------------------------------------------------------------------- #
@dataclass
class FingerprintResult:
    server_banner: Optional[str] = None
    powered_by: Optional[str] = None
    web_server: Optional[str] = None
    reverse_proxy: Optional[str] = None
    cdn: Optional[str] = None
    framework: Optional[str] = None
    operating_system: Optional[str] = None
    cms: Optional[str] = None
    language_runtime: Optional[str] = None
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
    resolved_ip: Optional[str] = None
    resolved_ipv6: Optional[str] = None
    reverse_dns: Optional[str] = None
    country: Optional[str] = None
    hosting_provider: Optional[str] = None
    asn: Optional[str] = None
    protocol: Optional[str] = None
    http_version: Optional[str] = None
    response_time_ms: Optional[float] = None
    redirect_count: int = 0
    total_headers: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Score
# --------------------------------------------------------------------------- #
@dataclass
class SecurityScore:
    score: int = 100
    grade: str = "A+"
    color: str = "#22C55E"

    @staticmethod
    def grade_for(score: int) -> tuple[str, str]:
        """Return (grade, color) for a numeric score 0-100."""
        if score >= 95:
            return "A+", "#22C55E"
        if score >= 85:
            return "A", "#22C55E"
        if score >= 70:
            return "B", "#3B82F6"
        if score >= 55:
            return "C", "#F59E0B"
        if score >= 40:
            return "D", "#F97316"
        return "F", "#EF4444"

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
    tool_version: str = "1.0.0"

    network: NetworkInfo = field(default_factory=NetworkInfo)
    tls: TLSAnalysis = field(default_factory=TLSAnalysis)
    fingerprint: FingerprintResult = field(default_factory=FingerprintResult)
    headers: list[HeaderResult] = field(default_factory=list)
    csp: CSPAnalysis = field(default_factory=CSPAnalysis)
    cookies: list[CookieResult] = field(default_factory=list)
    redirects: RedirectAnalysis = field(default_factory=RedirectAnalysis)
    findings: list[Finding] = field(default_factory=list)
    score: SecurityScore = field(default_factory=SecurityScore)
    raw_headers: dict[str, str] = field(default_factory=dict)
    options: ScanOptions = field(default_factory=ScanOptions)
    error: Optional[str] = None

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
            "score": self.score.to_dict(),
            "raw_headers": self.raw_headers,
            "options": self.options.to_dict(),
            "error": self.error,
        }
