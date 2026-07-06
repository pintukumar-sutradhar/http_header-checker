"""
scanner/scan_engine.py
=========================
Top-level orchestrator that ties together DNS resolution, HTTP requests,
TLS analysis, header evaluation, CSP parsing, cookie analysis, redirect
analysis, fingerprinting and scoring into a single ``ScanResult``.

This module contains NO Qt/GUI imports -- it is pure logic and can be
reused headlessly (e.g. from a CLI or test suite). The GUI drives it via
``gui/scan_worker.py`` which wraps ``run_scan`` in a QThread and emits
progress signals for each ``ScanStage``.
"""
from __future__ import annotations

import time
from typing import Callable, Optional
from urllib.parse import urlparse

import requests
import urllib3

from utils.logger import get_logger
from utils.models import (
    ScanResult, NetworkInfo, ScanOptions, ScanStage, Finding, Severity,
)
from utils.network import (
    normalize_url, resolve_ipv4, resolve_ipv6, reverse_dns, geolocate_ip,
    pick_user_agent, get_hostname,
)

from .header_scanner import evaluate_headers
from .csp_analyzer import parse_csp, csp_findings
from .cookie_scanner import parse_all_cookies, cookie_findings
from .redirect_scanner import analyze_redirects, redirect_findings
from .tls_scanner import analyze_tls, tls_findings
from .fingerprint import fingerprint_server
from .scoring import compute_score

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger()

ProgressCallback = Optional[Callable[[ScanStage, str], None]]


class ScanCancelled(Exception):
    """Raised internally when a scan is cooperatively cancelled."""


def _emit(cb: ProgressCallback, stage: ScanStage, message: str = "") -> None:
    if cb:
        cb(stage, message or stage.value)


def _build_requests_kwargs(options: ScanOptions, url: str) -> dict:
    headers = dict(options.custom_headers) if options.custom_headers else {}
    headers.setdefault("User-Agent", pick_user_agent(options.user_agent_mode, options.custom_user_agent))
    headers.setdefault("Accept", "*/*")

    if options.bearer_token:
        headers["Authorization"] = f"Bearer {options.bearer_token}"

    proxies = {}
    if options.proxy_url:
        proxies["http"] = options.proxy_url
        proxies["https"] = options.proxy_url
    if options.socks_proxy_url:
        proxies["http"] = options.socks_proxy_url
        proxies["https"] = options.socks_proxy_url

    kwargs = dict(
        headers=headers,
        allow_redirects=options.follow_redirects,
        verify=options.verify_ssl,
        timeout=options.timeout,
        cookies=options.cookies or None,
    )
    if proxies:
        kwargs["proxies"] = proxies
    return kwargs


def run_scan(
    raw_url: str,
    options: Optional[ScanOptions] = None,
    progress_cb: ProgressCallback = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    analyst: str = "Unknown Analyst",
) -> ScanResult:
    """
    Execute a complete security scan of ``raw_url`` and return a populated
    ``ScanResult``. Designed to run inside a worker thread; progress is
    reported via ``progress_cb(stage, message)`` and cooperative
    cancellation is supported via ``cancel_check()`` returning True.
    """
    options = options or ScanOptions()
    result = ScanResult(analyst=analyst, options=options)

    def check_cancel():
        if cancel_check and cancel_check():
            raise ScanCancelled()

    try:
        url = normalize_url(raw_url)
        result.network.target_url = url
        hostname = get_hostname(url)

        # ---------------------------------------------------------- DNS ----
        _emit(progress_cb, ScanStage.RESOLVING_DNS, f"Resolving DNS for {hostname}...")
        check_cancel()
        ipv4 = resolve_ipv4(hostname)
        ipv6 = resolve_ipv6(hostname) if options.force_ipv6 or not options.force_ipv4 else None
        result.network.resolved_ip = ipv4
        result.network.resolved_ipv6 = ipv6
        if ipv4:
            result.network.reverse_dns = reverse_dns(ipv4)
            geo = geolocate_ip(ipv4)
            result.network.country = geo.get("country")
            result.network.hosting_provider = geo.get("hosting_provider")
            result.network.asn = geo.get("asn")

        # ----------------------------------------------------- CONNECT -----
        _emit(progress_cb, ScanStage.CONNECTING, f"Connecting to {hostname}...")
        check_cancel()

        # ------------------------------------------------- TLS HANDSHAKE ---
        parsed = urlparse(url)
        if parsed.scheme == "https":
            _emit(progress_cb, ScanStage.TLS_HANDSHAKE, "Performing TLS handshake...")
            check_cancel()
            port = parsed.port or 443
            result.tls = analyze_tls(hostname, port=port, timeout=options.timeout)

        # ------------------------------------------------- SEND REQUEST ----
        _emit(progress_cb, ScanStage.SENDING_REQUEST, f"Sending {options.method} request...")
        check_cancel()

        session = requests.Session()
        req_kwargs = _build_requests_kwargs(options, url)

        start_time = time.perf_counter()
        method = options.method.upper()
        request_func = {
            "GET": session.get,
            "HEAD": session.head,
            "OPTIONS": session.options,
        }.get(method, session.get)

        last_exc = None
        response = None
        attempts = max(1, options.retries + 1)
        for attempt in range(attempts):
            try:
                check_cancel()
                response = request_func(url, **req_kwargs)
                break
            except ScanCancelled:
                raise
            except requests.exceptions.SSLError as exc:
                last_exc = exc
                logger.warning(f"SSL error on attempt {attempt+1}: {exc}")
            except requests.exceptions.ConnectionError as exc:
                last_exc = exc
                logger.warning(f"Connection error on attempt {attempt+1}: {exc}")
            except requests.exceptions.Timeout as exc:
                last_exc = exc
                logger.warning(f"Timeout on attempt {attempt+1}: {exc}")
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                logger.warning(f"Request error on attempt {attempt+1}: {exc}")

        if response is None:
            raise last_exc or RuntimeError("Request failed with no response and no exception captured.")

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        result.network.response_time_ms = round(elapsed_ms, 2)

        # ---------------------------------------------- RECEIVE HEADERS ----
        _emit(progress_cb, ScanStage.RECEIVING_HEADERS, "Receiving response headers...")
        check_cancel()

        history = list(response.history)
        result.network.final_url = response.url
        result.network.protocol = urlparse(response.url).scheme
        result.network.http_version = {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(
            getattr(response.raw, "version", 11), "HTTP/1.1"
        )
        result.network.redirect_count = len(history)

        merged_headers: dict[str, str] = {}
        all_set_cookie_raw: list[str] = []
        for r in history + [response]:
            for k, v in r.headers.items():
                if v and v.strip():
                    merged_headers[k.lower()] = v.strip()
            # requests merges multiple Set-Cookie into one header via .headers,
            # but raw provides access to each individually when available.
            raw_cookies = r.raw.headers.get_all("Set-Cookie") if r.raw and hasattr(r.raw, "headers") else None
            if raw_cookies:
                all_set_cookie_raw.extend(raw_cookies)
            elif "Set-Cookie" in r.headers:
                all_set_cookie_raw.append(r.headers["Set-Cookie"])

        result.raw_headers = merged_headers
        result.network.total_headers = len(merged_headers)

        # -------------------------------------------------------- PARSE ----
        _emit(progress_cb, ScanStage.PARSING, "Parsing headers, cookies & redirects...")
        check_cancel()

        result.redirects = analyze_redirects(history, response)
        result.cookies = parse_all_cookies(all_set_cookie_raw)

        body_snippet = ""
        try:
            if method == "GET":
                body_snippet = response.text[:20000]
        except Exception:
            body_snippet = ""

        result.fingerprint = fingerprint_server(merged_headers, all_set_cookie_raw, body_snippet)

        # ----------------------------------------------------- ANALYZE -----
        _emit(progress_cb, ScanStage.ANALYZING, "Analyzing security posture...")
        check_cancel()

        header_results, header_findings = evaluate_headers(merged_headers)
        result.headers = header_results

        csp_raw = merged_headers.get("content-security-policy", "")
        result.csp = parse_csp(csp_raw)

        all_findings: list[Finding] = []
        all_findings.extend(header_findings)
        all_findings.extend(csp_findings(result.csp))
        all_findings.extend(cookie_findings(result.cookies))
        all_findings.extend(redirect_findings(result.redirects))
        all_findings.extend(tls_findings(result.tls))

        if result.network.protocol == "http":
            all_findings.append(Finding(
                title="Site served over plaintext HTTP",
                severity=Severity.CRITICAL,
                description="The final URL uses HTTP instead of HTTPS.",
                business_impact="All traffic (including credentials) can be intercepted or "
                                 "modified by network attackers.",
                remediation="Enforce HTTPS everywhere and redirect all HTTP traffic to HTTPS with HSTS.",
                references=["https://owasp.org/www-project-top-ten/"],
                category="Transport Security",
            ))

        all_findings.sort(key=lambda f: -f.severity.weight)
        result.findings = all_findings

        # -------------------------------------------------------- SCORE ----
        result.score = compute_score(result)

        _emit(progress_cb, ScanStage.GENERATING_REPORT, "Finalizing results...")
        check_cancel()

        _emit(progress_cb, ScanStage.COMPLETED, "Scan completed successfully.")
        return result

    except ScanCancelled:
        _emit(progress_cb, ScanStage.CANCELLED, "Scan cancelled by user.")
        result.error = "Cancelled by user."
        return result
    except requests.exceptions.SSLError as exc:
        msg = f"SSL/TLS error: {exc}"
        logger.error(msg)
        result.error = msg
        _emit(progress_cb, ScanStage.FAILED, msg)
        return result
    except requests.exceptions.ConnectionError as exc:
        msg = f"Connection failed (DNS/firewall/refused): {exc}"
        logger.error(msg)
        result.error = msg
        _emit(progress_cb, ScanStage.FAILED, msg)
        return result
    except requests.exceptions.Timeout as exc:
        msg = f"Request timed out: {exc}"
        logger.error(msg)
        result.error = msg
        _emit(progress_cb, ScanStage.FAILED, msg)
        return result
    except requests.exceptions.TooManyRedirects as exc:
        msg = f"Too many redirects (possible loop): {exc}"
        logger.error(msg)
        result.error = msg
        _emit(progress_cb, ScanStage.FAILED, msg)
        return result
    except Exception as exc:  # pragma: no cover - defensive catch-all
        logger.exception("Unexpected scan failure")
        msg = f"Unexpected error: {exc}"
        result.error = msg
        _emit(progress_cb, ScanStage.FAILED, msg)
        return result
