"""
scanner/redirect_scanner.py
=============================
Builds a structured redirect chain analysis from the ``requests`` response
history, detecting HTTPS downgrades, mixed protocol hops, and loops.
"""
from __future__ import annotations

from urllib.parse import urlparse

import requests

from utils.models import RedirectAnalysis, RedirectHop, Finding, Severity

PERMANENT_CODES = {301, 308}


def analyze_redirects(history: list[requests.Response], final_response: requests.Response) -> RedirectAnalysis:
    analysis = RedirectAnalysis()
    all_responses = list(history) + [final_response]
    seen_urls: set[str] = set()

    schemes: list[str] = []
    for idx, resp in enumerate(all_responses):
        scheme = urlparse(resp.url).scheme
        schemes.append(scheme)
        location = resp.headers.get("Location")
        hop = RedirectHop(
            order=idx,
            url=resp.url,
            status_code=resp.status_code,
            location=location,
            headers=dict(resp.headers),
            is_https=(scheme == "https"),
            permanent=resp.status_code in PERMANENT_CODES,
        )
        analysis.hops.append(hop)

        if resp.url in seen_urls:
            analysis.redirect_loop_detected = True
        seen_urls.add(resp.url)

    analysis.total_redirects = len(history)

    # HTTPS downgrade: any hop after an https hop that is http
    saw_https = False
    for scheme in schemes:
        if scheme == "https":
            saw_https = True
        elif scheme == "http" and saw_https:
            analysis.https_downgrade = True

    if len(set(schemes)) > 1:
        analysis.mixed_redirects = True

    if analysis.https_downgrade:
        analysis.issues.append("Redirect chain downgrades from HTTPS back to HTTP at some point.")
    if analysis.redirect_loop_detected:
        analysis.issues.append("A redirect loop was detected (a URL was visited more than once).")
    if analysis.total_redirects > 5:
        analysis.issues.append(f"Excessive redirect chain length ({analysis.total_redirects} hops).")

    return analysis


def redirect_findings(analysis: RedirectAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    if analysis.https_downgrade:
        findings.append(Finding(
            title="HTTPS to HTTP downgrade in redirect chain",
            severity=Severity.HIGH,
            description="The site redirects from a secure HTTPS connection back to plaintext HTTP.",
            business_impact="Exposes users to man-in-the-middle interception and credential theft "
                             "during the downgraded portion of the session.",
            remediation="Ensure all redirects remain on HTTPS; enable HSTS to prevent protocol downgrade.",
            references=["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
            category="Transport Security",
        ))
    if analysis.redirect_loop_detected:
        findings.append(Finding(
            title="Redirect loop detected",
            severity=Severity.MEDIUM,
            description="The scanner detected the same URL being redirected to more than once.",
            business_impact="Can cause denial-of-service style failures for users and crawlers.",
            remediation="Review redirect/routing logic to eliminate circular redirects.",
            category="Availability",
        ))
    if analysis.total_redirects > 5:
        findings.append(Finding(
            title="Excessive redirect chain length",
            severity=Severity.LOW,
            description=f"{analysis.total_redirects} redirects were followed before reaching the final URL.",
            business_impact="Slows down page load and increases attack surface for redirect manipulation.",
            remediation="Simplify redirect chains to at most 1-2 hops.",
            category="Performance",
        ))
    return findings
