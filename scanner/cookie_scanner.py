"""
scanner/cookie_scanner.py
==========================
Analyzes Set-Cookie headers returned throughout the redirect chain for
common cookie security misconfigurations.
"""
from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Iterable

from utils.models import CookieResult, Finding, Severity


def _parse_single_set_cookie(raw: str) -> CookieResult:
    """Parse one Set-Cookie header string into a CookieResult."""
    # SimpleCookie chokes on some real-world attributes (SameSite=None, Partitioned),
    # so we do a manual, forgiving parse.
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return CookieResult(name="(unknown)", value_preview="")

    name_value = parts[0]
    if "=" in name_value:
        name, value = name_value.split("=", 1)
    else:
        name, value = name_value, ""

    attrs = {p.split("=")[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
             for p in parts[1:]}

    cookie = CookieResult(
        name=name.strip(),
        value_preview=(value[:24] + "...") if len(value) > 24 else value,
        secure="secure" in attrs,
        http_only="httponly" in attrs,
        same_site=attrs.get("samesite"),
        path=attrs.get("path"),
        domain=attrs.get("domain"),
        expires=attrs.get("expires") or (f"Max-Age={attrs.get('max-age')}" if "max-age" in attrs else None),
        priority=attrs.get("priority"),
        partitioned="partitioned" in attrs,
    )
    cookie.persistent = bool(cookie.expires)
    cookie.session_cookie = not cookie.persistent

    # -- Security checks --
    if not cookie.secure:
        cookie.issues.append("Missing 'Secure' flag — cookie may be sent over unencrypted HTTP.")
    if not cookie.http_only:
        cookie.issues.append("Missing 'HttpOnly' flag — cookie is readable via JavaScript (XSS theft risk).")
    if cookie.same_site is None:
        cookie.issues.append("Missing 'SameSite' attribute — browser defaults vary, CSRF exposure possible.")
    elif cookie.same_site.lower() == "none" and not cookie.secure:
        cookie.issues.append("'SameSite=None' without 'Secure' — invalid/rejected by modern browsers "
                              "and highly cross-site exploitable if accepted.")
    if any(k in name.lower() for k in ("sess", "sid", "auth", "token")) and not cookie.http_only:
        cookie.issues.append("Looks like a session/auth cookie but lacks HttpOnly — high session-hijack risk.")

    return cookie


def parse_all_cookies(set_cookie_headers: Iterable[str]) -> list[CookieResult]:
    return [_parse_single_set_cookie(raw) for raw in set_cookie_headers if raw]


def cookie_findings(cookies: list[CookieResult]) -> list[Finding]:
    findings: list[Finding] = []
    for c in cookies:
        for issue in c.issues:
            severity = Severity.HIGH if "hijack" in issue or "SameSite=None" in issue else Severity.MEDIUM
            findings.append(Finding(
                title=f"Cookie '{c.name}': {issue.split('—')[0].strip()}",
                severity=severity,
                description=issue,
                business_impact="Insecure cookie attributes can enable session hijacking, XSS-based "
                                 "token theft, or cross-site request forgery.",
                remediation="Set Secure, HttpOnly and an appropriate SameSite attribute on all "
                             "session/auth cookies.",
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                category="Cookie Security",
            ))
    return findings
