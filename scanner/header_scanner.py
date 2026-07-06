"""
scanner/header_scanner.py
==========================
Evaluates the raw HTTP response headers against the header knowledge base
and produces a list of ``HeaderResult`` objects plus derived ``Finding``
objects for the report.
"""
from __future__ import annotations

from utils.models import HeaderResult, HeaderStatus, Severity, Finding
from .header_definitions import (
    get_definition,
    all_security_headers,
    all_informational_headers,
    HEADER_DB,
)


def _evaluate_value(header_name: str, value: str) -> tuple[HeaderStatus, Severity, list[str]]:
    """Inspect the actual header value for weak/misconfigured patterns."""
    definition = get_definition(header_name)
    notes: list[str] = []
    lower_val = value.lower()

    if definition and definition.deprecated:
        return HeaderStatus.DEPRECATED, Severity.INFO, ["Header is deprecated by modern browsers."]

    if definition and definition.weak_values:
        for weak in definition.weak_values:
            if weak.lower() in lower_val:
                notes.append(f"Value contains weak/insecure token: '{weak}'")
                return HeaderStatus.WEAK, Severity.MEDIUM, notes

    # Header-specific deep checks
    name_lower = header_name.lower()

    if name_lower == "strict-transport-security":
        if "max-age=0" in lower_val:
            return HeaderStatus.MISCONFIGURED, Severity.HIGH, ["max-age=0 disables HSTS entirely."]
        try:
            max_age = int(lower_val.split("max-age=")[1].split(";")[0].strip())
            if max_age < 15552000:  # 180 days
                notes.append(f"max-age={max_age} is below recommended 15552000 (180 days).")
                return HeaderStatus.WEAK, Severity.LOW, notes
        except Exception:
            notes.append("Could not parse max-age directive.")
        if "includesubdomains" not in lower_val:
            notes.append("Missing 'includeSubDomains' directive.")
        if "preload" not in lower_val:
            notes.append("Missing 'preload' directive (optional but recommended).")
        if notes:
            return HeaderStatus.PRESENT, Severity.LOW, notes
        return HeaderStatus.PRESENT, Severity.INFO, notes

    if name_lower == "x-frame-options":
        if lower_val not in ("deny", "sameorigin") and "allow-from" not in lower_val:
            return HeaderStatus.MISCONFIGURED, Severity.MEDIUM, [f"Unrecognized value: {value}"]
        if "allow-from" in lower_val:
            notes.append("ALLOW-FROM is deprecated/unsupported in modern browsers.")
            return HeaderStatus.WEAK, Severity.LOW, notes

    if name_lower == "x-content-type-options":
        if lower_val != "nosniff":
            return HeaderStatus.MISCONFIGURED, Severity.MEDIUM, [f"Expected 'nosniff', got '{value}'"]

    if name_lower == "referrer-policy":
        weak_policies = {"unsafe-url", "no-referrer-when-downgrade"}
        if lower_val in weak_policies:
            notes.append(f"'{value}' leaks more referrer data than recommended.")
            return HeaderStatus.WEAK, Severity.LOW, notes

    if name_lower == "access-control-allow-origin":
        if value.strip() == "*":
            notes.append("Wildcard CORS origin allows any website to read this response.")
            return HeaderStatus.WEAK, Severity.MEDIUM, notes

    if name_lower == "x-xss-protection":
        if lower_val.startswith("1"):
            notes.append("Legacy filter enabled; some historical browser bugs made '1' exploitable "
                          "as an XSS vector via filter evasion. '0' + CSP is now preferred.")
            return HeaderStatus.WEAK, Severity.INFO, notes

    if name_lower == "server" or name_lower == "x-powered-by":
        if any(ch.isdigit() for ch in value):
            notes.append("Banner discloses a specific version number, aiding vulnerability targeting.")
            return HeaderStatus.WEAK, Severity.LOW, notes

    return HeaderStatus.PRESENT, Severity.INFO, notes


def evaluate_headers(headers: dict[str, str]) -> tuple[list[HeaderResult], list[Finding]]:
    """
    Evaluate all known headers (security + informational) against what was
    actually returned by the server.

    :param headers: lower-cased header name -> value mapping
    :return: (list of HeaderResult, list of Finding)
    """
    results: list[HeaderResult] = []
    findings: list[Finding] = []

    checklist = all_security_headers() + all_informational_headers()

    for header_name in checklist:
        definition = get_definition(header_name)
        key = header_name.lower()

        if key in headers:
            value = headers[key]
            status, severity, notes = _evaluate_value(header_name, value)
            result = HeaderResult(
                name=header_name,
                status=status,
                severity=severity,
                current_value=value,
                recommended_value=definition.recommended_value if definition else "",
                description=(definition.description if definition else "") + (
                    ("  Notes: " + "; ".join(notes)) if notes else ""
                ),
                why_it_matters=definition.why_it_matters if definition else "",
                owasp_reference=definition.owasp_reference if definition else "",
                mozilla_recommendation=definition.mozilla_recommendation if definition else "",
                microsoft_recommendation=definition.microsoft_recommendation if definition else "",
                example_secure_config=definition.example_secure_config if definition else "",
            )
            results.append(result)

            if status in (HeaderStatus.WEAK, HeaderStatus.MISCONFIGURED) and definition and definition.security_relevant:
                findings.append(Finding(
                    title=f"{header_name} is {status.value.lower()}",
                    severity=severity,
                    description="; ".join(notes) or f"{header_name} value may not follow best practice.",
                    business_impact=definition.why_it_matters,
                    remediation=f"Set to a secure value, e.g.: {definition.example_secure_config or definition.recommended_value}",
                    references=[r for r in [definition.owasp_reference, definition.mozilla_recommendation] if r],
                    category=definition.category,
                ))
        else:
            if definition and definition.security_relevant and header_name in all_security_headers():
                result = HeaderResult(
                    name=header_name,
                    status=HeaderStatus.MISSING,
                    severity=definition.missing_severity,
                    current_value=None,
                    recommended_value=definition.recommended_value,
                    description=definition.description,
                    why_it_matters=definition.why_it_matters,
                    owasp_reference=definition.owasp_reference,
                    mozilla_recommendation=definition.mozilla_recommendation,
                    microsoft_recommendation=definition.microsoft_recommendation,
                    example_secure_config=definition.example_secure_config,
                )
                results.append(result)
                findings.append(Finding(
                    title=f"Missing {header_name} header",
                    severity=definition.missing_severity,
                    description=definition.description,
                    business_impact=definition.why_it_matters,
                    remediation=f"Add header: {definition.example_secure_config or definition.recommended_value}",
                    references=[r for r in [definition.owasp_reference, definition.mozilla_recommendation] if r],
                    category=definition.category,
                ))
            elif definition:
                # informational header absent -- still show as missing, informational severity
                results.append(HeaderResult(
                    name=header_name,
                    status=HeaderStatus.MISSING,
                    severity=Severity.INFO,
                    current_value=None,
                    recommended_value=definition.recommended_value,
                    description=definition.description,
                    why_it_matters=definition.why_it_matters,
                    owasp_reference=definition.owasp_reference,
                    mozilla_recommendation=definition.mozilla_recommendation,
                    microsoft_recommendation=definition.microsoft_recommendation,
                    example_secure_config=definition.example_secure_config,
                ))

    return results, findings
