"""
header_checker.core.header_scanner
===================================
Evaluates raw HTTP response headers against the knowledge base and produces
``HeaderResult`` objects (Pass / Warning / Fail / Info) plus actionable
``Finding`` objects.

Rules:
* Every known header gets a row in the report -- even purely informational
  ones -- so users see the full picture.
* Only WARN/FAIL verdicts on security-relevant headers become findings.
  Informational observations never pollute the findings register.
"""
from __future__ import annotations

from header_checker.utils.models import (
    Finding,
    HeaderResult,
    HeaderStatus,
    Severity,
)

from .header_definitions import (
    all_informational_headers,
    all_security_headers,
    get_definition,
)


def _evaluate_value(header_name: str, value: str) -> tuple[HeaderStatus, Severity | None, str]:
    """
    Inspect an actual header value.

    Returns (status, finding_severity_or_None, plain_language_summary).
    ``finding_severity`` is None when the observation is not actionable
    enough to appear in the findings register.
    """
    definition = get_definition(header_name)
    lower_val = value.lower()
    name_lower = header_name.lower()

    if definition and definition.deprecated:
        return HeaderStatus.INFO, None, "Deprecated by modern browsers; safe to remove."

    if definition and definition.weak_values:
        for weak in definition.weak_values:
            if weak.lower() in lower_val:
                return (HeaderStatus.WARN, Severity.MEDIUM,
                        f"Value contains the insecure token '{weak}'.")

    # ------------------------------------------------------------- HSTS ----
    if name_lower == "strict-transport-security":
        if "max-age=0" in lower_val:
            return (HeaderStatus.FAIL, Severity.HIGH,
                    "max-age=0 actively disables HSTS for returning visitors.")
        try:
            max_age = int(lower_val.split("max-age=")[1].split(";")[0].strip())
            if max_age < 15552000:  # 180 days, OWASP minimum
                return (HeaderStatus.WARN, Severity.LOW,
                        f"max-age={max_age} is below the recommended 15552000 (180 days).")
        except (ValueError, IndexError):
            return (HeaderStatus.WARN, Severity.LOW, "Could not parse the max-age directive.")
        missing = [d for d in ("includesubdomains", "preload") if d not in lower_val]
        if missing:
            return (HeaderStatus.PASS, Severity.LOW,
                    f"Present, but consider adding: {', '.join(missing)}.")
        return HeaderStatus.PASS, None, "Well configured."

    # ---------------------------------------------------- X-Frame-Options --
    if name_lower == "x-frame-options":
        if lower_val not in ("deny", "sameorigin") and "allow-from" not in lower_val:
            return (HeaderStatus.FAIL, Severity.MEDIUM,
                    f"'{value}' is not a recognized value; use DENY or SAMEORIGIN.")
        if "allow-from" in lower_val:
            return (HeaderStatus.WARN, Severity.LOW,
                    "ALLOW-FROM is unsupported in modern browsers; use CSP frame-ancestors.")
        return HeaderStatus.PASS, None, "Correctly configured."

    # ---------------------------------------------- X-Content-Type-Options -
    if name_lower == "x-content-type-options":
        if lower_val != "nosniff":
            return (HeaderStatus.FAIL, Severity.MEDIUM,
                    f"Expected 'nosniff' but got '{value}'.")
        return HeaderStatus.PASS, None, "Correctly configured."

    # ----------------------------------------------------- Referrer-Policy -
    if name_lower == "referrer-policy":
        if lower_val in ("unsafe-url", "no-referrer-when-downgrade"):
            return (HeaderStatus.WARN, Severity.LOW,
                    f"'{value}' leaks more referrer data than recommended.")
        return HeaderStatus.PASS, None, "Acceptable policy."

    # ---------------------------------------------------------------- CORS -
    if name_lower == "access-control-allow-origin":
        if value.strip() == "*":
            return (HeaderStatus.WARN, Severity.MEDIUM,
                    "Wildcard origin: any website can read this response.")
        return HeaderStatus.PASS, None, "Restricted origin policy."

    # --------------------------------------------------- X-XSS-Protection --
    if name_lower == "x-xss-protection":
        if lower_val.startswith("1"):
            return (HeaderStatus.INFO, None,
                    "Legacy filter enabled; modern advice is to remove this header and rely on CSP.")

    # ------------------------------------------- Server / X-Powered-By -----
    if name_lower in ("server", "x-powered-by") and any(ch.isdigit() for ch in value):
        return (HeaderStatus.WARN, Severity.LOW,
                "Discloses a specific version number, which helps attackers target known CVEs.")

    return HeaderStatus.PASS, None, "Present."


def evaluate_headers(headers: dict[str, str]) -> tuple[list[HeaderResult], list[Finding]]:
    """
    Evaluate all known headers against what the server actually returned.

    :param headers: lower-cased header name -> value mapping
    :return: (list of HeaderResult, list of Finding)
    """
    results: list[HeaderResult] = []
    findings: list[Finding] = []
    security_set = set(all_security_headers())

    for header_name in all_security_headers() + all_informational_headers():
        definition = get_definition(header_name)
        key = header_name.lower()
        if not definition:
            continue

        if key in headers:
            value = headers[key]
            status, sev, summary = _evaluate_value(header_name, value)
            results.append(HeaderResult(
                name=header_name,
                status=status,
                current_value=value,
                recommended_value=definition.recommended_value,
                summary=summary,
                description=definition.description,
                why_it_matters=definition.why_it_matters,
                example_secure_config=definition.example_secure_config,
            ))
            if sev is not None and definition.security_relevant:
                findings.append(Finding(
                    title=f"{header_name}: {summary}",
                    severity=sev,
                    description=f"Current value: {value}",
                    business_impact=definition.why_it_matters,
                    remediation=f"Set a secure value, e.g. {definition.example_secure_config or definition.recommended_value}",
                    category=definition.category,
                ))
        elif header_name in security_set:
            actionable = definition.missing_severity != Severity.INFO
            results.append(HeaderResult(
                name=header_name,
                status=HeaderStatus.FAIL if actionable else HeaderStatus.INFO,
                current_value=None,
                recommended_value=definition.recommended_value,
                summary="Not sent by the server.",
                description=definition.description,
                why_it_matters=definition.why_it_matters,
                example_secure_config=definition.example_secure_config,
            ))
            if actionable:
                findings.append(Finding(
                    title=f"Missing {header_name} header",
                    severity=definition.missing_severity,
                    description=definition.description,
                    business_impact=definition.why_it_matters,
                    remediation=f"Add header: {definition.example_secure_config or definition.recommended_value}",
                    category=definition.category,
                ))
        else:
            results.append(HeaderResult(
                name=header_name,
                status=HeaderStatus.INFO,
                current_value=None,
                summary="Not sent by the server.",
                description=definition.description,
                why_it_matters=definition.why_it_matters,
                recommended_value=definition.recommended_value,
                example_secure_config=definition.example_secure_config,
            ))

    return results, findings
