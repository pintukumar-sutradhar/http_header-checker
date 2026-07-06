"""
scanner/csp_analyzer.py
========================
Parses and analyzes a Content-Security-Policy header value, flagging
dangerous directives (unsafe-inline, unsafe-eval, wildcard sources, missing
object-src/base-uri/frame-ancestors, etc.).
"""
from __future__ import annotations

from utils.models import CSPAnalysis, CSPDirective, Finding, Severity

DANGEROUS_SOURCE_KEYWORDS = {
    "'unsafe-inline'": "Allows inline scripts/styles, largely defeating XSS protection.",
    "'unsafe-eval'": "Allows eval()-like constructs, a common vector for DOM-based XSS.",
    "*": "Wildcard source allows content from ANY origin.",
    "data:": "Allows data: URIs which can be used to smuggle executable content.",
    "http:": "Allows insecure HTTP sources inside an otherwise HTTPS context.",
}

FETCH_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src", "object-src",
    "connect-src", "frame-src", "worker-src", "child-src", "font-src",
    "manifest-src", "media-src", "prefetch-src", "form-action",
]

DOCUMENT_DIRECTIVES = ["base-uri", "frame-ancestors", "sandbox"]
OTHER_DIRECTIVES = ["upgrade-insecure-requests", "block-all-mixed-content", "report-uri", "report-to"]

ALL_KNOWN_DIRECTIVES = FETCH_DIRECTIVES + DOCUMENT_DIRECTIVES + OTHER_DIRECTIVES


def parse_csp(raw_csp: str) -> CSPAnalysis:
    analysis = CSPAnalysis(raw=raw_csp, present=bool(raw_csp))
    if not raw_csp:
        analysis.dangerous_findings.append("No Content-Security-Policy header present at all.")
        analysis.score_penalty = 15
        return analysis

    directive_strings = [d.strip() for d in raw_csp.split(";") if d.strip()]
    directive_map: dict[str, list[str]] = {}

    for d in directive_strings:
        parts = d.split()
        if not parts:
            continue
        name = parts[0].lower()
        values = parts[1:]
        directive_map[name] = values

    penalty = 0

    for name, values in directive_map.items():
        directive = CSPDirective(name=name, values=values)
        joined = " ".join(values).lower()

        for keyword, explanation in DANGEROUS_SOURCE_KEYWORDS.items():
            if keyword in joined and name in FETCH_DIRECTIVES + ["default-src"]:
                msg = f"'{name}' includes {keyword} — {explanation}"
                directive.issues.append(msg)
                analysis.dangerous_findings.append(msg)
                penalty += 8 if "unsafe" in keyword else 4

        directive_map_entry = directive
        analysis.directives.append(directive_map_entry)

    # Structural checks
    if "default-src" not in directive_map and not any(fd in directive_map for fd in FETCH_DIRECTIVES):
        msg = "No 'default-src' or explicit fetch directives defined — policy may be ineffective."
        analysis.dangerous_findings.append(msg)
        penalty += 10

    if "object-src" not in directive_map:
        msg = "'object-src' not restricted — consider 'object-src none' to block legacy plugin content."
        analysis.dangerous_findings.append(msg)
        penalty += 4

    if "base-uri" not in directive_map:
        msg = "'base-uri' not restricted — attackers may inject a <base> tag to hijack relative URLs."
        analysis.dangerous_findings.append(msg)
        penalty += 4

    if "frame-ancestors" not in directive_map:
        msg = "'frame-ancestors' not set — clickjacking protection relies solely on X-Frame-Options."
        analysis.dangerous_findings.append(msg)
        penalty += 3

    if "upgrade-insecure-requests" not in directive_map:
        analysis.dangerous_findings.append(
            "'upgrade-insecure-requests' not set — mixed content may not be auto-upgraded to HTTPS."
        )
        penalty += 2

    analysis.score_penalty = min(penalty, 30)
    return analysis


def csp_findings(analysis: CSPAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    if not analysis.present:
        findings.append(Finding(
            title="Content-Security-Policy is missing",
            severity=Severity.HIGH,
            description="No CSP header was returned by the server.",
            business_impact="Without CSP, the application has no defense-in-depth against XSS "
                             "and data-injection attacks beyond output encoding.",
            remediation="Implement a strict CSP starting with 'default-src self' and refine per resource type.",
            references=["https://owasp.org/www-project-secure-headers/#content-security-policy"],
            category="Content Security",
        ))
        return findings

    for msg in analysis.dangerous_findings:
        severity = Severity.HIGH if "unsafe" in msg or "ANY origin" in msg else Severity.MEDIUM
        findings.append(Finding(
            title="CSP directive issue",
            severity=severity,
            description=msg,
            business_impact="Weakens CSP's ability to mitigate injection-based attacks.",
            remediation="Tighten the affected directive to a minimal, explicit allow-list.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            category="Content Security",
        ))
    return findings
