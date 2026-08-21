"""Tests for Content-Security-Policy parsing and analysis."""
from header_checker.core.csp_analyzer import csp_findings, parse_csp
from header_checker.utils.models import Severity


class TestParseCsp:
    def test_missing_policy(self):
        analysis = parse_csp("")
        assert not analysis.present
        assert any("No Content-Security-Policy" in f for f in analysis.dangerous_findings)

    def test_strict_policy_clean(self):
        csp = ("default-src 'self'; object-src 'none'; base-uri 'self'; "
               "frame-ancestors 'self'; upgrade-insecure-requests")
        analysis = parse_csp(csp)
        assert analysis.present
        assert analysis.dangerous_findings == []

    def test_unsafe_inline_detected(self):
        analysis = parse_csp("script-src 'unsafe-inline'")
        assert any("'unsafe-inline'" in f for f in analysis.dangerous_findings)

    def test_wildcard_detected(self):
        analysis = parse_csp("img-src *")
        assert any("*" in f for f in analysis.dangerous_findings)

    def test_directives_parsed(self):
        analysis = parse_csp("default-src 'self'; script-src cdn.example.com")
        names = {d.name for d in analysis.directives}
        assert names == {"default-src", "script-src"}

    def test_structural_checks_fire(self):
        analysis = parse_csp("style-src 'self'")  # no default-src/object-src/base-uri
        joined = "\n".join(analysis.dangerous_findings)
        assert "object-src" in joined
        assert "base-uri" in joined

    def test_multiple_dangerous_values_all_detected(self):
        analysis = parse_csp("script-src 'unsafe-inline' 'unsafe-eval' * data:")
        assert len(analysis.dangerous_findings) >= 4


class TestCspFindings:
    def test_missing_policy_produces_high_finding(self):
        findings = csp_findings(parse_csp(""))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_unsafe_inline_is_high_severity(self):
        findings = csp_findings(parse_csp("script-src 'unsafe-inline'"))
        assert any(f.severity == Severity.HIGH for f in findings)
