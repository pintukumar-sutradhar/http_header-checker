"""Tests for HTTP header evaluation against the knowledge base."""
from header_checker.core.header_scanner import evaluate_headers
from header_checker.utils.models import HeaderStatus


class TestEvaluateHeaders:
    def test_missing_security_headers_flagged(self):
        results, findings = evaluate_headers({})
        assert results, "expected at least the security-header checklist"
        failed = [r for r in results if r.status == HeaderStatus.FAIL]
        assert failed
        assert findings

    def test_strong_headers_pass(self):
        headers = {
            "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
        }
        results, _ = evaluate_headers(headers)
        hsts = next(r for r in results if r.name == "Strict-Transport-Security")
        xcto = next(r for r in results if r.name == "X-Content-Type-Options")
        xfo = next(r for r in results if r.name == "X-Frame-Options")
        assert hsts.status == HeaderStatus.PASS
        assert xcto.status == HeaderStatus.PASS
        assert xfo.status == HeaderStatus.PASS

    def test_hsts_low_max_age_warns(self):
        results, _ = evaluate_headers({"strict-transport-security": "max-age=3600"})
        hsts = next(r for r in results if r.name == "Strict-Transport-Security")
        assert hsts.status == HeaderStatus.WARN

    def test_hsts_max_age_zero_fails(self):
        results, findings = evaluate_headers({"strict-transport-security": "max-age=0"})
        hsts = next(r for r in results if r.name == "Strict-Transport-Security")
        assert hsts.status == HeaderStatus.FAIL
        assert any("Strict-Transport-Security" in f.title for f in findings)

    def test_bad_x_content_type_options_fails(self):
        results, _ = evaluate_headers({"x-content-type-options": "allow"})
        xcto = next(r for r in results if r.name == "X-Content-Type-Options")
        assert xcto.status == HeaderStatus.FAIL

    def test_versioned_server_banner_warns(self):
        results, _ = evaluate_headers({"server": "nginx/1.24.0"})
        server = next(r for r in results if r.name.lower() == "server")
        assert server.status == HeaderStatus.WARN

    def test_wildcard_cors_warns(self):
        results, _ = evaluate_headers({"access-control-allow-origin": "*"})
        aco = next(r for r in results if r.name == "Access-Control-Allow-Origin")
        assert aco.status == HeaderStatus.WARN

    def test_informational_missing_headers_are_not_failures(self):
        """Deprecated/noise headers (e.g. X-XSS-Protection) must not show as Fail."""
        results, _ = evaluate_headers({})
        by_name = {r.name: r for r in results}
        assert by_name["X-XSS-Protection"].status == HeaderStatus.INFO
        assert by_name["Origin-Agent-Cluster"].status == HeaderStatus.INFO

    def test_no_informational_findings_emitted(self):
        """The findings register must only contain actionable severities."""
        _, findings = evaluate_headers({})
        assert all(f.severity != __import__("header_checker.utils.models",
                                               fromlist=["Severity"]).Severity.INFO
                   for f in findings)

    def test_results_carry_guidance(self):
        results, _ = evaluate_headers({})
        with_guidance = [r for r in results if r.why_it_matters]
        assert with_guidance, "knowledge-base entries should explain why they matter"
