"""Tests for redirect chain analysis (using duck-typed fake responses)."""
from types import SimpleNamespace

from header_checker.core.redirect_scanner import analyze_redirects, redirect_findings


def _resp(url, status=200, location=None):
    return SimpleNamespace(url=url, status_code=status,
                           headers={"Location": location} if location else {})


class TestAnalyzeRedirects:
    def test_no_redirects(self):
        analysis = analyze_redirects([], _resp("https://example.com/"))
        assert analysis.total_redirects == 0
        assert len(analysis.hops) == 1
        assert not analysis.issues

    def test_simple_chain(self):
        history = [_resp("http://example.com", 301, "https://example.com")]
        analysis = analyze_redirects(history, _resp("https://example.com"))
        assert analysis.total_redirects == 1
        assert len(analysis.hops) == 2

    def test_https_downgrade_detected(self):
        history = [
            _resp("https://example.com", 302, "http://example.com"),
            _resp("http://example.com", 302, "https://example.com/final"),
        ]
        analysis = analyze_redirects(history, _resp("https://example.com/final"))
        assert analysis.https_downgrade
        assert any("downgrade" in i for i in analysis.issues)

    def test_loop_detection(self):
        history = [
            _resp("https://a.com", 302, "https://b.com"),
            _resp("https://b.com", 302, "https://a.com"),
        ]
        analysis = analyze_redirects(history, _resp("https://a.com"))
        assert analysis.redirect_loop_detected

    def test_excessive_chain_length(self):
        url = "https://example.com"
        history = [_resp(f"{url}/hop{i}", 302, f"{url}/hop{i+1}") for i in range(7)]
        analysis = analyze_redirects(history, _resp(f"{url}/end"))
        assert analysis.total_redirects > 5
        assert any("Excessive" in i for i in analysis.issues)


class TestRedirectFindings:
    def test_downgrade_produces_high_finding(self):
        from header_checker.utils.models import Severity
        analysis = analyze_redirects(
            [_resp("https://x.com", 302, "http://x.com")], _resp("http://x.com")
        )
        findings = redirect_findings(analysis)
        assert any(f.severity == Severity.HIGH for f in findings)
