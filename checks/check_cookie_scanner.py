"""Tests for Set-Cookie parsing and cookie security analysis."""
from header_checker.core.cookie_scanner import cookie_findings, parse_all_cookies
from header_checker.utils.models import Severity


class TestParseCookies:
    def test_flags_parsed(self):
        raw = "SID=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
        (cookie,) = parse_all_cookies([raw])
        assert cookie.name == "SID"
        assert cookie.secure and cookie.http_only
        assert cookie.same_site == "Lax"
        assert cookie.issues == []

    def test_missing_secure_and_httponly(self):
        (cookie,) = parse_all_cookies(["pref=1"])
        issues = "\n".join(cookie.issues)
        assert "Secure" in issues
        assert "HttpOnly" in issues

    def test_missing_samesite(self):
        (cookie,) = parse_all_cookies(["a=b; Secure; HttpOnly"])
        assert any("SameSite" in i for i in cookie.issues)

    def test_samesite_none_without_secure(self):
        (cookie,) = parse_all_cookies(["a=b; SameSite=None"])
        assert any("SameSite=None" in i for i in cookie.issues)

    def test_session_cookie_detection(self):
        session = parse_all_cookies(["sess=x"])[0]
        persistent = parse_all_cookies(["sess=x; Max-Age=3600"])[0]
        assert session.session_cookie
        assert not persistent.session_cookie
        assert persistent.persistent

    def test_value_preview_truncated(self):
        (cookie,) = parse_all_cookies(["k=" + "x" * 40])
        assert len(cookie.value_preview) <= 28  # 24 chars + "..."

    def test_multiple_cookies(self):
        cookies = parse_all_cookies(["a=1", "b=2; Secure"])
        assert [c.name for c in cookies] == ["a", "b"]

    def test_empty_input_ignored(self):
        assert parse_all_cookies(["", None]) == []


class TestCookieFindings:
    def test_issues_become_findings(self):
        cookies = parse_all_cookies(["auth_token=xyz"])  # no flags at all
        findings = cookie_findings(cookies)
        assert findings
        assert all(f.category == "Cookie Security" for f in findings)

    def test_session_cookie_without_httponly_is_high(self):
        cookies = parse_all_cookies(["sessionid=xyz; Secure"])
        findings = cookie_findings(cookies)
        assert any(f.severity == Severity.HIGH for f in findings)
