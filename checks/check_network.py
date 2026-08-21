"""Tests for URL normalization, validation and user-agent selection."""
from header_checker.utils.network import (
    get_hostname,
    is_valid_url,
    normalize_url,
    pick_user_agent,
)


class TestNormalizeUrl:
    def test_adds_https_scheme(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_preserves_existing_scheme(self):
        assert normalize_url("http://example.com") == "http://example.com"
        assert normalize_url("https://example.com/path") == "https://example.com/path"

    def test_strips_whitespace(self):
        assert normalize_url("  example.com  ") == "https://example.com"

    def test_empty_string(self):
        assert normalize_url("") == ""


class TestIsValidUrl:
    def test_valid(self):
        assert is_valid_url("https://example.com")
        assert is_valid_url("http://localhost:8080/x")

    def test_invalid(self):
        assert not is_valid_url("ftp://example.com")
        assert not is_valid_url("example.com")  # no scheme
        assert not is_valid_url("")


class TestPickUserAgent:
    def test_default_mode(self):
        ua = pick_user_agent("default")
        assert "HTTP Header Checker" in ua

    def test_random_mode_returns_known_ua(self):
        from header_checker.utils.constants import USER_AGENTS
        assert pick_user_agent("random") in USER_AGENTS

    def test_custom_mode(self):
        assert pick_user_agent("custom", "MyAgent/1.0") == "MyAgent/1.0"

    def test_custom_mode_falls_back_when_blank(self):
        assert "HTTP Header Checker" in pick_user_agent("custom", "   ")


def test_get_hostname():
    assert get_hostname("https://example.com:8443/path") == "example.com"
