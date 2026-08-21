"""Tests for the CLI: option mapping and exit-code gates (no network)."""
import pytest

from header_checker.cli import build_options, build_parser, main
from header_checker.utils.models import Finding, ScanOptions, ScanResult, Severity


def _parse(argv):
    return build_parser().parse_args(argv)


class TestArgumentParsing:
    def test_scan_defaults(self):
        args = _parse(["scan", "example.com"])
        assert args.url == "example.com"
        assert args.method == "GET"
        assert args.timeout == 15
        assert args.verify_ssl is False
        assert args.fail_on is None

    def test_repeatable_headers_and_cookies(self):
        args = _parse(["scan", "x.com", "--header", "A: 1", "--header", "B: 2",
                       "--cookie", "k=v"])
        assert args.header == ["A: 1", "B: 2"]
        assert args.cookie == ["k=v"]


class TestBuildOptions:
    def test_maps_to_scan_options(self):
        args = _parse([
            "scan", "example.com", "--method", "HEAD", "--timeout", "5",
            "--retries", "3", "--proxy", "http://127.0.0.1:8080",
            "--verify-ssl", "--no-follow-redirects",
            "--header", "X-Test: yes", "--cookie", "a=b",
            "--bearer", "tok", "--user-agent", "UA/1",
        ])
        opts = build_options(args)
        assert isinstance(opts, ScanOptions)
        assert opts.method == "HEAD"
        assert opts.timeout == 5
        assert opts.retries == 3
        assert opts.proxy_url == "http://127.0.0.1:8080"
        assert opts.verify_ssl is True
        assert opts.follow_redirects is False
        assert opts.custom_headers == {"X-Test": "yes"}
        assert opts.cookies == {"a": "b"}
        assert opts.bearer_token == "tok"
        assert opts.user_agent_mode == "custom"

    def test_random_ua_mode(self):
        args = _parse(["scan", "x.com", "--random-ua"])
        assert build_options(args).user_agent_mode == "random"

    def test_bad_header_format_exits(self):
        with pytest.raises(SystemExit):
            build_options(_parse(["scan", "x.com", "--header", "no-colon"]))


class TestExitCodes:
    def _fake_run(self, monkeypatch, severities):
        def fake_run(url, options=None, progress_cb=None, cancel_check=None, analyst=""):
            result = ScanResult()
            result.network.target_url = url
            result.findings = [Finding(title=f"f{i}", severity=s)
                               for i, s in enumerate(severities)]
            return result
        monkeypatch.setattr("header_checker.cli.run_scan", fake_run)

    def test_success_without_gate(self, monkeypatch, capsys):
        self._fake_run(monkeypatch, [Severity.LOW])
        assert main(["scan", "https://ok.test"]) == 0

    def test_fail_on_high_triggers_exit_2(self, monkeypatch, capsys):
        self._fake_run(monkeypatch, [Severity.MEDIUM, Severity.HIGH])
        code = main(["scan", "https://bad.test", "--fail-on", "high", "-q"])
        assert code == 2

    def test_gate_passes_when_below_threshold(self, monkeypatch, capsys):
        self._fake_run(monkeypatch, [Severity.LOW])
        assert main(["scan", "https://ok.test", "--fail-on", "high"]) == 0

    def test_invalid_url_returns_1(self, monkeypatch):
        assert main(["scan", ""]) == 1
