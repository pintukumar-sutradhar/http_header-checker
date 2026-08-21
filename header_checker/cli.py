#!/usr/bin/env python3
"""
header_checker.cli
==================
Headless command-line interface for HTTP Header Checker.

Runs the same scanning engine as the GUI and prints a terminal summary,
with optional JSON / HTML report export and a CI-friendly ``--fail-on``
severity gate.

Commands:
    scan   Scan a URL and print a terminal summary (JSON/HTML export optional).
    ui     Launch the local web dashboard in your browser.

Exit codes (scan):
    0  scan completed (and no findings at/above --fail-on threshold)
    1  scan failed (connection error, invalid URL, ...)
    2  scan completed but findings met/exceeded the --fail-on severity
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .core.scan_engine import run_scan
from .reporting import render_text_summary, save_html, save_json
from .utils.logger import get_logger
from .utils.models import ScanOptions, ScanResult, Severity
from .utils.network import is_valid_url, normalize_url

logger = get_logger()

_SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


# --------------------------------------------------------------------------- #
# ANSI helpers
# --------------------------------------------------------------------------- #
def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _use_color() else text


def _sev_color_code(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "1;31",
        Severity.HIGH: "31",
        Severity.MEDIUM: "33",
        Severity.LOW: "34",
        Severity.INFO: "90",
    }.get(severity, "0")


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="http-header-checker",
        description="HTTP security header, TLS, cookie, redirect and technology "
                    "analyzer - headless CLI mode.",
        epilog="examples:\n"
               "  http-header-checker scan https://example.com\n"
               "  http-header-checker scan example.com --json report.json --html report.html\n"
               "  http-header-checker scan https://example.com --fail-on high   # CI gate\n"
               "  http-header-checker ui\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a target URL and print a summary")
    scan.add_argument("url", help="target URL (scheme optional, https assumed)")
    scan.add_argument("--method", choices=["GET", "HEAD", "OPTIONS"], default="GET")
    scan.add_argument("--timeout", type=int, default=15, metavar="SEC")
    scan.add_argument("--retries", type=int, default=1, metavar="N")
    scan.add_argument("--proxy", default="", metavar="URL", help="HTTP(S) proxy")
    scan.add_argument("--socks-proxy", dest="socks_proxy", default="", metavar="URL")
    scan.add_argument("--verify-ssl", action="store_true",
                      help="enforce TLS certificate verification (default: off)")
    scan.add_argument("--no-follow-redirects", action="store_true")
    scan.add_argument("--header", action="append", default=[], metavar='"NAME: VALUE"',
                      help="custom request header (repeatable)")
    scan.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE",
                      help="request cookie (repeatable)")
    scan.add_argument("--bearer", default="", metavar="TOKEN", help="Authorization: Bearer token")
    scan.add_argument("--user-agent", dest="user_agent", default="", metavar="UA")
    scan.add_argument("--random-ua", dest="random_ua", action="store_true")
    scan.add_argument("--analyst", default="Unknown Analyst", metavar="NAME")
    scan.add_argument("--json", dest="json_path", default=None, metavar="PATH",
                      help="write full JSON report to PATH")
    scan.add_argument("--html", dest="html_path", default=None, metavar="PATH",
                      help="write standalone HTML report to PATH")
    scan.add_argument("--fail-on", dest="fail_on", default=None,
                      choices=["critical", "high", "medium", "low", "info"],
                      help="exit with code 2 if any finding is at/above this severity (CI gate)")
    scan.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")

    ui = sub.add_parser("ui", help="launch the local web dashboard")
    ui.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost)")
    ui.add_argument("--port", type=int, default=8765, help="port (default: 8765)")
    ui.add_argument("--open", dest="open_browser", action="store_true",
                    help="open the dashboard in the default browser")
    return parser


def _parse_key_value(pairs: list[str], option: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"error: {option} expects NAME=VALUE format, got: {pair}")
        key, _, value = pair.partition("=")
        result[key.strip()] = value.strip()
    return result


def _parse_headers(pairs: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for pair in pairs:
        if ":" not in pair:
            raise SystemExit(f'error: --header expects "Name: Value" format, got: {pair}')
        name, _, value = pair.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def build_options(args: argparse.Namespace) -> ScanOptions:
    """Map parsed CLI arguments onto a ScanOptions dataclass."""
    return ScanOptions(
        method=args.method,
        custom_headers=_parse_headers(args.header),
        bearer_token=args.bearer,
        cookies=_parse_key_value(args.cookie, "--cookie"),
        proxy_url=args.proxy,
        socks_proxy_url=args.socks_proxy,
        timeout=args.timeout,
        retries=args.retries,
        follow_redirects=not args.no_follow_redirects,
        verify_ssl=args.verify_ssl,
        user_agent_mode="random" if args.random_ua else ("custom" if args.user_agent else "default"),
        custom_user_agent=args.user_agent or "",
    )


def _progress(stage: str, message: str) -> None:
    print(f"  [{stage}] {message}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_scan(args: argparse.Namespace) -> int:
    url = normalize_url(args.url)
    if not is_valid_url(url):
        print(_c(f"error: invalid target URL: {args.url}", "31"), file=sys.stderr)
        return 1

    options = build_options(args)
    if not args.quiet:
        print(_c(f"HTTP Header Checker v{__version__} - scanning {url}", "1;36"))
    result: ScanResult = run_scan(url, options=options, analyst=args.analyst)

    if args.json_path:
        path = save_json(result, args.json_path)
        print(f"JSON report written to: {path}")
    if args.html_path:
        path = save_html(result, args.html_path)
        print(f"HTML report written to: {path}")

    if result.error:
        summary = render_text_summary(result)
        print(_c(summary, "31"), file=sys.stderr)
        return 1

    print()
    print(render_text_summary(result))

    if args.fail_on:
        threshold = _SEVERITY_ALIASES[args.fail_on]
        worst = max((f.severity for f in result.findings), key=lambda s: s.weight, default=None)
        if worst is not None and worst.weight >= threshold.weight:
            print(_c(f"\nGate: findings at/above '{args.fail_on}' detected "
                     f"(worst: {worst.value}) - failing.", "1;31"), file=sys.stderr)
            return 2
        print(_c(f"\nGate: no findings at/above '{args.fail_on}'.", "32"))
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    import threading
    import webbrowser

    import uvicorn

    from .web.app import app as web_app

    url = f"http://{args.host}:{args.port}"
    print(_c(f"HTTP Header Checker dashboard running at {url}", "1;36"))
    print("Press Ctrl+C to stop.")
    if args.open_browser:
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()
    try:
        uvicorn.run(web_app, host=args.host, port=args.port, log_level="warning")
    except KeyboardInterrupt:
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "ui":
        return cmd_ui(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
