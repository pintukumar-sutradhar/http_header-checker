<div align="center">

# HTTP Header Checker

**Fast, local-first security analysis of HTTP headers, TLS, cookies and redirect chains.**

A clean CLI and a local web dashboard. No accounts, no telemetry, no data leaves your machine.

[Features](#features) · [Installation](#installation) · [Usage](#usage) · [Development](#development)

<img src="screenshots/screenshot_dashboard.png" alt="Header Checker dashboard" width="820">

</div>

---

## Features

| | |
|---|---|
| **Security headers** | 45+ headers evaluated against OWASP / Mozilla guidance — HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy and more |
| **CSP deep analysis** | Parses directives; flags `unsafe-inline`, wildcards, `data:` URIs and structural gaps |
| **Cookies** | Secure / HttpOnly / SameSite flags and session-cookie risk across the entire redirect chain |
| **TLS & certificates** | Protocol, cipher suite, expiry countdown, SANs, self-signed / hostname-mismatch / weak-crypto detection |
| **Redirects** | HTTPS downgrade, loops, excessive hops |
| **Fingerprinting** | Passive detection of server, CDN, framework and CMS |
| **Reports** | JSON and standalone HTML exports for documentation and pipelines |
| **CI gate mode** | Fails your pipeline when findings meet a severity threshold |

Findings are severity-ranked with impact and concrete remediation — no scores,
no jargon, no noise.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/pintukumar-sutradhar/http_header-checker.git
cd http_header-checker
pip install .
```

Or directly:

```bash
pip install git+https://github.com/pintukumar-sutradhar/http_header-checker.git
```

Pure Python — no compilers, no system libraries.

## Usage

### Web dashboard

```bash
http-header-checker ui --open
```

Opens `http://127.0.0.1:8765` in your browser. Enter a URL, click **Analyze**.
Tip: append `?url=example.com` to auto-start a scan — handy for bookmarks.

### CLI

```bash
http-header-checker scan https://example.com              # terminal summary
http-header-checker scan example.com --html report.html   # standalone HTML report
http-header-checker scan example.com --json report.json   # JSON export
http-header-checker scan example.com --fail-on high       # exit 2 if High+ findings (CI gate)
```

Common options: `--method HEAD` · `--timeout 10` · `--proxy http://127.0.0.1:8080`
· `--verify-ssl` · `--header "X-Request-Id: audit-42"` · `--cookie "session=..."` · `--random-ua`

Exit codes: `0` success · `1` scan failed · `2` findings met `--fail-on` gate.

### Library

```python
from header_checker.core.scan_engine import run_scan
from header_checker.utils.models import ScanOptions

result = run_scan("https://example.com", options=ScanOptions(method="HEAD"))
for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
    print(f"    Fix: {finding.remediation}")
```

## Screenshots

<img src="screenshots/screenshot_results.png" alt="Scan results view" width="820">

## Development

```bash
pip install -e ".[dev]"
pytest                           # runs the checks/ suite
ruff check header_checker checks # lint
```

To extend the knowledge base, start with the module docstring in
`header_checker/core/header_definitions.py`.

## Legal

Intended **only** for authorized security testing — systems you own or have
explicit written permission to assess. Unauthorized scanning may violate
computer misuse laws in your jurisdiction. The authors accept no liability
for misuse.

## License

Released under the [MIT License](LICENSE).

Guidance references: [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
· [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
· [Mozilla HTTP Observatory](https://developer.mozilla.org/en-US/docs/observatory)
