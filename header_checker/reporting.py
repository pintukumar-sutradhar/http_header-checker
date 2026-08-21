"""
header_checker.reporting
=========================
Report generation for scan results: JSON export, standalone HTML reports
and plain-text terminal summaries. Pure logic, no web-framework or Qt
dependencies.
"""
from __future__ import annotations

import html as _html
import json
from pathlib import Path

from .utils.models import HeaderStatus, ScanResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def save_json(result: ScanResult, path: str | Path) -> Path:
    """Serialize a ScanResult to a pretty-printed JSON file."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return out


# --------------------------------------------------------------------------- #
# Terminal summary
# --------------------------------------------------------------------------- #
def render_text_summary(result: ScanResult) -> str:
    """Human-readable multi-line summary of a scan result (no ANSI colors)."""
    lines: list[str] = []
    net = result.network

    target = net.target_url or "(unknown)"
    if net.final_url and net.final_url != net.target_url:
        target += f"  (final: {net.final_url})"

    lines.append(f"Target:   {target}")
    if result.error:
        lines.append(f"Status:   FAILED - {result.error}")
        return "\n".join(lines)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in result.findings:
        if f.severity in counts:
            counts[f.severity] += 1
    summary = ", ".join(f"{counts[s]} {s.value}" for s in SEVERITY_ORDER if counts[s])
    lines.append(f"Findings: {summary or 'none'}")

    if net.resolved_ip:
        geo = f" ({net.country})" if net.country else ""
        lines.append(f"Host:     {net.resolved_ip}{geo}")
    if result.fingerprint.web_server:
        lines.append(f"Server:   {result.fingerprint.web_server}")
    if tls := result.tls:
        if tls.supported:
            lines.append(f"TLS:      {tls.tls_version} - {tls.cipher_suite}")

    lines.append("")
    current: Severity | None = None
    for f in result.findings:
        if f.severity != current:
            current = f.severity
            lines.append(f"{current.value.upper()}")
        desc = f.description.split(";")[0].strip()
        lines.append(f"  - [{f.category}] {f.title}: {desc}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTTP Header Checker Report - {target}</title>
<style>
  :root {{ --bg:#f8fafc; --panel:#ffffff; --border:#e2e8f0; --text:#0f172a;
          --muted:#64748b; --accent:#2563eb; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:24px; background:var(--bg); color:var(--text);
         font:14px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1000px; margin:0 auto; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  h2 {{ font-size:15px; margin:28px 0 10px; }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-top:16px; }}
  .card {{ flex:1 1 170px; background:var(--panel); border:1px solid var(--border);
          border-radius:10px; padding:12px 16px; }}
  .card .k {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.07em; }}
  .card .v {{ font-size:17px; font-weight:600; margin-top:4px; word-break:break-all; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:10px; overflow:hidden; }}
  th,td {{ text-align:left; padding:7px 12px; border-bottom:1px solid var(--border);
          vertical-align:top; font-size:13px; }}
  th {{ background:#f1f5f9; color:var(--muted); font-size:11px;
       text-transform:uppercase; letter-spacing:.05em; }}
  tr:last-child td {{ border-bottom:none; }}
  code {{ background:#f1f5f9; border-radius:4px; padding:1px 5px; font-size:12px; word-break:break-all; }}
  .pill {{ display:inline-block; min-width:64px; text-align:center; border-radius:999px;
          font-size:11px; font-weight:700; padding:2px 10px; color:#fff; }}
  footer {{ margin-top:32px; color:var(--muted); font-size:12px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>HTTP Header Checker &mdash; Security Report</h1>
  <div class="sub">Scan {scan_id} &middot; {timestamp} &middot; Analyst: {analyst} &middot; Tool v{version}</div>

  <div class="cards">
    <div class="card"><div class="k">Target</div><div class="v">{target}</div></div>
    <div class="card"><div class="k">Final URL</div><div class="v">{final_url}</div></div>
    <div class="card"><div class="k">Response Time</div><div class="v">{response_time}</div></div>
  </div>

  <h2>Network</h2>
  <table>
    <tr><th style="width:200px">IPv4</th><td>{ipv4}</td></tr>
    <tr><th>IPv6</th><td>{ipv6}</td></tr>
    <tr><th>Country / Provider</th><td>{geo}</td></tr>
    <tr><th>Protocol</th><td>{protocol}</td></tr>
    <tr><th>Redirects / Headers</th><td>{redirect_count} / {total_headers}</td></tr>
  </table>

  <h2>TLS / Certificate</h2>
  {tls_section}

  <h2>Headers ({header_count})</h2>
  <table>
    <tr><th>Header</th><th>Status</th><th>Value / Recommendation</th><th>Verdict</th></tr>
    {header_rows}
  </table>

  <h2>Cookies ({cookie_count})</h2>
  {cookie_section}

  <h2>Redirect Chain ({hop_count} hops)</h2>
  {redirect_section}

  <h2>Findings ({finding_count})</h2>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>Remediation</th></tr>
    {finding_rows}
  </table>

  <footer>Generated by HTTP Header Checker v{version}. Authorized testing only.</footer>
</div>
</body>
</html>
"""


def _esc(value) -> str:
    return _html.escape(str(value)) if value is not None else ""


def _sev_pill(severity: Severity) -> str:
    return (f'<span class="pill" style="background:{severity.color}">'
            f"{_esc(severity.value)}</span>")


def _status_pill(status: HeaderStatus) -> str:
    return (f'<span class="pill" style="background:{status.color}">'
            f"{_esc(status.value)}</span>")


def render_html(result: ScanResult) -> str:
    """Render a fully self-contained HTML report (inline CSS, no JS)."""
    net, tls = result.network, result.tls

    if tls.supported:
        tls_rows = "".join(
            f"<tr><th>{k}</th><td>{v}</td></tr>"
            for k, v in [
                ("Protocol", _esc(tls.tls_version)),
                ("Cipher Suite", f"{_esc(tls.cipher_suite)} ({_esc(tls.cipher_bits)} bits)" if tls.cipher_suite else ""),
                ("Subject", _esc(tls.certificate_subject)),
                ("Issuer", _esc(tls.certificate_issuer)),
                ("Valid Until", f"{_esc(tls.certificate_expiry)} ({tls.days_until_expiry} days left)" if tls.days_until_expiry is not None else ""),
                ("Public Key", f"{_esc(tls.public_key_type)} {_esc(tls.public_key_size)} bits" if tls.public_key_type else ""),
            ]
            if v
        )
        issues = "".join(f"<li>{_esc(i)}</li>" for i in tls.issues)
        tls_section = f"<table>{tls_rows}</table>" + (f"<ul>{issues}</ul>" if issues else "")
    else:
        tls_section = f"<p class='sub'>No TLS analysis available. {_esc(tls.error or '')}</p>"

    header_rows = "".join(
        "<tr>"
        f"<td><code>{_esc(h.name)}</code></td>"
        f"<td>{_status_pill(h.status)}</td>"
        f"<td>{('<code>' + _esc(h.current_value) + '</code>') if h.current_value else '-'}"
        f"{(' &rarr; <code>' + _esc(h.recommended_value) + '</code>') if h.recommended_value and h.status != HeaderStatus.PASS else ''}</td>"
        f"<td class='sub'>{_esc(h.summary)}</td>"
        "</tr>"
        for h in result.headers
    )

    if result.cookies:
        cookie_rows = "".join(
            f"<tr><td><code>{_esc(c.name)}</code></td>"
            f"<td>{'Secure' if c.secure else '<strong style=color:#dc2626>no Secure</strong>'} / "
            f"{'HttpOnly' if c.http_only else '<strong style=color:#dc2626>no HttpOnly</strong>'} / "
            f"SameSite={_esc(c.same_site) if c.same_site else '<strong style=color:#d97706>unset</strong>'}</td>"
            f"<td>{'; '.join(_esc(i) for i in c.issues)}</td></tr>"
            for c in result.cookies
        )
        cookie_section = ("<table><tr><th>Cookie</th><th>Flags</th><th>Issues</th></tr>"
                          + cookie_rows + "</table>")
    else:
        cookie_section = "<p class='sub'>No cookies observed.</p>"

    if result.redirects.hops:
        hop_rows = "".join(
            f"<tr><td>{h.order}</td><td><code>{_esc(h.url)}</code></td>"
            f"<td>{h.status_code}</td><td>{_esc(h.location)}</td></tr>"
            for h in result.redirects.hops
        )
        redirect_section = ("<table><tr><th>#</th><th>URL</th><th>Status</th><th>Location</th></tr>"
                            + hop_rows + "</table>")
    else:
        redirect_section = "<p class='sub'>No redirects followed.</p>"

    finding_rows = "".join(
        "<tr>"
        f"<td>{_sev_pill(f.severity)}</td>"
        f"<td><strong>{_esc(f.title)}</strong><br><span class='sub'>{_esc(f.description)}</span></td>"
        f"<td>{_esc(f.remediation)}</td>"
        "</tr>"
        for f in result.findings
    ) or "<tr><td colspan=3 class='sub'>No findings.</td></tr>"

    return _HTML_TEMPLATE.format(
        target=_esc(net.target_url),
        scan_id=_esc(result.scan_id[:8]),
        timestamp=_esc(result.timestamp),
        analyst=_esc(result.analyst),
        version=_esc(result.tool_version),
        final_url=_esc(net.final_url),
        response_time=f"{net.response_time_ms:.0f} ms" if net.response_time_ms else "-",
        ipv4=_esc(net.resolved_ip or "-"),
        ipv6=_esc(net.resolved_ipv6 or "-"),
        geo=_esc(", ".join(x for x in [net.country, net.hosting_provider] if x) or "-"),
        protocol=_esc(net.protocol or "-"),
        redirect_count=net.redirect_count,
        total_headers=net.total_headers,
        tls_section=tls_section,
        header_count=len(result.headers),
        header_rows=header_rows,
        cookie_count=len(result.cookies),
        cookie_section=cookie_section,
        hop_count=len(result.redirects.hops),
        redirect_section=redirect_section,
        finding_count=len(result.findings),
        finding_rows=finding_rows,
    )


def save_html(result: ScanResult, path: str | Path) -> Path:
    """Render and write a standalone HTML report."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(result), encoding="utf-8")
    return out
