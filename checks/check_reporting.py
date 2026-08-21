"""Tests for report generation: JSON export, HTML rendering, text summary."""
import json

from header_checker.reporting import render_html, render_text_summary, save_json
from header_checker.utils.models import Finding, ScanResult, Severity


def _sample_result() -> ScanResult:
    from header_checker.utils.models import HeaderResult, HeaderStatus
    result = ScanResult()
    result.network.target_url = "https://example.com"
    result.network.final_url = "https://example.com/"
    result.network.resolved_ip = "93.184.216.34"
    result.network.protocol = "https"
    result.network.response_time_ms = 123.45
    result.tls.supported = True
    result.tls.tls_version = "TLSv1.3"
    result.tls.cipher_suite = "TLS_AES_256_GCM_SHA384"
    result.fingerprint.web_server = "Nginx"
    result.headers.append(HeaderResult(
        name="Strict-Transport-Security", status=HeaderStatus.FAIL,
        summary="Not sent by the server.", recommended_value="max-age=63072000"))
    result.findings.append(Finding(
        title="Missing Strict-Transport-Security header",
        severity=Severity.HIGH,
        description="No HSTS header was returned.",
        remediation="Add Strict-Transport-Security.",
    ))
    return result


class TestJsonExport:
    def test_save_json_round_trip(self, tmp_path):
        out = save_json(_sample_result(), tmp_path / "report.json")
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["network"]["target_url"] == "https://example.com"
        assert data["findings"][0]["severity"] == "High"

    def test_creates_parent_dirs(self, tmp_path):
        out = save_json(_sample_result(), tmp_path / "a" / "b" / "report.json")
        assert out.exists()


class TestHtmlReport:
    def test_contains_core_sections(self):
        html = render_html(_sample_result())
        for fragment in ("Security Report", "Network", "TLS", "Findings",
                         "example.com", "TLSv1.3", "Strict-Transport-Security"):
            assert fragment in html

    def test_escapes_hostile_values(self):
        result = _sample_result()
        result.headers[0].current_value = 'max-age=0<script>alert("x")</script>'
        html = render_html(result)
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html


class TestTextSummary:
    def test_summary_lines(self):
        summary = render_text_summary(_sample_result())
        assert "https://example.com" in summary
        assert "Findings:" in summary
        assert "High" in summary
        assert "Missing Strict-Transport-Security" in summary

    def test_error_result_reported(self):
        result = ScanResult()
        result.error = "Connection failed"
        summary = render_text_summary(result)
        assert "FAILED" in summary
