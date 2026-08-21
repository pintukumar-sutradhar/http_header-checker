"""Tests for data models: severity weights, grading and serialization."""
import json

from header_checker.utils.models import (
    Finding,
    HeaderStatus,
    ScanResult,
    Severity,
)


class TestSeverity:
    def test_weight_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight

    def test_info_has_zero_weight(self):
        assert Severity.INFO.weight == 0

    def test_colors_are_hex(self):
        for sev in Severity:
            assert sev.color.startswith("#") and len(sev.color) == 7


class TestHeaderStatus:
    def test_plain_language_statuses(self):
        assert {s.value for s in HeaderStatus} == {"Pass", "Warning", "Fail", "Info"}


class TestSerialization:
    def test_finding_to_dict_is_json_serializable(self):
        finding = Finding(
            title="Test finding",
            severity=Severity.HIGH,
            description="d",
            references=["https://example.com"],
        )
        data = json.dumps(finding.to_dict())
        assert json.loads(data)["severity"] == "High"

    def test_full_result_to_dict_is_json_serializable(self):
        result = ScanResult()
        result.findings.append(Finding(title="x", severity=Severity.LOW))
        payload = json.dumps(result.to_dict())
        loaded = json.loads(payload)
        assert "score" not in loaded
        assert loaded["findings"][0]["severity"] == "Low"
