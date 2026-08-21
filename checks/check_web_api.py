"""Tests for the web dashboard API (no network)."""
import pytest
from fastapi.testclient import TestClient

from header_checker.utils.models import ScanResult


@pytest.fixture()
def client(monkeypatch):
    from header_checker.web.app import app

    def fake_run(url, options=None, progress_cb=None, cancel_check=None, analyst=""):
        result = ScanResult()
        result.network.target_url = url
        result.network.final_url = url
        return result

    monkeypatch.setattr("header_checker.web.app.run_scan", fake_run)
    return TestClient(app)


def test_index_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "Header Checker" in res.text
    assert "<script>" in res.text  # self-contained page


def test_scan_endpoint_returns_result(client):
    res = client.post("/api/scan", json={"url": "https://example.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["network"]["target_url"] == "https://example.com"
    assert "findings" in data and "headers" in data and "tls" in data


def test_scan_endpoint_validates_method(client):
    res = client.post("/api/scan", json={"url": "https://x.com", "method": "POST"})
    assert res.status_code == 422


def test_scan_endpoint_rejects_bad_timeout(client):
    res = client.post("/api/scan", json={"url": "https://x.com", "timeout": 999})
    assert res.status_code == 422
