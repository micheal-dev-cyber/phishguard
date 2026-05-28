"""Tests for SIEM webhook dispatch — formatting and dispatch logic."""

import pytest
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestSIEMClient:
    """SIEMClient tests — mock ENV, verify formatting."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.SIEM_SPLUNK_HEC_URL", "https://splunk.example.com:8088")
        monkeypatch.setattr("src.env.ENV.SIEM_SPLUNK_HEC_TOKEN", "splunk-token")
        monkeypatch.setattr("src.env.ENV.SIEM_ELASTIC_CLOUD_ID", "my-deployment")
        monkeypatch.setattr("src.env.ENV.SIEM_ELASTIC_API_KEY", "elastic-key")
        monkeypatch.setattr("src.env.ENV.SIEM_QRAZAR_URL", "https://qradar.example.com")
        monkeypatch.setattr("src.env.ENV.SIEM_QRAZAR_API_KEY", "qradar-key")

    def test_any_enabled_true_when_configured(self):
        from src.siem_webhook import SIEMClient
        client = SIEMClient()
        assert client.any_enabled is True

    def test_any_enabled_false_when_unconfigured(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.SIEM_SPLUNK_HEC_URL", "")
        monkeypatch.setattr("src.env.ENV.SIEM_ELASTIC_CLOUD_ID", "")
        monkeypatch.setattr("src.env.ENV.SIEM_QRAZAR_URL", "")
        from src.siem_webhook import SIEMClient
        client = SIEMClient()
        assert client.any_enabled is False

    def test_dispatch_calls_all_three(self, monkeypatch):
        from src.siem_webhook import SIEMClient
        client = SIEMClient()
        sentinel = []

        def _fake_post(req, name):
            sentinel.append(name)
            return {"siem": name, "status": 200, "success": True}

        monkeypatch.setattr(client, "_post", _fake_post)
        event = {"risk_score": 85, "severity": "HIGH", "timestamp": "2026-01-01T00:00:00"}
        results = client.dispatch(event)
        assert len(results) == 3
        assert sorted(sentinel) == ["Elastic", "QRadar", "Splunk"]

    def test_splunk_payload_format(self, monkeypatch):
        from src.siem_webhook import SIEMClient
        from urllib.request import Request

        client = SIEMClient()
        captured = {}

        def _fake_post(req, name):
            captured["req"] = req
            captured["name"] = name
            return {"siem": name, "status": 200, "success": True}

        monkeypatch.setattr(client, "_post", _fake_post)
        event = {"risk_score": 90, "severity": "CRITICAL", "username": "admin"}
        client._send_splunk(event)

        body = json.loads(captured["req"].data)
        assert body["sourcetype"] == "phishguard:threat"
        assert body["event"]["risk_score"] == 90
        assert captured["req"].headers["Authorization"] == "Splunk splunk-token"

    def test_post_failure_returns_error(self, monkeypatch):
        from src.siem_webhook import SIEMClient
        from urllib.error import URLError

        client = SIEMClient()

        def _fake_urlopen(req, timeout=10):
            raise URLError("connection failed")
        monkeypatch.setattr("src.siem_webhook.urlopen", _fake_urlopen)

        result = client._send_splunk({"risk_score": 50})
        assert result["success"] is False
        assert "connection failed" in result["error"]

    def test_dispatch_empty_when_nothing_configured(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.SIEM_SPLUNK_HEC_URL", "")
        monkeypatch.setattr("src.env.ENV.SIEM_ELASTIC_CLOUD_ID", "")
        monkeypatch.setattr("src.env.ENV.SIEM_QRAZAR_URL", "")
        from src.siem_webhook import SIEMClient
        client = SIEMClient()
        assert client.dispatch({}) == []
