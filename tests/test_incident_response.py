"""Tests for Incident Responder — verdict-based actions."""

import pytest
import sys
import sqlite3
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestIncidentResponder:
    """IncidentResponder tests with isolated temp DB."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self._db_path = str(Path(self.tmpdir) / "ir_test.db")
        self._real_connect = sqlite3.connect

        def _fake_connect(db_path, *a, **kw):
            return self._real_connect(self._db_path, *a, **kw)
        monkeypatch.setattr(sqlite3, "connect", _fake_connect)

    def test_low_severity_no_action(self, monkeypatch):
        from src.incident_response import IncidentResponder
        ir = IncidentResponder()
        monkeypatch.setattr(ir, "graph", None)
        result = ir.respond({"severity": "LOW", "risk_score": 10})
        assert result["actions"] == []

    def test_medium_severity_flag_for_review(self, monkeypatch):
        from src.incident_response import IncidentResponder
        ir = IncidentResponder()
        monkeypatch.setattr(ir, "graph", None)
        result = ir.respond({"severity": "MEDIUM", "risk_score": 50})
        assert "flag_for_review" in result["actions"]

    def test_high_severity_triggers_alert_admin(self, monkeypatch):
        from src.incident_response import IncidentResponder
        ir = IncidentResponder()
        monkeypatch.setattr(ir, "graph", None)
        result = ir.respond({
            "severity": "HIGH", "risk_score": 75,
            "sender_email": "phish@evil.com",
        })
        assert "alert_admin" in result["actions"]

    def test_critical_severity_triggers_block_domain(self, monkeypatch):
        from src.incident_response import IncidentResponder
        ir = IncidentResponder()
        monkeypatch.setattr(ir, "graph", None)
        result = ir.respond({
            "severity": "CRITICAL", "risk_score": 95,
            "sender_email": "phish@evil.com",
        })
        assert "alert_admin" in result["actions"]
        assert "block_domain_dns" in result["actions"]

    def test_critical_response_logs_incident(self, monkeypatch):
        from src.incident_response import IncidentResponder
        ir = IncidentResponder()
        monkeypatch.setattr(ir, "graph", None)
        ir.respond({
            "severity": "CRITICAL", "risk_score": 90,
            "sender_email": "attacker@bad.com",
        })
        conn = self._real_connect(self._db_path)
        c = conn.cursor()
        c.execute("SELECT sender, severity, action FROM incident_responses")
        rows = c.fetchall()
        conn.close()
        assert len(rows) >= 1
        assert rows[0][0] == "attacker@bad.com"

    def test_score_below_threshold_no_action(self, monkeypatch):
        from src.incident_response import IncidentResponder
        ir = IncidentResponder()
        monkeypatch.setattr(ir, "graph", None)
        result = ir.respond({"severity": "HIGH", "risk_score": 50})
        assert result["actions"] == []

    def test_respond_returns_severity(self, monkeypatch):
        from src.incident_response import IncidentResponder
        ir = IncidentResponder()
        monkeypatch.setattr(ir, "graph", None)
        result = ir.respond({"severity": "CRITICAL", "risk_score": 100, "sender_email": "a@b.com"})
        assert result["severity"] == "CRITICAL"
