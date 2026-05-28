"""Tests for auto-training assignment — severity-based campaign allocation."""

import pytest
import sys
import sqlite3
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestAutoTraining:
    """Auto-training tests with isolated temp DB."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self._db_path = str(Path(self.tmpdir) / "training_test.db")
        self._real_connect = sqlite3.connect

        def _fake_connect(db_path, *a, **kw):
            return self._real_connect(self._db_path, *a, **kw)
        monkeypatch.setattr(sqlite3, "connect", _fake_connect)

    def test_critical_assigns_advanced(self):
        from src.auto_training import assign_training
        result = assign_training("user1", 95, "CRITICAL")
        assert result["assigned"] is True
        assert "advanced_phishing_awareness" in result["template"]
        assert result["priority"] == "high"

    def test_high_assigns_basics(self):
        from src.auto_training import assign_training
        result = assign_training("user2", 70, "HIGH")
        assert result["assigned"] is True
        assert "phishing_basics" in result["template"]
        assert result["priority"] == "medium"

    def test_medium_assigns_refresher(self):
        from src.auto_training import assign_training
        result = assign_training("user3", 50, "MEDIUM")
        assert result["assigned"] is True
        assert "security_refresher" in result["template"]
        assert result["priority"] == "low"

    def test_low_risk_no_assignment(self):
        from src.auto_training import assign_training
        result = assign_training("user4", 20, "LOW")
        assert result["assigned"] is False
        assert "risk_below_threshold" in result["reason"]

    def test_duplicate_assignment_skipped(self):
        from src.auto_training import assign_training
        r1 = assign_training("user5", 95, "CRITICAL")
        assert r1["assigned"] is True
        r2 = assign_training("user5", 95, "CRITICAL")
        assert r2["assigned"] is False
        assert "already_assigned" in r2["reason"]

    def test_get_training_status(self):
        from src.auto_training import assign_training, get_training_status
        assign_training("user6", 80, "CRITICAL")
        status = get_training_status("user6")
        assert len(status) >= 1
        assert status[0]["template"] == "advanced_phishing_awareness"
        assert status[0]["status"] == "pending"

    def test_get_training_status_empty(self):
        from src.auto_training import get_training_status
        assert get_training_status("nonexistent") == []
