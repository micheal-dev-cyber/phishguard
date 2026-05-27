"""Tests for database operations — pure Python, no streamlit dependency."""

import os
import pytest
import sys
import tempfile
import json
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestDatabase:
    """Test database CRUD with isolated temp database."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"

        import src.database as db

        monkeypatch.setattr(db, "DB_PATH", str(self.db_path))
        monkeypatch.setattr(db, "DATA_DIR", Path(self.tmpdir))
        db.init_db()
        self.db = db

    def test_save_and_get_history(self):
        self.db.save_analysis(
            {"risk_score": 75, "severity": "HIGH", "total_keyword_hits": 5, "suspicious_url_count": 2},
            "Suspicious email...",
        )
        self.db.save_analysis(
            {"risk_score": 20, "severity": "LOW", "total_keyword_hits": 1, "suspicious_url_count": 0},
            "Safe email...",
        )
        history = self.db.get_history(10)
        assert len(history) == 2

        # Most recent first (second save has id=2)
        assert history[0][1] == 20
        assert history[0][2] == "LOW"

    def test_save_with_ai_report(self):
        self.db.save_analysis(
            {"risk_score": 85, "severity": "CRITICAL", "total_keyword_hits": 8, "suspicious_url_count": 3},
            "Phishing email...",
            ai_report="This is a phishing attempt...",
        )
        history = self.db.get_history(10)
        assert len(history) == 1
        assert history[0][1] == 85

    def test_empty_history(self):
        history = self.db.get_history(10)
        assert history == []

    def test_save_analysis_returns_none(self):
        result = self.db.save_analysis(
            {"risk_score": 50, "severity": "MEDIUM", "total_keyword_hits": 3, "suspicious_url_count": 1},
            "Test",
        )
        assert result is None

    def test_multiple_saves_order(self):
        scores = [10, 50, 90]
        for s in scores:
            self.db.save_analysis(
                {"risk_score": s, "severity": "TEST", "total_keyword_hits": 0, "suspicious_url_count": 0},
                f"Email {s}",
            )
        history = self.db.get_history(5)
        assert [h[1] for h in history] == [90, 50, 10]

    def test_history_limit(self):
        for i in range(20):
            self.db.save_analysis(
                {"risk_score": i * 5, "severity": "TEST", "total_keyword_hits": i, "suspicious_url_count": 0},
                f"Email {i}",
            )
        history = self.db.get_history(5)
        assert len(history) == 5
