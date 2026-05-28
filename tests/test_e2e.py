"""
E2E / smoke tests — verify the entire application wiring.

These tests:
  1. Check every module imports cleanly (no Streamlit init needed)
  2. Validate the detector → database integration
  3. Verify the API proxy processes requests correctly
  4. Confirm all enterprise components can be instantiated

Run with:
    pytest tests/test_e2e.py -v --tb=short
"""

import os
import sys
import json
import tempfile
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def db_setup():
    """Set up an isolated temp database for the full module."""
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "test_e2e.db"

    import src.database as db
    import src.env as env_mod

    # Point database to temp file
    from src.database import DB_PATH as _orig_db, DATA_DIR as _orig_dir
    db.DB_PATH = str(db_path)
    db.DATA_DIR = Path(tmpdir)
    db.init_db()

    yield db

    # Cleanup
    if db_path.exists():
        db_path.unlink()


# ── Import smoke tests ───────────────────────────────────────────────────

class TestImports:
    """Every module must import without Streamlit initialisation."""

    def test_detector_imports(self):
        from src.detector import analyze_email
        assert callable(analyze_email)

    def test_database_imports(self):
        from src.database import save_analysis, get_history, init_db
        assert callable(save_analysis)

    def test_threat_intel_imports(self):
        from src.threat_intel import check_url_virustotal, check_multiple_urls
        assert callable(check_url_virustotal)

    def test_osint_imports(self):
        from src.osint import run_osint, investigate_domain, extract_domains
        assert callable(run_osint)

    def test_alerts_imports(self):
        from src.alerts import send_threat_alert, get_alert_log, _get_smtp_config
        assert callable(send_threat_alert)

    def test_paddle_billing_imports(self):
        from src.paddle_billing import is_configured, get_price_id, generate_checkout_url
        assert callable(is_configured)

    def test_tenants_imports(self):
        from src.tenants import create_tenant, verify_tenant, get_all_tenants
        assert callable(create_tenant)

    def test_leaderboard_imports(self):
        from src.leaderboard import render_leaderboard
        assert callable(render_leaderboard)

    def test_threat_intel_sharing_imports(self):
        from src.threat_intel_sharing import build_stix_bundle, broadcast_intel
        assert callable(build_stix_bundle)

    def test_env_imports(self):
        from src.env import ENV, load_env, get_config_status
        assert ENV.ADMIN_PASSWORD == "phishguard2026"


# ── Detector → Database integration ──────────────────────────────────────

class TestDetectorDatabaseIntegration:
    """Verify the full pipeline: analyze text → save → retrieve."""

    def test_full_pipeline(self, db_setup):
        from src.detector import analyze_email

        text = "URGENT: Your account has been compromised. Click here to verify: http://evil.com/login"
        results = analyze_email(text)

        # Detector must return all expected keys
        for key in ("risk_score", "severity", "total_keyword_hits",
                     "suspicious_url_count", "url_count", "keyword_matches",
                     "suspicious_urls", "has_attachments"):
            assert key in results, f"Missing key: {key}"

        # Save to DB
        db_setup.save_analysis(results, text)
        history = db_setup.get_history(10)
        assert len(history) == 1
        assert history[0][1] == results["risk_score"]
        assert history[0][2] == results["severity"]

    def test_high_risk_email(self, db_setup):
        from src.detector import analyze_email

        text = (
            "URGENT: Your PayPal account has been suspended due to unusual activity. "
            "You must verify your identity immediately or your account will be terminated. "
            "Click here to confirm your password: http://bit.ly/evil-phish "
            "This is your final notice. Act now before your account is locked."
        )
        results = analyze_email(text)
        assert results["risk_score"] >= 50
        assert results["severity"] in ("HIGH", "CRITICAL")
        assert results["suspicious_url_count"] >= 1
        assert results["total_keyword_hits"] >= 3

    def test_safe_email(self, db_setup):
        from src.detector import analyze_email

        text = "Hey team, just a reminder about tomorrow's standup at 10am. Thanks!"
        results = analyze_email(text)
        assert results["risk_score"] < 25
        assert results["severity"] == "LOW"

    def test_database_persistence(self, db_setup):
        """Multiple saves maintain correct order."""
        texts = [
            ("Safe email here", 0),
            ("URGENT: verify now http://evil.com", 1),
        ]
        for text, _ in texts:
            from src.detector import analyze_email
            results = analyze_email(text)
            db_setup.save_analysis(results, text)

        history = db_setup.get_history(5)
        assert len(history) >= 2


# ── OSINT integration ───────────────────────────────────────────────────

class TestOSINTIntegration:
    def test_domain_extraction(self):
        from src.osint import extract_domains
        text = "Check http://evil.com and contact user@gmail.com"
        domains = extract_domains(text)
        assert "evil.com" in domains
        assert "gmail.com" in domains

    def test_sender_extraction(self):
        from src.osint import extract_sender_email
        text = "From: hacker@evil.com\nSome content here"
        email = extract_sender_email(text)
        assert email == "hacker@evil.com"

    def test_ip_extraction(self):
        from src.osint import extract_ips
        text = "Connection from 185.220.101.42 at 3am"
        ips = extract_ips(text)
        assert len(ips) > 0


# ── API proxy smoke test ─────────────────────────────────────────────────

class TestAPIProxy:
    """Start a real API proxy server and call it."""

    @classmethod
    def setup_class(cls):
        cls.server = None
        cls.thread = None
        cls.port = 19876  # High port to avoid conflicts

        # Import and start
        import api_proxy
        from http.server import HTTPServer

        cls.handler = api_proxy.APIHandler
        cls.server = HTTPServer(("127.0.0.1", cls.port), cls.handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)  # Let server start

    @classmethod
    def teardown_class(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def test_health_endpoint(self):
        import urllib.request
        resp = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert data["service"] == "phishguard-api-proxy"

    def test_scan_endpoint(self):
        import urllib.request
        body = json.dumps({"text": "URGENT: verify your account now"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/v1/scan",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req)
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "risk_score" in data
        assert "severity" in data
        assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ── Health check smoke test ──────────────────────────────────────────────

class TestHealthCheck:
    def test_health_check_database(self):
        """health_check.py must handle database failure gracefully."""
        import health_check
        # Point to non-existent DB — should report failure, not crash
        import src.database as db
        orig = db.DB_PATH
        try:
            import tempfile, os; db.DB_PATH = os.path.join(tempfile.gettempdir(), "nonexistent_phishguard.db")
            ok, msg = health_check.check_database()
            assert not ok
            assert "error" in msg.lower() or "not found" in msg.lower()
        finally:
            db.DB_PATH = orig
