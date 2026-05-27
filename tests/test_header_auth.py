"""Tests for email header authentication analysis."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.header_auth import analyze_auth_headers


class TestHeaderAuth:
    def test_spf_pass(self):
        text = """From: someone@example.com
Authentication-Results: spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass
Subject: Legitimate email"""
        result = analyze_auth_headers(text)
        assert result["overall"] == "PASS"
        assert result["spf_status"] == "pass"
        assert result["risk_contribution"] == 0

    def test_spf_fail(self):
        text = """From: spoofed@evil.com
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
Subject: Phishing attempt"""
        result = analyze_auth_headers(text)
        assert result["overall"] == "FAIL"
        assert result["spf_status"] == "fail"
        assert result["risk_contribution"] >= 20

    def test_partial_pass(self):
        text = """From: user@company.com
Authentication-Results: spf=pass; dkim=neutral; dmarc=bestguesspass
Subject: Partially authenticated"""
        result = analyze_auth_headers(text)
        assert result["overall"] in ("PASS", "WARNING")

    def test_missing_headers(self):
        text = """From: unknown@somewhere.com
Subject: No auth headers"""
        result = analyze_auth_headers(text)
        assert result["spf_status"] == "missing"
        assert result["overall"] in ("WARNING", "FAIL")

    def test_received_spf_fallback(self):
        text = """From: test@example.com
Received-SPF: fail (example.com: domain does not designate 1.2.3.4 as permitted sender)
Subject: SPF fail via Received-SPF"""
        result = analyze_auth_headers(text)
        assert result["spf_status"] == "fail"
        assert result["overall"] == "FAIL"

    def test_dkim_signed_without_result(self):
        text = """From: signed@example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
Subject: DKIM present but no auth result"""
        result = analyze_auth_headers(text)
        assert result["has_dkim_signature"] is True

    def test_empty_text(self):
        result = analyze_auth_headers("")
        assert result["overall"] == "WARNING"
