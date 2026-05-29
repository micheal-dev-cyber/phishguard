"""Tests for the core email analysis engine — no streamlit dependency."""


class TestDetector:
    """Detector module is pure Python with no streamlit dependency."""

    def test_phishing_email_high_risk(self):
        from src.detector import analyze_email

        email = (
            "From: support@bank-secure-update.com\n"
            "Subject: URGENT: Account Suspended — Verify Now\n"
            "Dear valued customer,\n"
            "Your account has been suspended due to suspicious activity. "
            "Click here to verify: http://evil-phish.example.com\n"
            "Failure to act within 24 hours will result in permanent closure."
        )
        result = analyze_email(email)
        assert result["risk_score"] >= 50
        assert result["severity"] in ("HIGH", "CRITICAL")
        assert len(result["suspicious_urls"]) > 0
        assert result["total_keyword_hits"] > 0

    def test_safe_email_low_risk(self):
        from src.detector import analyze_email

        email = (
            "From: alice@example.com\n"
            "Subject: Lunch tomorrow\n"
            "Hi Bob, want to grab lunch tomorrow at 12? Let me know. Best, Alice"
        )
        result = analyze_email(email)
        assert result["risk_score"] < 30
        assert result["severity"] == "LOW"
        assert result["total_keyword_hits"] == 0

    def test_empty_email(self):
        from src.detector import analyze_email

        result = analyze_email("")
        assert result["risk_score"] == 0

    def test_url_extraction(self):
        from src.detector import analyze_email

        email = "Visit http://evil.com and http://phish.net for details."
        result = analyze_email(email)
        assert len(result["urls_found"]) >= 2
        assert "http://evil.com" in result["urls_found"]

    def test_keyword_detection(self):
        from src.detector import analyze_email

        email = "URGENT: Your account will be suspended. Click here to verify your password."
        result = analyze_email(email)
        matches = result.get("keyword_matches", {})
        all_keywords = []
        for cat in matches.values():
            all_keywords.extend(cat)
        assert len(all_keywords) >= 2

    def test_social_engineering_detection(self):
        from src.detector import analyze_email

        email = (
            "From: ceo@company.com\n"
            "Subject: URGENT Wire transfer needed\n"
            "Hi, I'm in a meeting. Wire money urgently. "
            "Click here http://evil-phish.com to verify. "
            "This is confidential — don't tell anyone."
        )
        result = analyze_email(email)
        assert result["risk_score"] >= 35
        assert result["total_keyword_hits"] >= 1

    def test_suspicious_urls_decreases_without_urls(self):
        from src.detector import analyze_email

        email = "Just a normal message with no links whatsoever."
        result = analyze_email(email)
        assert result["url_count"] == 0
        assert result["suspicious_url_count"] == 0

    def test_returns_all_expected_keys(self):
        from src.detector import analyze_email

        email = "Test email http://example.com"
        result = analyze_email(email)
        expected_keys = {
            "risk_score", "severity", "severity_color",
            "urls_found", "suspicious_urls", "url_count",
            "suspicious_url_count", "keyword_matches",
            "total_keyword_hits", "has_attachments",
            "header_analysis", "attachment_analysis",
            "language_analysis", "languages_detected",
            "kit_fingerprinting",
        }
        assert expected_keys.issubset(result.keys())
