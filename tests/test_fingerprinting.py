"""Tests for the phishing kit fingerprinting module."""


class TestFingerprinting:
    def test_evilginx_detection(self):
        from src.fingerprinting import fingerprint_email

        html = (
            '<html><title>login</title>'
            '<form action="https://login.microsoftonline.com">'
            '<input name="loginfmt"><input name="passwd">'
            '<button>Sign in</button></form></html>'
        )
        result = fingerprint_email(html, html)
        assert result["total_kits_detected"] > 0
        assert "EvilGinx" in result["kit_matches"]

    def test_gophish_detection(self):
        from src.fingerprinting import fingerprint_email

        text = (
            'Click here to track your campaign: http://evil.com/track/campaign123 '
            '<img src="http://evil.com/track/open.gif" />'
        )
        result = fingerprint_email(text, text)
        assert "Gophish" in result["kit_matches"]

    def test_safe_email_no_kits(self):
        from src.fingerprinting import fingerprint_email

        result = fingerprint_email(
            "Hi Bob, want to grab lunch tomorrow?",
            "",
        )
        assert result["total_kits_detected"] == 0
        assert result["highest_confidence"] == 0.0

    def test_set_detection(self):
        from src.fingerprinting import fingerprint_email

        html = (
            '<html><form action="index.html">'
            '<input name="username"><input name="password">'
            '<input type="submit"></form></html>'
        )
        text = "SEToolkit credential harvester web attack"
        result = fingerprint_email(text, html)
        assert "SET (Social Engineering Toolkit)" in result["kit_matches"]

    def test_confidence_scoring(self):
        from src.fingerprinting import fingerprint_email

        html = (
            '<html><title>login</title>'
            '<form action="https://login.microsoftonline.com/oauth2">'
            '<input name="loginfmt"><input name="passwd"><input name="otc">'
            '<button>Sign in</button></form></html>'
        )
        text = "access_token id_token authorization endpoint"
        headers = {"x-forwarded-host": "evil.com", "x-real-ip": "10.0.0.1"}
        result = fingerprint_email(text, html, headers)
        evilginx = [m for m in result["matches"] if m["name"] == "EvilGinx"]
        assert len(evilginx) > 0
        assert evilginx[0]["confidence"] >= 30

    def test_returns_expected_structure(self):
        from src.fingerprinting import fingerprint_email

        result = fingerprint_email("test", "")
        expected_keys = {
            "kit_matches", "matches", "total_kits_detected",
            "highest_confidence",
        }
        assert expected_keys.issubset(result.keys())

    def test_multiple_kits_detected(self):
        from src.fingerprinting import fingerprint_email

        text = (
            'gophish tracking campaign '
            'SEToolkit credential harvester '
            'socialfish ngrok'
        )
        result = fingerprint_email(text, text)
        assert result["total_kits_detected"] >= 2

    def test_modlishka_detection(self):
        from src.fingerprinting import fingerprint_email

        text = (
            'modlishka reverse proxy auth '
            'username password token 2fa totp'
        )
        result = fingerprint_email(text, text)
        assert "Modlishka" in result["kit_matches"]
