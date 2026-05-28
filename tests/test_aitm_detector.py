import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.aitm_detector import detect_aitm_harvester


def test_clean_email_no_indicators():
    email = "Hi team, please find the quarterly report attached. Best, John"
    result = detect_aitm_harvester(email_text=email, urls=[])
    assert result["detected"] is False
    assert result["confidence"] < 35
    assert result["severity"] == "LOW"
    assert len(result["indicators"]) == 0


def test_otp_harvester_body_pattern():
    email = "We detected unusual activity on your account. Please verify your identity by entering the OTP code sent to your phone. This link will expire in 10 minutes."
    result = detect_aitm_harvester(email_text=email, urls=["https://secure-login.example.com/verify"])
    assert result["detected"] is True
    assert result["confidence"] >= 35
    assert any("OTP" in i or "verification" in i or "MFA" in i for i in result["indicators"])


def test_url_with_mfa_keywords():
    email = "Click here to secure your account."
    result = detect_aitm_harvester(
        email_text=email,
        urls=["https://paypal-authenticator.com/2fa/verify/token"],
    )
    assert result["detected"] is True
    assert result["url_score"] >= 15
    assert any("URL" in i for i in result["indicators"])


def test_multiple_brand_mentions():
    email = "Your PayPal account has been suspended. Please verify with Microsoft Authenticator. Amazon login required."
    result = detect_aitm_harvester(
        email_text=email,
        urls=["https://paypal-secure.xyz/verify"],
    )
    assert result["detected"] is True
    assert result["body_score"] >= 10
    assert any("brand" in i.lower() for i in result["indicators"])


def test_high_risk_tld_domain():
    email = "Verify your account now."
    result = detect_aitm_harvester(
        email_text=email,
        urls=["https://secure-login.xyz/verify"],
    )
    assert result["detected"] is True
    assert result["domain_score"] >= 15
    assert any("TLD" in i for i in result["indicators"])


def test_domain_impersonates_brand():
    email = "Please update your payment information."
    result = detect_aitm_harvester(
        email_text=email,
        urls=["https://paypal-secure-appeal.xyz/login/"],
    )
    assert result["detected"] is True
    assert result["domain_score"] >= 20
    assert any("impersonate" in i.lower() or "imperson" in i for i in result["indicators"])


def test_osint_data_integration():
    email = "Your account requires verification."
    osint_data = {
        "osint_risk_score": 80,
        "domain_results": [
            {
                "domain": "evil-phish.xyz",
                "risk_score": 85,
            }
        ],
    }
    result = detect_aitm_harvester(
        email_text=email,
        urls=["https://evil-phish.xyz/verify"],
        osint_data=osint_data,
    )
    assert result["detected"] is True
    assert result["domain_score"] >= 15


def test_critical_severity():
    email = "We detected unauthorized access to your Microsoft account. Please verify your identity using Google Authenticator and enter the OTP code. Your account will be suspended."
    result = detect_aitm_harvester(
        email_text=email,
        urls=["https://microsoft-account-verify.xyz/2fa/authenticator"],
    )
    assert result["detected"] is True
    assert result["confidence"] >= 70
    assert result["severity"] == "CRITICAL"
    assert "AitM" in result["label"]


def test_none_inputs():
    result = detect_aitm_harvester()
    assert result["detected"] is False
    assert result["confidence"] == 0


def test_dict_urls():
    email = "Click here to verify your account identity."
    result = detect_aitm_harvester(
        email_text=email,
        urls=[{"url": "https://evil.com/verify"}, {"url": "https://safe.com"}],
    )
    assert result["detected"] is True
