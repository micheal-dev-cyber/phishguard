import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.enterprise_api import handle_scan_request, _severity_label


def test_missing_fields_returns_error():
    result = handle_scan_request({})
    assert "error" in result
    assert "Provide" in result["error"]


def test_only_text_returns_verdict():
    result = handle_scan_request({"text": "Hi team, please find the report attached. Best, John"})
    assert "verdict" in result
    assert "risk_score" in result["verdict"]
    assert "severity" in result["verdict"]
    assert result["verdict"]["is_threat"] is False


def test_phishing_text_elevates_score():
    result = handle_scan_request({
        "text": "URGENT: Your PayPal account has been compromised. Click here to verify your identity immediately or your account will be suspended.",
    })
    assert result["verdict"]["risk_score"] >= 25
    assert result["layers"]["heuristic"] is not None
    assert result["layers"]["heuristic"]["score"] >= 25


def test_returns_all_three_layers():
    result = handle_scan_request({"text": "Test email content here."})
    assert "layers" in result
    assert "heuristic" in result["layers"]
    assert "ai_text_detection" in result["layers"]
    assert "aitm_detection" in result["layers"]


def test_ai_text_detection_layer():
    result = handle_scan_request({"text": "Formal text that sounds like a human wrote it carefully."})
    ai = result["layers"]["ai_text_detection"]
    assert "probability" in ai
    assert "score" in ai
    assert isinstance(ai.get("indicators"), list)


def test_aitm_layer_with_urls():
    result = handle_scan_request({
        "text": "Please verify your account.",
        "urls": ["https://secure-login.xyz/2fa/verify"],
    })
    aitm = result["layers"]["aitm_detection"]
    assert aitm is not None
    assert aitm.get("confidence", 0) >= 15


def test_verdict_has_meta():
    result = handle_scan_request({"text": "Test"})
    assert result["meta"]["service"] == "phishguard-enterprise-api"
    assert result["meta"]["version"] == "3.0.0"


def test_severity_label():
    assert _severity_label(0) == "LOW"
    assert _severity_label(25) == "MEDIUM"
    assert _severity_label(50) == "HIGH"
    assert _severity_label(75) == "CRITICAL"
    assert _severity_label(100) == "CRITICAL"


def test_high_risk_threat():
    result = handle_scan_request({
        "text": "URGENT: We detected unusual activity on your Microsoft account. Please verify your identity by entering the OTP code sent to your phone. This link will expire in 10 minutes. Click here to secure your account: https://microsoft-account-verify.xyz/2fa/authenticator",
        "urls": ["https://microsoft-account-verify.xyz/2fa/authenticator"],
    })
    assert result["verdict"]["is_threat"] is True
    assert result["verdict"]["aitm_confidence"] >= 35


def test_urls_field_passed_to_layers():
    result = handle_scan_request({
        "text": "",
        "urls": ["https://evil-phish.xyz/verify"],
    })
    assert "verdict" in result
    assert result["verdict"]["aitm_confidence"] >= 15


def test_composite_score_uplifted_by_aitm():
    result = handle_scan_request({
        "text": "Please verify your Microsoft account.",
        "urls": ["https://microsoft-verify.tk/2fa/otp"],
    })
    v = result["verdict"]
    h = result["layers"]["heuristic"]
    if h and h["score"] < v["risk_score"]:
        assert v["risk_score"] >= v["aitm_confidence"]
