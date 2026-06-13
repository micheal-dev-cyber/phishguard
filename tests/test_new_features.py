"""Tests for the new advanced investigation features."""
import sys
sys.path.insert(0, '.')

# Sample results for testing
SAMPLE_RESULTS = {
    "risk_score": 85,
    "severity": "CRITICAL",
    "severity_color": "#FF0000",
    "keyword_matches": {"credentials": ["password", "login"], "urgent": ["immediately"]},
    "total_keyword_hits": 3,
    "language_analysis": {"urgency_count": 3, "fear_count": 2, "findings": ["Urgency detected"]},
    "header_analysis": {"findings": ["Suspicious sender domain: no-reply@secure-verify2738.xyz"]},
    "suspicious_urls": [{"url": "https://secure-verify2738.xyz/login", "flags": ["secure-"]}],
    "suspicious_url_count": 1,
    "url_count": 2,
    "has_attachments": True,
    "urls_found": ["https://secure-verify2738.xyz/login"],
    "perplexity_result": {"ai_probability": 80},
}


def test_threat_explainer():
    from src.threat_explainer import build_explanation, build_beginner_explanation, build_educational_content
    explanation = build_explanation(SAMPLE_RESULTS)
    assert "explanation" in explanation
    assert "triggers" in explanation
    assert "techniques" in explanation
    assert "confidence" in explanation
    assert explanation["confidence"] == "high"
    beginner = build_beginner_explanation(SAMPLE_RESULTS)
    assert len(beginner) > 20
    edu = build_educational_content(SAMPLE_RESULTS)
    assert len(edu) > 0
    print("OK test_threat_explainer")


def test_recommendations():
    from src.recommendations import get_recommendations, render_recommendations_text
    recs = get_recommendations(SAMPLE_RESULTS)
    assert len(recs) > 0
    text = render_recommendations_text(recs)
    assert len(text) > 0
    print(f"OK test_recommendations ({len(recs)} items)")


def test_clicked_link_handler():
    from src.clicked_link_handler import assess_post_click_risk
    assess = assess_post_click_risk(SAMPLE_RESULTS, "credentials_given", work_account=True)
    assert assess["risk"] == "Critical"
    assert len(assess["next_steps"]) > 0
    assess2 = assess_post_click_risk(SAMPLE_RESULTS, "no_interaction")
    assert assess2["risk"] == "Low"
    print("OK test_clicked_link_handler")


def test_red_flags():
    from src.red_flags import detect_red_flags, get_red_flag_summary
    flags = detect_red_flags(SAMPLE_RESULTS)
    assert len(flags) > 0
    summary = get_red_flag_summary(flags)
    assert summary["total"] > 0
    print(f"OK test_red_flags ({summary['total']} flags)")


def test_bec_detector():
    from src.bec_detector import detect_bec
    bec_text = "URGENT: Please wire the payment of $50,000 to our new vendor. The CEO requests you handle this immediately and keep it confidential."
    bec = detect_bec(bec_text, SAMPLE_RESULTS)
    assert bec["bec_detected"]
    assert "total_weight" in bec
    print(f"OK test_bec_detector (type={bec['bec_type']})")


def test_tactic_classifier():
    from src.tactic_classifier import classify_tactics, get_primary_tactic
    tactics = classify_tactics("Verify your password at https://secure-login.xyz", SAMPLE_RESULTS)
    assert len(tactics) > 0
    primary = get_primary_tactic(tactics)
    assert primary is not None
    print(f"OK test_tactic_classifier (primary={primary['label']})")


def test_beginner_mode():
    from src.beginner_mode import simplify_verdict, translate_technical_term
    simple = simplify_verdict(SAMPLE_RESULTS)
    assert len(simple) > 0
    term = translate_technical_term("phishing")
    assert term["simple"] == "Email Scam"
    term2 = translate_technical_term("unknown_term")
    assert term2 is not None
    print("OK test_beginner_mode")


def test_educational_content():
    from src.educational_content import get_educational_content
    from src.tactic_classifier import classify_tactics
    tactics = classify_tactics("test email", SAMPLE_RESULTS)
    edu = get_educational_content(SAMPLE_RESULTS, tactics)
    assert len(edu) > 0
    print(f"OK test_educational_content ({len(edu)} modules)")


def test_compare_emails():
    from src.compare_emails import compare_email_analyses, get_verdict_text
    results_b = dict(SAMPLE_RESULTS)
    results_b["risk_score"] = 30
    results_b["severity"] = "LOW"
    results_b["severity_color"] = "#22c55e"
    results_b["total_keyword_hits"] = 1
    results_b["suspicious_url_count"] = 0
    results_b["has_attachments"] = False
    comp = compare_email_analyses(SAMPLE_RESULTS, results_b)
    assert comp["differences"]["more_suspicious"] == "A"
    vt = get_verdict_text(comp)
    assert "Email A" in vt
    print("OK test_compare_emails")


def test_screenshot_analyzer():
    from src.screenshot_analyzer import analyze_screenshot_image
    # Test with invalid image bytes — should return error, not crash
    result = analyze_screenshot_image(b"not a real image")
    assert result is not None
    assert "success" in result
    # Test with empty bytes
    result = analyze_screenshot_image(b"")
    assert result is not None
    print(f"OK test_screenshot_analyzer (handles invalid input: success={result.get('success')})")


def test_url_intelligence():
    from src.url_intelligence import analyze_url
    # Test malicious URL
    r1 = analyze_url("https://secure-verify-paypal.tk/login")
    assert r1["verdict"] == "Malicious"
    assert r1["risk_score"] >= 60
    # Test safe URL
    r2 = analyze_url("https://www.google.com")
    assert r2["verdict"] == "Safe"
    # Test suspicious URL
    r3 = analyze_url("http://bit.ly/test123")
    assert r3["risk_score"] > 0
    # Test URL without scheme
    r4 = analyze_url("example.com")
    assert r4["parsed"]["has_https"] is True
    print("OK test_url_intelligence")


def test_security_action_center():
    from src.security_action_center import get_security_actions, get_action_summary, get_incident_plan
    # Test with critical risk
    r = get_security_actions({"risk_score": 85, "severity": "CRITICAL"})
    assert len(r) > 0
    summary = get_action_summary(r)
    assert "critical" in summary.lower()
    # Test with low risk
    r2 = get_security_actions({"risk_score": 5, "severity": "LOW"})
    summary2 = get_action_summary(r2)
    assert len(summary2) > 0
    # Test incident plan
    plan = get_incident_plan({"risk_score": 85, "severity": "CRITICAL"})
    assert len(plan) > 50
    # Test with context (credentials entered)
    r3 = get_security_actions({"risk_score": 85, "severity": "CRITICAL"},
                               context={"credentials_entered": True})
    has_change_pw = any("password" in a.get("title", "").lower() for a in r3)
    assert has_change_pw
    print("OK test_security_action_center")


if __name__ == "__main__":
    test_threat_explainer()
    test_recommendations()
    test_clicked_link_handler()
    test_red_flags()
    test_bec_detector()
    test_tactic_classifier()
    test_beginner_mode()
    test_educational_content()
    test_compare_emails()
    test_screenshot_analyzer()
    test_url_intelligence()
    test_security_action_center()
    print("\nALL NEW FEATURE TESTS PASSED")
