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
    print("\nALL NEW FEATURE TESTS PASSED")
