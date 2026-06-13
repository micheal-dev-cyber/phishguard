"""Compare Emails — side-by-side email analysis comparison.

Allows users to compare two emails and understand which is more
suspicious and why, with a detailed breakdown of differences.
"""

from __future__ import annotations

from typing import Any

import streamlit as st


def compare_email_analyses(result_a: dict, result_b: dict) -> dict:
    """Compare two email analysis results side by side.

    Args:
        result_a: Analysis results for email A
        result_b: Analysis results for email B

    Returns:
        Comparison dict with scores, differences, and verdict
    """
    score_a = result_a.get("risk_score", 0)
    score_b = result_b.get("risk_score", 0)

    severities = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "SAFE": 1}
    sev_a = severities.get(result_a.get("severity", "LOW"), 0)
    sev_b = severities.get(result_b.get("severity", "LOW"), 0)

    kw_a = result_a.get("total_keyword_hits", 0)
    kw_b = result_b.get("total_keyword_hits", 0)

    urls_a = result_a.get("suspicious_url_count", 0)
    urls_b = result_b.get("suspicious_url_count", 0)

    att_a = result_a.get("has_attachments", False)
    att_b = result_b.get("has_attachments", False)

    # Determine more suspicious
    if score_a > score_b:
        more_suspicious = "A"
        diff_score = score_a - score_b
    elif score_b > score_a:
        more_suspicious = "B"
        diff_score = score_b - score_a
    else:
        if sev_a > sev_b:
            more_suspicious = "A"
            diff_score = 0
        elif sev_b > sev_a:
            more_suspicious = "B"
            diff_score = 0
        else:
            more_suspicious = "similar"
            diff_score = 0

    return {
        "email_a": {
            "score": score_a,
            "severity": result_a.get("severity", "LOW"),
            "severity_color": result_a.get("severity_color", "#22c55e"),
            "keyword_hits": kw_a,
            "suspicious_urls": urls_a,
            "has_attachments": att_a,
            "url_count": result_a.get("url_count", 0),
            "keyword_categories": list((result_a.get("keyword_matches", {}) or {}).keys()),
        },
        "email_b": {
            "score": score_b,
            "severity": result_b.get("severity", "LOW"),
            "severity_color": result_b.get("severity_color", "#22c55e"),
            "keyword_hits": kw_b,
            "suspicious_urls": urls_b,
            "has_attachments": att_b,
            "url_count": result_b.get("url_count", 0),
            "keyword_categories": list((result_b.get("keyword_matches", {}) or {}).keys()),
        },
        "differences": {
            "score_diff": diff_score,
            "score_a_higher": score_a > score_b,
            "score_b_higher": score_b > score_a,
            "more_suspicious": more_suspicious,
            "reasons": _build_comparison_reasons(result_a, result_b),
        },
    }


def _build_comparison_reasons(result_a: dict, result_b: dict) -> list[str]:
    """Build human-readable reasons why one email is more suspicious."""
    reasons = []
    score_a = result_a.get("risk_score", 0)
    score_b = result_b.get("risk_score", 0)

    kw_a = result_a.get("total_keyword_hits", 0)
    kw_b = result_b.get("total_keyword_hits", 0)
    if kw_a > kw_b:
        reasons.append(f"Email A has more phishing keyword matches ({kw_a} vs {kw_b})")
    elif kw_b > kw_a:
        reasons.append(f"Email B has more phishing keyword matches ({kw_b} vs {kw_a})")

    urls_a = result_a.get("suspicious_url_count", 0)
    urls_b = result_b.get("suspicious_url_count", 0)
    if urls_a > urls_b:
        reasons.append(f"Email A has more suspicious URLs ({urls_a} vs {urls_b})")
    elif urls_b > urls_a:
        reasons.append(f"Email B has more suspicious URLs ({urls_b} vs {urls_a})")

    att_a = result_a.get("has_attachments", False)
    att_b = result_b.get("has_attachments", False)
    if att_a and not att_b:
        reasons.append("Email A has attachments (potential malware vector)")
    elif att_b and not att_a:
        reasons.append("Email B has attachments (potential malware vector)")

    sev_a = result_a.get("severity", "LOW")
    sev_b = result_b.get("severity", "LOW")
    sev_order = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if sev_order.index(sev_a) > sev_order.index(sev_b):
        reasons.append(f"Email A severity is higher ({sev_a} vs {sev_b})")
    elif sev_order.index(sev_b) > sev_order.index(sev_a):
        reasons.append(f"Email B severity is higher ({sev_b} vs {sev_a})")

    lang_a = result_a.get("language_analysis", {}) or {}
    lang_b = result_b.get("language_analysis", {}) or {}
    urgency_a = lang_a.get("urgency_count", 0)
    urgency_b = lang_b.get("urgency_count", 0)
    if urgency_a > urgency_b:
        reasons.append(f"Email A uses more urgency language ({urgency_a} vs {urgency_b} patterns)")
    elif urgency_b > urgency_a:
        reasons.append(f"Email B uses more urgency language ({urgency_b} vs {urgency_a} patterns)")

    if not reasons:
        reasons.append("Both emails show similar risk characteristics")

    return reasons


def get_verdict_text(comparison: dict) -> str:
    """Get a human-readable verdict from comparison results."""
    more = comparison["differences"]["more_suspicious"]
    diff = comparison["differences"]["score_diff"]

    if more == "similar":
        return "Both emails show similar levels of risk."
    elif more == "A":
        return f"**Email A is more suspicious** — {diff} point{'s' if diff != 1 else ''} higher risk than Email B."
    else:
        return f"**Email B is more suspicious** — {diff} point{'s' if diff != 1 else ''} higher risk than Email A."
