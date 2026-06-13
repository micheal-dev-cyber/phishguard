"""Phishing Tactic Classifier — attack type taxonomy engine.

Classifies a phishing email into one or more attack categories
based on linguistic patterns, URL analysis, header analysis,
and behavioral indicators.
"""

from __future__ import annotations

import re
from typing import Any


TACTIC_DEFINITIONS = {
    "credential_harvesting": {
        "label": "Credential Harvesting",
        "icon": "🔑",
        "description": "Attempts to steal usernames, passwords, or personal information via fake login pages or forms.",
        "indicators": [
            "Requests for password or login credentials",
            "Links to fake login pages",
            "'Verify your account' messaging",
            "Password reset notifications",
        ],
        "color": "#ef4444",
    },
    "bec": {
        "label": "Business Email Compromise",
        "icon": "💰",
        "description": "Targeted financial fraud against businesses — wire transfers, fake invoices, vendor payment redirection.",
        "indicators": [
            "CEO or executive impersonation",
            "Urgent wire transfer requests",
            "Fake invoice attachments",
            "Payment account change requests",
        ],
        "color": "#f97316",
    },
    "fake_login_page": {
        "label": "Fake Login Page",
        "icon": "🌐",
        "description": "Links to counterfeit login pages that capture credentials when entered.",
        "indicators": [
            "Links containing 'login', 'signin', 'account' in suspicious domains",
            "'Secure' or 'verify' pages hosted on lookalike domains",
            "Brand impersonation with login-themed URLs",
        ],
        "color": "#ef4444",
    },
    "mfa_bypass": {
        "label": "MFA Bypass / AitM Attack",
        "icon": "🕵️",
        "description": "Sophisticated proxy-based attacks that intercept passwords AND session cookies to bypass MFA.",
        "indicators": [
            "Real-time credential relaying infrastructure",
            "Reverse proxy phishing kit signatures",
            "Session cookie theft via adversary-in-the-middle proxy",
        ],
        "color": "#dc2626",
    },
    "tech_support": {
        "label": "Tech Support Scam",
        "icon": "🖥️",
        "description": "Fake technical support warnings designed to trick users into calling a scam hotline or installing remote access software.",
        "indicators": [
            "Fake virus or infection warnings",
            "Claims of compromised accounts or devices",
            "Requests to call a phone number for 'support'",
            "Remote access software prompts",
        ],
        "color": "#f59e0b",
    },
    "invoice_scam": {
        "label": "Invoice / Payment Scam",
        "icon": "📄",
        "description": "Fake invoices, overdue notices, or billing statements designed to trick payment processors.",
        "indicators": [
            "Invoice attachments from unknown senders",
            "Urgent payment due notices",
            "Fake subscription renewals",
            "Overdue balance threats",
        ],
        "color": "#f97316",
    },
    "gift_card": {
        "label": "Gift Card Scam",
        "icon": "🎁",
        "description": "Requests for gift card purchases — almost exclusively used by scammers due to untraceability.",
        "indicators": [
            "Gift card purchase requests",
            "Claims a gift card is needed for payment or verification",
            "Instructions to scratch off and share the PIN",
        ],
        "color": "#eab308",
    },
    "malware_delivery": {
        "label": "Malware Delivery",
        "icon": "💀",
        "description": "Emails containing malicious attachments or download links that install malware on the victim's device.",
        "indicators": [
            "Suspicious attachments (.docm, .xlsm, .exe, .js, .vbs)",
            "Macro-enabled document prompts",
            "Double-extension files (invoice.pdf.exe)",
            "Links to file download pages",
        ],
        "color": "#dc2626",
    },
    "brand_impersonation": {
        "label": "Brand Impersonation",
        "icon": "🏷️",
        "description": "Impersonation of well-known brands (Microsoft, Amazon, PayPal, banks) to build false trust.",
        "indicators": [
            "Lookalike domains (rnicrosoft.com, paypa1.com)",
            "Brand logo misuse in email body",
            "Official-sounding sender names that mismatch email addresses",
        ],
        "color": "#a855f7",
    },
    "spear_phishing": {
        "label": "Spear Phishing",
        "icon": "🎯",
        "description": "Highly targeted attack against a specific individual using personalized context and research.",
        "indicators": [
            "Personalized greeting with real name and title",
            "References to real projects, colleagues, or recent events",
            "Contextually relevant subject lines",
            "Impersonation of a known contact or service",
        ],
        "color": "#ef4444",
    },
    "whaling": {
        "label": "Whaling (Executive Targeting)",
        "icon": "🐋",
        "description": "Highly targeted phishing aimed at senior executives, often involving legal or financial pretexts.",
        "indicators": [
            "Targeting C-level executives specifically",
            "Legal or compliance-related pretexts",
            "Requests for sensitive corporate data",
            "Executive-specific urgency language",
        ],
        "color": "#dc2626",
    },
    "vishing_setup": {
        "label": "Vishing / Phone Call Setup",
        "icon": "📞",
        "description": "Email designed to initiate a phone call where voice phishing (vishing) occurs.",
        "indicators": [
            "Phone numbers prominently featured",
            "Instructions to call a number for 'verification' or 'support'",
            "Fake caller ID / support center claims",
        ],
        "color": "#f59e0b",
    },
    "sextortion": {
        "label": "Sextortion / Blackmail",
        "icon": "🔞",
        "description": "Emails claiming to have compromising information or recordings and demanding payment.",
        "indicators": [
            "Claims of compromised webcam or recordings",
            "Demands for cryptocurrency payment",
            "Includes a password you've used before (from data breaches)",
            "Threatens to expose information to contacts",
        ],
        "color": "#ef4444",
    },
    "lottery_fraud": {
        "label": "Lottery / Inheritance Fraud",
        "icon": "🎰",
        "description": "Claims you've won a prize or inherited money and need to pay fees to receive it.",
        "indicators": [
            "Claims of winning a lottery or competition you didn't enter",
            "Inheritance from unknown relatives",
            "Requests for advance fees to release funds",
        ],
        "color": "#f59e0b",
    },
}


def classify_tactics(email_text: str, results: dict | None = None) -> list[dict]:
    """Classify the email into one or more phishing tactic categories.

    Args:
        email_text: The raw email text
        results: Pre-computed analysis results for enrichment

    Returns:
        List of tactic dicts, sorted by confidence descending, each with:
            id, label, icon, description, confidence (0-100),
            indicators (list), color
    """
    text_lower = email_text.lower()
    results = results or {}
    kw_matches = results.get("keyword_matches", {}) or {}
    suspicious_urls = results.get("suspicious_urls", []) or []
    header_analysis = results.get("header_analysis", {}) or {}
    lang_analysis = results.get("language_analysis", {}) or {}

    tactics = []

    # Credential Harvesting
    if kw_matches.get("credentials") or kw_matches.get("password"):
        tactics.append({
            "id": "credential_harvesting",
            **TACTIC_DEFINITIONS["credential_harvesting"],
            "confidence": _compute_confidence(text_lower, ["verify", "account", "password", "login", "sign in", "credential"]),
        })

    # BEC
    bec_keywords = ["wire", "transfer", "invoice", "payment", "ceo", "vendor", "supplier"]
    if any(kw in text_lower for kw in bec_keywords):
        tactics.append({
            "id": "bec",
            **TACTIC_DEFINITIONS["bec"],
            "confidence": _compute_confidence(text_lower, bec_keywords),
        })

    # Fake Login Page
    login_url_patterns = ["login", "signin", "account", "verify", "secure"]
    if any(lu in text_lower for lu in login_url_patterns) and suspicious_urls:
        tactics.append({
            "id": "fake_login_page",
            **TACTIC_DEFINITIONS["fake_login_page"],
            "confidence": _compute_confidence(text_lower, login_url_patterns + ["link", "click", "https://"]),
        })

    # Tech Support Scam
    tech_keywords = ["virus", "infected", "compromised", "technical support", "call", "microsoft certified"]
    if any(tk in text_lower for tk in tech_keywords):
        tactics.append({
            "id": "tech_support",
            **TACTIC_DEFINITIONS["tech_support"],
            "confidence": _compute_confidence(text_lower, tech_keywords),
        })

    # Invoice Scam
    if kw_matches.get("financial") or any(w in text_lower for w in ["invoice", "overdue", "billing", "subscription"]):
        tactics.append({
            "id": "invoice_scam",
            **TACTIC_DEFINITIONS["invoice_scam"],
            "confidence": _compute_confidence(text_lower, ["invoice", "overdue", "payment", "billing", "due"]),
        })

    # Gift Card
    if kw_matches.get("gift_card") or any(w in text_lower for w in ["gift card", "itunes", "google play"]):
        tactics.append({
            "id": "gift_card",
            **TACTIC_DEFINITIONS["gift_card"],
            "confidence": _compute_confidence(text_lower, ["gift card", "pin", "scratch", "redeem"]),
        })

    # Malware Delivery
    has_macro = any(kw_matches.get(cat) for cat in ["attachments", "macro"]) if isinstance(kw_matches, dict) else False
    if results.get("has_attachments") or has_macro:
        tactics.append({
            "id": "malware_delivery",
            **TACTIC_DEFINITIONS["malware_delivery"],
            "confidence": _compute_confidence(text_lower, ["attachment", "download", "open", "file", "document"]),
        })

    # Brand Impersonation
    brand_result = results.get("brand_check", {}) or {}
    if brand_result.get("impersonation_detected"):
        tactics.append({
            "id": "brand_impersonation",
            **TACTIC_DEFINITIONS["brand_impersonation"],
            "confidence": brand_result.get("total_risk", 60),
        })

    # Spear Phishing
    if kw_matches.get("personalized") or (header_analysis.get("findings") and any("personal" in f.lower() for f in header_analysis.get("findings", []))):
        tactics.append({
            "id": "spear_phishing",
            **TACTIC_DEFINITIONS["spear_phishing"],
            "confidence": _compute_confidence(text_lower, ["dear", "your account", "personal", "specifically"]),
        })

    tactics.sort(key=lambda t: t.get("confidence", 0), reverse=True)

    return tactics


def _compute_confidence(text: str, keywords: list[str]) -> int:
    """Compute a 0-100 confidence score based on keyword presence."""
    text_lower = text.lower()
    matches = sum(1 for kw in keywords if kw in text_lower)
    ratio = matches / len(keywords) if keywords else 0
    return min(int(ratio * 100) + 10, 100)


def get_primary_tactic(tactics: list[dict]) -> dict | None:
    """Get the highest-confidence tactic."""
    if not tactics:
        return None
    return max(tactics, key=lambda t: t.get("confidence", 0))
