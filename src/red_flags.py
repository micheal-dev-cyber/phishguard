"""Email Red Flags Section — visual phishing indicator dashboard.

Displays a clear, visual breakdown of all phishing red flags detected
in the email, with explanations for each flag.
"""

from __future__ import annotations


RED_FLAG_DEFINITIONS = {
    "domain_mismatch": {
        "label": "Domain Mismatch",
        "icon": "🌐",
        "description": "The sender's email domain doesn't match the organization they claim to be from.",
        "severity": "high",
        "detail": "Check the actual email address carefully. Attackers use domains that look similar (e.g., '@rnicrosoft.com' instead of '@microsoft.com').",
    },
    "urgency_language": {
        "label": "Urgency Language",
        "icon": "⏰",
        "description": "The email pressures you to act quickly without thinking.",
        "severity": "medium",
        "detail": "Phrases like 'immediately', 'within 24 hours', 'last warning', and 'act now' are designed to create panic and bypass your critical thinking.",
    },
    "credential_harvesting": {
        "label": "Credential Harvesting Attempt",
        "icon": "🔑",
        "description": "The email asks for passwords, login details, or personal information.",
        "severity": "high",
        "detail": "Legitimate organizations never ask for passwords by email. Links to 'verify your account' typically lead to fake login pages.",
    },
    "payment_request": {
        "label": "Payment Request",
        "icon": "💳",
        "description": "The email asks you to send money, make a payment, or provide financial details.",
        "severity": "high",
        "detail": "Unsolicited payment requests — especially urgent ones — are a hallmark of fraud. Verify through official channels before sending money.",
    },
    "gift_card_scam": {
        "label": "Gift Card Scam",
        "icon": "🎁",
        "description": "The email requests payment via gift cards.",
        "severity": "critical",
        "detail": "Gift card requests are ALWAYS scams. No legitimate company accepts gift cards as payment. This is a near-definitive sign of fraud.",
    },
    "ceo_impersonation": {
        "label": "CEO / Executive Impersonation",
        "icon": "👔",
        "description": "The email pretends to be from a senior executive to authorize financial actions.",
        "severity": "critical",
        "detail": "Attackers spoof executive email addresses to trick finance teams into making wire transfers. Always verify high-value requests in person.",
    },
    "reply_to_mismatch": {
        "label": "Reply-To Mismatch",
        "icon": "↩️",
        "description": "The reply-to address is different from the sender's address.",
        "severity": "high",
        "detail": "If you reply, your message goes to the attacker's address, not the claimed sender's. This is a common phishing technique.",
    },
    "suspicious_attachment": {
        "label": "Suspicious Attachment",
        "icon": "📎",
        "description": "The email contains or references files that could deliver malware.",
        "severity": "high",
        "detail": "Be especially careful with .docm, .xlsm, .exe, .zip, .js, and .scr files. These are commonly used to deliver ransomware and stealers.",
    },
    "fear_tactics": {
        "label": "Fear / Intimidation",
        "icon": "😨",
        "description": "The email uses threats to make you comply.",
        "severity": "medium",
        "detail": "Threats of legal action, account suspension, or financial penalties are designed to scare you into bypassing normal security precautions.",
    },
    "display_name_spoof": {
        "label": "Display Name Spoofing",
        "icon": "👤",
        "description": "The display name is faked to impersonate a trusted person or brand.",
        "severity": "high",
        "detail": "Email clients often show only the display name. Attackers set names like 'PayPal Support' while using unrelated email addresses.",
    },
    "free_email_brand": {
        "label": "Free Email Impersonating Brand",
        "icon": "📧",
        "description": "A free email service (Gmail, Yahoo, Hotmail) is being used to impersonate a major brand.",
        "severity": "high",
        "detail": "Legitimate companies use their own domain for email. A 'PayPal' email from '@gmail.com' is always phishing.",
    },
    "ai_generated": {
        "label": "AI-Generated Content",
        "icon": "🤖",
        "description": "The email text shows patterns typical of AI-written phishing messages.",
        "severity": "medium",
        "detail": "Attackers now use AI to craft convincing emails with perfect grammar. Look for overly structured formatting and unnatural transitions.",
    },
    "homograph_attack": {
        "label": "Homograph / Script Spoofing",
        "icon": "🔤",
        "description": "Lookalike characters from different alphabets are used to disguise URLs or names.",
        "severity": "high",
        "detail": "Cyrillic 'а' looks identical to Latin 'a' but leads to a different website. These are nearly invisible to the untrained eye.",
    },
    "excessive_caps": {
        "label": "Excessive Capitalization",
        "icon": "🔠",
        "description": "Unusual amounts of ALL CAPS text, typical of scam emails.",
        "severity": "low",
        "detail": "While not dangerous by itself, excessive capitalization combined with other flags increases the overall risk.",
    },
    "poor_grammar": {
        "label": "Suspicious Grammar / Phrasing",
        "icon": "📝",
        "description": "Unusual grammar patterns, especially 'kindly' requests and awkward phrasing.",
        "severity": "low",
        "detail": "Foreign-origin phishing often uses overly formal or slightly incorrect English. However, AI-generated phishing now has near-perfect grammar.",
    },
    "spf_fail": {
        "label": "SPF Authentication Failed",
        "icon": "🔓",
        "description": "The email failed Sender Policy Framework (SPF) authentication.",
        "severity": "high",
        "detail": "SPF failure means the email was sent from a server not authorized by the domain owner — a strong indicator of spoofing.",
    },
    "dkim_fail": {
        "label": "DKIM Signature Invalid",
        "icon": "✍️",
        "description": "The email's DKIM signature is missing or invalid.",
        "severity": "high",
        "detail": "DKIM failure means the email content may have been tampered with or the sender is impersonating a legitimate domain.",
    },
    "dmarc_fail": {
        "label": "DMARC Policy Failed",
        "icon": "🛡️",
        "description": "The email failed DMARC authentication, which combines SPF and DKIM checks.",
        "severity": "high",
        "detail": "DMARC failure is a strong indicator of email spoofing. Legitimate emails from properly configured domains pass DMARC.",
    },
}


def detect_red_flags(results: dict, header_auth: dict | None = None,
                     xai_result: dict | None = None,
                     perplexity_result: dict | None = None) -> list[dict]:
    """Detect all applicable red flags from analysis results.

    Returns list of dicts with keys: id, label, icon, description,
    severity, detail, present (bool).
    """
    flags = []
    kw_matches = results.get("keyword_matches", {}) or {}
    lang_analysis = results.get("language_analysis", {}) or {}
    header_analysis = results.get("header_analysis", {}) or {}
    suspicious_urls = results.get("suspicious_urls", []) or []

    # Check each red flag
    if any("spoof" in f.lower() or "domain" in f.lower() for f in header_analysis.get("findings", [])):
        flags.append({**RED_FLAG_DEFINITIONS["domain_mismatch"], "present": True})

    if lang_analysis.get("urgency_count", 0) > 0:
        flags.append({**RED_FLAG_DEFINITIONS["urgency_language"], "present": True})

    if kw_matches.get("credentials") or kw_matches.get("password"):
        flags.append({**RED_FLAG_DEFINITIONS["credential_harvesting"], "present": True})

    if kw_matches.get("financial") or kw_matches.get("payment"):
        flags.append({**RED_FLAG_DEFINITIONS["payment_request"], "present": True})

    if kw_matches.get("gift_card"):
        flags.append({**RED_FLAG_DEFINITIONS["gift_card_scam"], "present": True})

    if kw_matches.get("ceo") or any("ceo" in f.lower() or "executive" in f.lower() for f in header_analysis.get("findings", [])):
        flags.append({**RED_FLAG_DEFINITIONS["ceo_impersonation"], "present": True})

    if any("reply" in f.lower() for f in header_analysis.get("findings", [])):
        flags.append({**RED_FLAG_DEFINITIONS["reply_to_mismatch"], "present": True})

    if results.get("has_attachments"):
        flags.append({**RED_FLAG_DEFINITIONS["suspicious_attachment"], "present": True})

    if lang_analysis.get("fear_count", 0) > 0:
        flags.append({**RED_FLAG_DEFINITIONS["fear_tactics"], "present": True})

    if any("display" in f.lower() or "name" in f.lower() for f in header_analysis.get("findings", [])):
        flags.append({**RED_FLAG_DEFINITIONS["display_name_spoof"], "present": True})

    emails_found = header_analysis.get("emails_found", [])
    if any("@gmail.com" in e or "@yahoo.com" in e or "@hotmail.com" in e for e in emails_found):
        if any(b in (kw_matches or {}) for b in ["urgent", "security", "financial"]):
            flags.append({**RED_FLAG_DEFINITIONS["free_email_brand"], "present": True})

    if perplexity_result and perplexity_result.get("ai_probability", 0) >= 60:
        flags.append({**RED_FLAG_DEFINITIONS["ai_generated"], "present": True})

    url_analysis = results.get("url_analysis", {}) or {}
    if url_analysis.get("homograph_detected"):
        flags.append({**RED_FLAG_DEFINITIONS["homograph_attack"], "present": True})

    if lang_analysis.get("caps_ratio", 0) > 0.15 or lang_analysis.get("exclamation_count", 0) > 3:
        flags.append({**RED_FLAG_DEFINITIONS["excessive_caps"], "present": True})

    if lang_analysis.get("grammar_issues", 0) > 0:
        flags.append({**RED_FLAG_DEFINITIONS["poor_grammar"], "present": True})

    if header_auth:
        if header_auth.get("spf_status") == "fail":
            flags.append({**RED_FLAG_DEFINITIONS["spf_fail"], "present": True})
        if header_auth.get("dkim_status") == "fail":
            flags.append({**RED_FLAG_DEFINITIONS["dkim_fail"], "present": True})
        if header_auth.get("dmarc_status") == "fail":
            flags.append({**RED_FLAG_DEFINITIONS["dmarc_fail"], "present": True})

    return flags


def get_red_flag_summary(flags: list[dict]) -> dict:
    """Get a summary of red flags for dashboard display."""
    critical = sum(1 for f in flags if f.get("severity") == "critical" and f.get("present"))
    high = sum(1 for f in flags if f.get("severity") == "high" and f.get("present"))
    medium = sum(1 for f in flags if f.get("severity") == "medium" and f.get("present"))
    low = sum(1 for f in flags if f.get("severity") == "low" and f.get("present"))
    total = critical + high + medium + low

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "display": f"{total} red flag{'s' if total != 1 else ''} found"
                   + (f" ({critical} critical)" if critical else ""),
    }
