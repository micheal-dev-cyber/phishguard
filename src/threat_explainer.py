"""Threat Explanation Engine — explains WHY something is phishing in plain English.

Translates raw detection signals into human-readable explanations
categorized by attack technique, severity, and user confidence level.
"""

from __future__ import annotations

import re
from typing import Any


EXPLANATION_TEMPLATES = {
    "urgency": {
        "label": "Urgency & Time Pressure",
        "description": "The email tries to rush you into acting without thinking by creating a false sense of urgency.",
        "examples": [
            "Phishers use deadlines and threats of account suspension to bypass your rational thinking. "
            "Legitimate companies rarely demand immediate action via email.",
        ],
        "icon": "⏰",
    },
    "fear": {
        "label": "Fear & Intimidation",
        "description": "The email uses scare tactics to make you panic and comply without verification.",
        "examples": [
            "Threats of legal action, account closure, or financial loss are designed to trigger fear responses. "
            "Real organizations communicate important issues through official channels, not email ultimatums.",
        ],
        "icon": "😨",
    },
    "credentials": {
        "label": "Credential Harvesting Attempt",
        "description": "The email is trying to trick you into revealing your username and password.",
        "examples": [
            "Lookalike login pages and password reset requests are the most common credential theft techniques. "
            "Always navigate to websites manually rather than clicking email links.",
        ],
        "icon": "🔑",
    },
    "sender_spoof": {
        "label": "Sender Impersonation",
        "description": "The sender's email address or display name is being faked to appear as someone you trust.",
        "examples": [
            "Attackers forge 'From' addresses to impersonate colleagues, executives, or trusted brands. "
            "Check the actual email address, not just the display name.",
        ],
        "icon": "👤",
    },
    "reply_to_mismatch": {
        "label": "Reply-To Address Mismatch",
        "description": "The reply-to address differs from the sender — replies go to the attacker instead.",
        "examples": [
            "A common trick: the 'From' looks legitimate but replies route to the attacker's inbox. "
            "Always verify reply-to fields in email headers.",
        ],
        "icon": "↩️",
    },
    "domain_spoof": {
        "label": "Domain Spoofing / Lookalike Domain",
        "description": "The domain name is designed to visually resemble a trusted brand's domain.",
        "examples": [
            "Attackers register domains like 'paypa1.com' or 'rnicrosoft.com' that look nearly identical at a glance. "
            "Look for subtle typos, extra characters, or wrong TLDs.",
        ],
        "icon": "🌐",
    },
    "suspicious_attachment": {
        "label": "Suspicious Attachment",
        "description": "The email contains or references files commonly used to deliver malware.",
        "examples": [
            "Attackers attach malicious documents (.docm, .xlsm) that install malware when macros are enabled. "
            "Never enable macros unless you are 100% certain of the file's origin.",
        ],
        "icon": "📎",
    },
    "suspicious_url": {
        "label": "Malicious Link Detected",
        "description": "The email contains links to known or suspected malicious websites.",
        "examples": [
            "Links may lead to fake login pages, drive-by download sites, or credential harvesting portals. "
            "Hover over links (without clicking) to inspect the actual destination URL.",
        ],
        "icon": "🔗",
    },
    "bec_fraud": {
        "label": "Business Email Compromise (BEC) — Financial Fraud",
        "description": "The email matches patterns of targeted financial fraud against businesses.",
        "examples": [
            "Attackers impersonate CEOs, vendors, or partners to request wire transfers, fake invoices, or gift cards. "
            "Always verify payment requests through a separate communication channel.",
        ],
        "icon": "💰",
    },
    "payment_request": {
        "label": "Unsolicited Payment Request",
        "description": "The email asks you to make a payment, transfer money, or share financial information.",
        "examples": [
            "Unsolicited payment requests are a hallmark of advance-fee fraud and BEC scams. "
            "Legitimate organizations do not request urgent payments via email.",
        ],
        "icon": "💳",
    },
    "gift_card": {
        "label": "Gift Card Scam",
        "description": "The email requests payment via gift cards — a near-certain sign of fraud.",
        "examples": [
            "Gift card requests are almost always scams because they are untraceable and irreversible. "
            "No legitimate organization accepts gift cards as payment.",
        ],
        "icon": "🎁",
    },
    "ceo_fraud": {
        "label": "CEO / Executive Impersonation",
        "description": "The email impersonates a senior executive to authorize fraudulent transactions.",
        "examples": [
            "Attackers spoof executive email accounts to instruct finance teams to make urgent payments. "
            "Verify high-value requests in person or via a known phone number.",
        ],
        "icon": "👔",
    },
    "aitm": {
        "label": "Adversary-in-the-Middle (AitM) Attack",
        "description": "The email is part of a sophisticated proxy-based phishing attack that can bypass MFA.",
        "examples": [
            "AitM attacks use reverse proxies to intercept credentials and session cookies in real-time. "
            "Even entering your password triggers an instant relay to the real site.",
        ],
        "icon": "🕵️",
    },
    "ai_generated": {
        "label": "AI-Generated Phishing Content",
        "description": "The email text shows patterns consistent with AI-written phishing messages.",
        "examples": [
            "Attackers now use LLMs to craft grammatically perfect, culturally adapted phishing emails. "
            "Look for overly structured formatting, unnatural transitions, and generic politeness.",
        ],
        "icon": "🤖",
    },
    "homograph": {
        "label": "Homograph / Script Spoofing",
        "description": "The email uses lookalike characters from different alphabets to disguise URLs or names.",
        "examples": [
            "Attackers substitute Latin letters with Cyrillic or Greek lookalikes (e.g., 'а' instead of 'a'). "
            "These visually identical characters redirect to attacker-controlled domains.",
        ],
        "icon": "🔤",
    },
}

RISK_VERDICTS = {
    (0, 24): {
        "label": "Safe",
        "icon": "🟢",
        "summary": "This email shows no significant signs of phishing. Maintain normal vigilance.",
        "detail": (
            "Our analysis found minimal phishing indicators. The email appears to be legitimate "
            "based on language patterns, sender reputation, and structural analysis. "
            "However, always remain cautious with unexpected emails."
        ),
    },
    (25, 49): {
        "label": "Suspicious",
        "icon": "🟡",
        "summary": "Some suspicious elements were found. Review carefully before acting.",
        "detail": (
            "This email contains elements that warrant caution. While not definitively malicious, "
            "certain patterns — such as urgency language or unusual sender details — suggest "
            "it could be an attempted phishing attack."
        ),
    },
    (50, 74): {
        "label": "High Risk",
        "icon": "🟠",
        "summary": "Multiple phishing indicators detected. Treat with extreme caution.",
        "detail": (
            "This email exhibits multiple characteristics commonly associated with phishing attacks. "
            "The combination of detected signals strongly suggests malicious intent. "
            "Do not interact with links, attachments, or sender requests."
        ),
    },
    (75, 100): {
        "label": "Phishing",
        "icon": "🔴",
        "summary": "Confirmed phishing attack. Do not engage — follow the recommended actions immediately.",
        "detail": (
            "This email is almost certainly a phishing attack. Multiple high-confidence signals "
            "align with known attack patterns. Treat this as a confirmed threat and follow "
            "the remediation steps without delay."
        ),
    },
}


def _find_verdict(score: int) -> tuple:
    for (lo, hi), v in RISK_VERDICTS.items():
        if lo <= score <= hi:
            return v["label"], v["icon"], v["summary"], v["detail"]
    return "Unknown", "❓", "Could not determine risk level.", ""


def build_explanation(results: dict, xai_result: dict | None = None) -> dict:
    """Build a human-readable explanation from analysis results.

    Returns:
        explanation (str) — full narrative
        triggers (list) — what specific things were detected
        techniques (list) — which phishing techniques are present
        confidence (str) — low/medium/high
        verdict (dict) — label/icon/summary/detail
    """
    score = results.get("risk_score", 0)
    severity = results.get("severity", "LOW")

    label, icon, summary, detail = _find_verdict(score)

    techniques = []
    triggers = []

    kw_matches = results.get("keyword_matches", {}) or {}
    lang_analysis = results.get("language_analysis", {}) or {}
    header_analysis = results.get("header_analysis", {}) or {}
    suspicious_urls = results.get("suspicious_urls", []) or []

    if lang_analysis.get("urgency_count", 0) > 0:
        techniques.append("urgency")
        triggers.append("⏰ **Urgency language** — words like 'immediately', 'expires', 'deadline' pressure you to act fast")
    if lang_analysis.get("fear_count", 0) > 0:
        techniques.append("fear")
        triggers.append("😨 **Fear tactics** — threats of suspension, closure, or legal action")
    if kw_matches.get("credentials") or kw_matches.get("password"):
        techniques.append("credentials")
        triggers.append("🔑 **Credential request** — the email asks for passwords or login details")
    for finding in header_analysis.get("findings", []):
        if "sender" in finding.lower() and "domain" in finding.lower():
            techniques.append("sender_spoof")
            triggers.append(f"👤 **{finding}**")
        if "reply" in finding.lower():
            techniques.append("reply_to_mismatch")
            triggers.append(f"↩️ **{finding}**")
    if suspicious_urls:
        techniques.append("suspicious_url")
        triggers.append(f"🔗 **{len(suspicious_urls)} suspicious URL(s)** — links point to untrusted destinations")
    if results.get("has_attachments"):
        techniques.append("suspicious_attachment")
        triggers.append("📎 **Suspicious attachment** — the email contains or references file downloads")

    for cat in kw_matches:
        if cat in ("financial", "payment", "invoice"):
            if "payment" not in techniques:
                techniques.append("payment_request")
                triggers.append("💰 **Payment request** — the email discusses financial transactions")
        if cat in ("gift_card", "gift"):
            techniques.append("gift_card")
            triggers.append("🎁 **Gift card reference** — gift cards are a common fraud vector")
        if cat in ("ceo", "executive", "impersonation"):
            techniques.append("ceo_fraud")
            triggers.append("👔 **Executive impersonation** — the email mimics a company leader")

    aitm_result = results.get("aitm_result", {}) or {}
    if aitm_result.get("detected"):
        techniques.append("aitm")
        triggers.append("🕵️ **AitM attack detected** — sophisticated proxy-based phishing that bypasses MFA")

    perplexity = results.get("perplexity_result", {}) or {}
    if perplexity.get("ai_probability", 0) >= 60:
        techniques.append("ai_generated")
        triggers.append("🤖 **AI-generated text** — the message shows patterns typical of LLM-written phishing")

    if not techniques:
        triggers.append("✅ No specific phishing techniques detected")
        techniques.append("none")

    # Confidence
    if score >= 75:
        confidence = "high"
    elif score >= 50:
        confidence = "medium"
    else:
        confidence = "low"

    # Build narrative
    parts = [f"{icon} **{label}** — {summary}"]
    parts.append("")
    parts.append(f"**Risk Score: {score}/100** — {confidence.upper()} confidence")
    parts.append("")

    if triggers:
        parts.append("### What triggered this detection")
        for t in triggers:
            parts.append(f"- {t}")
        parts.append("")

    technique_descriptions = []
    for tech in techniques:
        if tech in EXPLANATION_TEMPLATES:
            tpl = EXPLANATION_TEMPLATES[tech]
            technique_descriptions.append(f"**{tpl['icon']} {tpl['label']}:** {tpl['description']}")

    if technique_descriptions:
        parts.append("### Phishing techniques identified")
        for td in technique_descriptions:
            parts.append(f"- {td}")
        parts.append("")

    parts.append(f"### Security verdict")
    parts.append(detail)

    return {
        "explanation": "\n".join(parts),
        "triggers": triggers,
        "techniques": [EXPLANATION_TEMPLATES.get(t, {}).get("label", t) for t in techniques if t != "none"],
        "technique_slugs": techniques,
        "confidence": confidence,
        "verdict": {"label": label, "icon": icon, "summary": summary, "detail": detail},
    }


def build_beginner_explanation(results: dict) -> str:
    """Ultra-simple explanation for non-technical users."""
    score = results.get("risk_score", 0)
    severity = results.get("severity", "LOW")

    if score >= 75:
        return (
            "**🚨 This email is trying to trick you.**\n\n"
            "It looks real, but it's actually a scam. The person who sent it wants you to "
            "click a link or give them personal information. "
            "**Do not click anything, do not reply, and do not open any files.**\n\n"
            "Just delete it. If you're worried about your accounts, "
            "go to the website yourself (type the address manually) and check there."
        )
    elif score >= 50:
        return (
            "**⚠️ This email has some warning signs.**\n\n"
            "Some parts of it don't look right — like the sender's address or what it's asking you to do. "
            "It might be a scam, but we're not 100% sure.\n\n"
            "**Play it safe:** don't click links or reply. "
            "If it claims to be from a company, visit their website directly (don't use the link in the email)."
        )
    elif score >= 25:
        return (
            "**👀 This email has a few small warning signs.**\n\n"
            "Nothing major, but there are a couple of things worth checking. "
            "Look closely at the sender's email address and think about whether you were expecting this message.\n\n"
            "**When in doubt:** don't click links. Go directly to the website instead."
        )
    else:
        return (
            "**✅ This email looks normal.**\n\n"
            "We didn't find any obvious signs of a scam. But even with normal-looking emails, "
            "it's always smart to: check the sender carefully, don't click unexpected links, "
            "and trust your gut if something feels off."
        )


def build_educational_content(results: dict) -> list[dict]:
    """Generate 'How to spot this attack in the future' guidance."""
    items = []
    score = results.get("risk_score", 0)

    kw_matches = results.get("keyword_matches", {}) or {}
    lang_analysis = results.get("language_analysis", {}) or {}
    suspicious_urls = results.get("suspicious_urls", []) or []
    header_analysis = results.get("header_analysis", {}) or {}

    if lang_analysis.get("urgency_count", 0) > 0:
        items.append({
            "title": "Spotting urgency tricks",
            "icon": "⏰",
            "tip": (
                "Phishers create fake emergencies to make you act without thinking. "
                "**Real companies don't threaten to close your account via email.** "
                "If an email demands immediate action, pause and verify through official channels."
            ),
            "how_to": "Look for: 'immediately', '24 hours', 'final warning', 'account suspended', 'urgent action required'.",
        })
    if lang_analysis.get("fear_count", 0) > 0:
        items.append({
            "title": "Recognising fear tactics",
            "icon": "😨",
            "tip": (
                "Fear is a powerful tool scammers use to override your better judgment. "
                "They threaten legal action, financial loss, or data breaches. "
                "**If an email tries to scare you, it's probably a scam.**"
            ),
            "how_to": "Be suspicious of: threats about legal action, 'unauthorized activity' warnings, and demands to 'verify immediately'.",
        })
    if kw_matches.get("credentials") or kw_matches.get("password"):
        items.append({
            "title": "Protecting your passwords",
            "icon": "🔑",
            "tip": (
                "**No legitimate company will ever ask for your password by email.** "
                "Password reset links should take you to the official website — "
                "check the URL carefully before clicking."
            ),
            "how_to": "Always type the website address yourself instead of clicking email links for logins.",
        })
    if suspicious_urls:
        items.append({
            "title": "Checking links safely",
            "icon": "🔗",
            "tip": (
                "Hover your mouse over a link (without clicking) to see the real destination. "
                "If the displayed text says 'paypal.com' but the link goes to 'paypa1-security.xyz', "
                "it's phishing."
            ),
            "how_to": "On mobile, press and hold a link to preview the URL before opening.",
        })
    if header_analysis.get("findings", []):
        items.append({
            "title": "Verifying the sender",
            "icon": "👤",
            "tip": (
                "The sender's name can be faked. **Always check the actual email address, "
                "not just the display name.** Look for misspellings and unusual domains."
            ),
            "how_to": (
                "Example: 'Amazon Support <amazon-support@secure-verify2738.xyz>' — "
                "the name says Amazon but the address is not amazon.com."
            ),
        })
    if results.get("has_attachments"):
        items.append({
            "title": "Handling attachments safely",
            "icon": "📎",
            "tip": (
                "Malware often arrives as email attachments. **Never enable macros in documents** "
                "from unknown senders. Be especially careful with .docm, .xlsm, .exe, and .zip files."
            ),
            "how_to": "If you weren't expecting a file, confirm with the sender through a phone call or separate message.",
        })
    if kw_matches.get("financial") or kw_matches.get("payment") or kw_matches.get("invoice"):
        items.append({
            "title": "Avoiding payment scams",
            "icon": "💰",
            "tip": (
                "**Unsolicited payment requests are almost always scams.** "
                "Attackers send fake invoices, overdue notices, and wire transfer requests. "
                "Always verify financial requests through official channels."
            ),
            "how_to": "Call the company using their publicly listed number (not one from the email) to verify invoices.",
        })

    if not items:
        items.append({
            "title": "General safety tips",
            "icon": "🛡️",
            "tip": (
                "Even safe-looking emails can be phishing. Stay vigilant: "
                "check senders, hover links, and trust your instincts."
            ),
            "how_to": "When in doubt, don't click. Go directly to the official website.",
        })

    return items
