"""Educational Mode — how to spot this attack in the future.

Generates reusable, practical educational content based on the detected
attack type so users learn to identify similar threats independently.
"""

from __future__ import annotations

from typing import Any


EDUCATION_MODULES = {
    "urgency": {
        "title": "How to Spot Urgency Tricks",
        "icon": "⏰",
        "content": (
            "Phishers create fake emergencies to bypass your rational thinking.\n\n"

            "**🚩 Warning signs to look for:**\n"
            "- 'Act immediately' or 'Urgent action required'\n"
            "- 'Your account will be closed/suspended' deadlines\n"
            "- 'Last warning' or 'Final notice'\n"
            "- 'Within 24 hours' or 'Limited time'\n\n"

            "**✅ What to do instead:**\n"
            "- Pause. Take a breath. Scammers rely on you NOT thinking.\n"
            "- Contact the company directly using their official phone number or website.\n"
            "- Real emergencies from real companies don't arrive via email ultimatums."
        ),
    },
    "credential_harvesting": {
        "title": "How to Spot Fake Login Pages",
        "icon": "🔑",
        "content": (
            "Attackers create fake login pages that look identical to the real thing.\n\n"

            "**🚩 Warning signs to look for:**\n"
            "- Emails saying 'Verify your account' or 'Confirm your identity'\n"
            "- Links to 'login' or 'sign in' pages you weren't expecting\n"
            "- Password reset emails you didn't request\n\n"

            "**✅ What to do instead:**\n"
            "- NEVER click email links to reach login pages. Type the address yourself.\n"
            "- Check the URL carefully — look for misspellings (g00gle.com, faceb00k.com)\n"
            "- Use a password manager — it will auto-fill only on the REAL website.\n"
            "- Enable Two-Step Verification (MFA) on all important accounts."
        ),
    },
    "sender_spoofing": {
        "title": "How to Spot Fake Senders",
        "icon": "👤",
        "content": (
            "Email display names are easy to fake. The name says 'CEO' but the address is a scam.\n\n"

            "**🚩 Warning signs to look for:**\n"
            "- A familiar name but a strange email address you don't recognize\n"
            "- Free email services (Gmail, Yahoo) used for 'official' communications\n"
            "- Slightly misspelled company names in the email address\n\n"

            "**✅ What to do instead:**\n"
            "- Always check the actual email address, not just the name you see.\n"
            "- Hover over the 'From' field to see the full address.\n"
            "- If something seems off, contact the person through a different method."
        ),
    },
    "bec": {
        "title": "How to Spot Business Email Compromise",
        "icon": "💰",
        "content": (
            "BEC is the most financially damaging type of cybercrime. "
            "Attackers impersonate executives or vendors to steal money.\n\n"

            "**🚩 Warning signs to look for:**\n"
            "- An executive emails you directly asking for a wire transfer or gift cards\n"
            "- 'Urgent' and 'Confidential' requests that bypass normal approval processes\n"
            "- Someone claiming they're in a meeting and can't talk\n"
            "- Vendors requesting payment details be changed\n\n"

            "**✅ What to do to protect your company:**\n"
            "- Always verify payment requests in person or by phone (use a known number)\n"
            "- Never trust email-only instructions to change banking details\n"
            "- Implement a two-person approval rule for all wire transfers\n"
            "- Train all finance team members to spot BEC red flags"
        ),
    },
    "attachments": {
        "title": "How to Handle Email Attachments Safely",
        "icon": "📎",
        "content": (
            "Attachments are one of the most common ways malware gets on your computer.\n\n"

            "**🚩 Warning signs to look for:**\n"
            "- Unexpected attachments from people you know or don't know\n"
            "- Files ending in: .docm, .xlsm, .exe, .js, .vbs, .scr, .zip\n"
            "- Messages that say 'Enable macros' or 'Enable editing' to view the content\n"
            "- Double extensions like 'invoice.pdf.exe'\n\n"

            "**✅ What to do instead:**\n"
            "- Don't open unexpected attachments — confirm with the sender first.\n"
            "- Never enable macros in documents. Macros run code that can infect your PC.\n"
            "- Use cloud preview instead of downloading files (Google Docs, Office Online).\n"
            "- Keep your antivirus software up to date."
        ),
    },
    "links": {
        "title": "How to Check Links Safely",
        "icon": "🔗",
        "content": (
            "One click on a malicious link can compromise your accounts or device.\n\n"

            "**🚩 Warning signs to look for:**\n"
            "- The link text says one thing but the actual URL goes somewhere else\n"
            "- Shortened URLs (bit.ly, tinyurl) that hide the real destination\n"
            "- URLs with misspellings, extra characters, or unusual domain endings\n"
            "- Links that claim to be 'secure' but use http:// instead of https://\n\n"

            "**✅ What to do instead:**\n"
            "- Hover over links (without clicking) to see the real URL in the status bar.\n"
            "- On mobile, press and hold a link to preview the URL.\n"
            "- Type the website address directly into your browser instead of clicking.\n"
            "- Use a link checker tool if you're unsure."
        ),
    },
    "mfa": {
        "title": "Why Multi-Factor Authentication (MFA) Matters",
        "icon": "🔐",
        "content": (
            "MFA is the single most important thing you can do to protect your accounts.\n\n"

            "**What MFA does:**\n"
            "- Even if a scammer steals your password, they can't log in without the second step.\n"
            "- The second step is usually: a code sent to your phone, a fingerprint, or an app notification.\n\n"

            "**⚠️ Important warning about modern phishing:**\n"
            "- Advanced MFA-bypass attacks (AitM) can now steal session cookies too.\n"
            "- If you get a login notification you didn't trigger — ALWAYS deny it.\n\n"

            "**Where to enable MFA:**\n"
            "- Email accounts (Gmail, Outlook, iCloud)\n"
            "- Social media (Facebook, Instagram, LinkedIn, Twitter)\n"
            "- Banking and financial accounts\n"
            "- Work accounts (Office 365, VPN, payroll)"
        ),
    },
    "ai_phishing": {
        "title": "How to Spot AI-Generated Phishing",
        "icon": "🤖",
        "content": (
            "Attackers now use AI to write phishing emails. These emails have perfect grammar "
            "and sound very professional — making them harder to spot.\n\n"

            "**🚩 Warning signs to look for:**\n"
            "- Emails that sound 'too perfect' — very structured, formal, and well-organized\n"
            "- Lots of transition words: 'furthermore', 'moreover', 'consequently', 'additionally'\n"
            "- Overly polite and formal language throughout\n"
            "- Bullet points and numbered lists that look templated\n"
            "- Content that feels generic — like it could apply to anyone\n\n"

            "**✅ What to do instead:**\n"
            "- Perfect grammar doesn't mean legitimate email. Focus on the ASK, not the writing.\n"
            "- Is the email asking you to do something unusual? Click a link? Send money?\n"
            "- Verify through a separate channel regardless of how well-written the email is."
        ),
    },
    "general": {
        "title": "General Phishing Prevention Tips",
        "icon": "🛡️",
        "content": (
            "These basic habits will protect you from 90% of phishing attacks:\n\n"

            "**🛡️ Your phishing safety checklist:**\n"
            "1. **Don't click** — Navigate to websites manually instead of clicking email links\n"
            "2. **Don't rush** — Scammers create urgency. Take your time.\n"
            "3. **Check the sender** — Look at the actual email address, not just the name\n"
            "4. **Hover links** — See where they really go before clicking\n"
            "5. **Don't open unexpected attachments** — Verify with the sender first\n"
            "6. **Never share passwords by email** — Legitimate companies won't ask\n"
            "7. **Enable MFA** — Two-step verification blocks most account takeovers\n"
            "8. **Use a password manager** — It won't auto-fill on fake websites\n"
            "9. **Trust your gut** — If something feels off, it probably is\n"
            "10. **Report it** — Forward phishing to your IT team or reportphishing@apwg.org"
        ),
    },
}


def get_educational_content(results: dict, tactic_results: list[dict] | None = None) -> list[dict]:
    """Generate educational content based on analysis results.

    Args:
        results: Analysis results dict
        tactic_results: Pre-computed tactic classification results

    Returns:
        List of educational module dicts with title, icon, content
    """
    modules = []
    used_keys = set()

    kw_matches = results.get("keyword_matches", {}) or {}
    lang_analysis = results.get("language_analysis", {}) or {}
    results_object = results or {}
    has_attachments = results_object.get("has_attachments", False) or results_object.get("attachments_detected", False)

    if lang_analysis.get("urgency_count", 0) > 0:
        modules.append(EDUCATION_MODULES["urgency"])
        used_keys.add("urgency")

    if kw_matches.get("credentials") or kw_matches.get("password"):
        modules.append(EDUCATION_MODULES["credential_harvesting"])
        used_keys.add("credential_harvesting")

    header_analysis = results.get("header_analysis", {}) or {}
    if header_analysis.get("findings"):
        modules.append(EDUCATION_MODULES["sender_spoofing"])
        used_keys.add("sender_spoofing")

    if kw_matches.get("financial") or kw_matches.get("wire") or kw_matches.get("ceo"):
        modules.append(EDUCATION_MODULES["bec"])
        used_keys.add("bec")

    if has_attachments:
        modules.append(EDUCATION_MODULES["attachments"])
        used_keys.add("attachments")

    if results.get("suspicious_url_count", 0) > 0:
        modules.append(EDUCATION_MODULES["links"])
        used_keys.add("links")

    perplexity = results.get("perplexity_result", {}) or {}
    if perplexity.get("ai_probability", 0) >= 60:
        modules.append(EDUCATION_MODULES["ai_phishing"])
        used_keys.add("ai_phishing")

    if tactic_results:
        for tactic in tactic_results:
            tid = tactic.get("id", "")
            if tid == "mfa_bypass" and "mfa" not in used_keys:
                modules.append(EDUCATION_MODULES["mfa"])
                used_keys.add("mfa")

    modules.append(EDUCATION_MODULES["general"])

    return modules
