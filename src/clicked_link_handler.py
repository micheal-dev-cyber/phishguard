"""Clicked Link Response Mode — post-interaction risk assessment.

When a user confirms they interacted with a phishing email,
this module generates a personalized risk assessment and
remediation plan based on the specific interaction type.
"""

from __future__ import annotations


RISK_ASSESSMENTS = {
    "link_only": {
        "title": "Link Clicked — No Credentials Entered",
        "risk": "Medium",
        "priority": "🟠 High",
        "what_happened": (
            "By clicking the link, you may have: (1) confirmed your email address is active "
            "to the attacker, (2) triggered a drive-by download that installed malware silently, "
            "or (3) been redirected through tracking servers that log your IP, browser, and location."
        ),
        "next_steps": [
            "🛡️ **Run an antivirus scan** on your device immediately",
            "🔑 **Change your email password** from a different, trusted device",
            "🔐 **Enable MFA** on your email account if not already active",
            "👁️ **Check for unusual login activity** in your account security settings",
            "📢 **Notify your IT/security team** — they need to check for lateral movement",
            "🔄 **Review recent account activity** for any unauthorized changes",
        ],
        "urgency": "Complete within 2 hours",
    },
    "credentials_given": {
        "title": "Credentials Entered — Account May Be Compromised",
        "risk": "Critical",
        "priority": "🔴 Critical",
        "what_happened": (
            "Your username and password have been captured by the attacker. Even if the page "
            "showed an error or redirected you, the credentials were already collected. "
            "If you use the same password elsewhere, those accounts are also at risk. "
            "Modern phishing kits relay credentials in real-time to the real login page, "
            "making you think you just mistyped your password."
        ),
        "next_steps": [
            "🔄 **Change your password NOW** — use a strong, unique password not used elsewhere",
            "🔐 **Enable MFA immediately** if not active — this is your most important defense",
            "🔄 **Change passwords on all accounts** where you use the same or similar credentials",
            "👁️ **Check account activity** for unauthorized logins, forwarding rules, or settings changes",
            "🔓 **Review active sessions** and log out all devices except your current one",
            "📢 **Report to IT/security team** — credential theft requires incident response",
            "🛡️ **Run malware scan** — the phishing page may have delivered malware alongside credential theft",
            "📋 **Check email forwarding rules** — attackers often add stealthy forwarding after compromise",
        ],
        "urgency": "Immediate — within 30 minutes",
    },
    "file_downloaded": {
        "title": "File Downloaded — Possible Malware Infection",
        "risk": "High",
        "priority": "🔴 Critical",
        "what_happened": (
            "Downloading and opening a file from a phishing email is one of the most dangerous "
            "things you can do. The file may contain: ransomware that encrypts your files, "
            "a stealer that captures passwords and browser data, a RAT (Remote Access Trojan) "
            "giving attackers control of your device, or macro malware that activates when you "
            "enable document macros."
        ),
        "next_steps": [
            "🛡️ **Run a full antivirus/anti-malware scan immediately**",
            "🔌 **Disconnect from the network** if you suspect ransomware (stop encryption spread)",
            "🔄 **Change all passwords** from a DIFFERENT trusted device",
            "🔐 **Enable MFA** on all critical accounts",
            "🖥️ **Check for new software, browser extensions, or processes** you didn't install",
            "📢 **Contact your IT/security team urgently** — they need to check for lateral movement",
            "⚠️ **Do NOT pay ransomware demands** — contact law enforcement (CISA, FBI)",
            "📋 **Check for data exfiltration** — look for unusual outbound network traffic",
        ],
        "urgency": "Immediate — device may be compromised",
    },
    "no_interaction": {
        "title": "No Interaction — Low Direct Risk",
        "risk": "Low",
        "priority": "🟢 Medium",
        "what_happened": (
            "Since you did not click any links or download any files, the direct risk to your "
            "device and accounts is low. However, simply opening the email may have triggered "
            "tracking pixels that inform the attacker your email address is active."
        ),
        "next_steps": [
            "🗑️ **Delete the email** from your inbox and trash folder",
            "🚫 **Block the sender** to prevent future phishing attempts",
            "📢 **Report to IT** so they can block the sender at the gateway level",
            "👁️ **Stay vigilant** — being targeted once means you may be targeted again",
            "🔐 **Enable MFA** if not already done (general good practice)",
        ],
        "urgency": "Within 24 hours",
    },
    "mfa_bypassed": {
        "title": "MFA Bypass Attempted — AitM Attack Confirmed",
        "risk": "Critical",
        "priority": "🔴 Critical",
        "what_happened": (
            "This was likely an Adversary-in-the-Middle (AitM) phishing attack that used a "
            "reverse proxy to intercept not just your password but also your MFA token or "
            "session cookie. Even if you entered your MFA code and the page showed an error, "
            "the attacker used that code in real-time to authenticate as you. "
            "This is how modern phishing campaigns bypass MFA protection."
        ),
        "next_steps": [
            "🔄 **Reset ALL passwords immediately** — do this from a trusted device",
            "🔐 **Contact your MFA provider** to invalidate all active sessions and tokens",
            "🔑 **Revoke and reissue API keys, OAuth tokens, and app passwords**",
            "👁️ **Audit all recent account activity** — look for session hijacking indicators",
            "📢 **Escalate to IT/security team as a confirmed breach** — this requires forensic analysis",
            "🛡️ **Check for persistence mechanisms** — attackers may have added backup MFA methods",
            "📋 **Review email forwarding rules, auto-reply, and mailbox permissions**",
        ],
        "urgency": "Immediate — session hijacking in progress",
    },
}


def assess_post_click_risk(results: dict, interaction_type: str, work_account: bool = False) -> dict:
    """Generate post-click risk assessment based on interaction type.

    Args:
        results: The analysis results dict
        interaction_type: One of 'link_only', 'credentials_given',
                         'file_downloaded', 'no_interaction', 'mfa_bypassed'
        work_account: Whether the account is a work/business account

    Returns:
        Assessment dict with title, risk, priority, what_happened,
        next_steps, urgency, and a general note about work accounts.
    """
    assessment = RISK_ASSESSMENTS.get(interaction_type, RISK_ASSESSMENTS["link_only"]).copy()
    score = results.get("risk_score", 0)

    if work_account:
        assessment["next_steps"].insert(
            0,
            "🏢 **This is a WORK account — notify your security team immediately.** "
            "Corporate accounts have higher-value data and attackers will move laterally.",
        )
        urgency_boost = {
            "Medium": "High",
            "High": "Critical",
            "Critical": "Critical",
            "Low": "Medium",
        }
        current_risk = assessment.get("risk", "Medium")
        assessment["risk"] = urgency_boost.get(current_risk, current_risk)

    assessment["score"] = score
    assessment["interaction_type"] = interaction_type
    return assessment
