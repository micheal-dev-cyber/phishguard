"""Security Action Center — dynamic incident response actions based on threat profile.

Generates prioritized, categorized actions for immediate response, containment,
investigation, prevention, and reporting. More comprehensive than the base
recommendations module — tailored to the specific threat type detected.
"""

from __future__ import annotations

from typing import Any

CATEGORY_LABELS = {
    "immediate": ("🔴 Immediate Actions", 0),
    "containment": ("🟠 Containment", 1),
    "investigation": ("🟡 Investigation", 2),
    "prevention": ("🟢 Prevention", 3),
    "reporting": ("🔵 Reporting", 4),
}

ACTION_TEMPLATES = {
    # ── Immediate ──────────────────────────────────────────────────────────
    "do_not_interact": {
        "category": "immediate",
        "priority": "critical",
        "title": "Do not interact with this email",
        "description": "Stop — do not reply, click any links, open attachments, or forward this email.",
        "instructions": "Close the email. If you already clicked or entered data, use the Clicked Link Response tool above.",
        "icon": "🛑",
        "when": lambda r, s: s in ("CRITICAL", "HIGH"),
    },
    "delete_email": {
        "category": "immediate",
        "priority": "critical",
        "title": "Delete this email immediately",
        "description": "Remove the email from your inbox to prevent accidental interaction.",
        "instructions": "Move the email to your trash/deleted items, then empty the trash folder.",
        "icon": "🗑️",
        "when": lambda r, s: s in ("CRITICAL", "HIGH"),
    },
    "disconnect_network": {
        "category": "immediate",
        "priority": "critical",
        "title": "Disconnect from the network",
        "description": "If you downloaded or opened a suspicious file, disconnect immediately.",
        "instructions": "Turn off Wi-Fi, unplug ethernet, or enable airplane mode. This limits malware communication.",
        "icon": "📡",
        "when": lambda r, s, ctx: r >= 75 and ctx.get("file_downloaded", False),
    },
    "change_password_now": {
        "category": "immediate",
        "priority": "critical",
        "title": "Change your password immediately",
        "description": "If you entered credentials, attackers have them. Change your password now.",
        "instructions": "Use a different device to change your password. Do NOT use the same device where you opened the email. Enable MFA first, then change password.",
        "icon": "🔑",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("credentials_entered", False),
    },
    "do_not_reply": {
        "category": "immediate",
        "priority": "high",
        "title": "Do not reply to this email",
        "description": "Replying confirms your email address is active, inviting more attacks.",
        "instructions": "Delete the email without replying. If you need to contact the sender, use a known phone number or official website — not contact info from this email.",
        "icon": "🔇",
        "when": lambda r, s: r >= 40,
    },

    # ── Containment ────────────────────────────────────────────────────────
    "block_sender": {
        "category": "containment",
        "priority": "high",
        "title": "Block the sender address",
        "description": "Prevent future emails from this sender from reaching your inbox.",
        "instructions": "In Gmail: open the email → More (⋮) → Block. In Outlook: right-click email → Junk → Block Sender.",
        "icon": "🚫",
        "when": lambda r, s: r >= 50,
    },
    "quarantine": {
        "category": "containment",
        "priority": "high",
        "title": "Quarantine this email",
        "description": "Isolate the email so it cannot be accidentally accessed.",
        "instructions": "Report as phishing in your email client. In Gmail: select the email → Report phishing. In Outlook: Report → Report phishing.",
        "icon": "🧊",
        "when": lambda r, s: r >= 65,
    },
    "scan_device": {
        "category": "containment",
        "priority": "high",
        "title": "Run a full antivirus scan",
        "description": "If you downloaded a file or clicked a link, scan your device for malware.",
        "instructions": "Run a full system scan with Windows Defender, Malwarebytes, or your corporate AV. Update definitions first.",
        "icon": "🛡️",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("file_downloaded", False),
    },
    "revoke_sessions": {
        "category": "containment",
        "priority": "high",
        "title": "Revoke active sessions",
        "description": "Force logout of all active sessions on your accounts.",
        "instructions": "Go to your account security settings and revoke all active sessions. This kicks out any attacker who may have gained access.",
        "icon": "🚪",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("credentials_entered", False),
    },

    # ── Investigation ──────────────────────────────────────────────────────
    "check_account_activity": {
        "category": "investigation",
        "priority": "medium",
        "title": "Check your account activity",
        "description": "Look for unauthorized access or unusual logins.",
        "instructions": "Check login history, recent devices, and account recovery activity for your email, banking, and social media accounts.",
        "icon": "👁️",
        "when": lambda r, s: r >= 25,
    },
    "check_for_forwarding": {
        "category": "investigation",
        "priority": "medium",
        "title": "Check for unauthorized email forwarding",
        "description": "Attackers often set up forwarding rules to monitor your mail.",
        "instructions": "In Gmail: Settings → See all settings → Forwarding and POP/IMAP. In Outlook: Settings → Mail → Forwarding. Disable any forwarding you didn't set up.",
        "icon": "↪️",
        "when": lambda r, s: r >= 40,
    },
    "review_linked_accounts": {
        "category": "investigation",
        "priority": "medium",
        "title": "Review linked accounts and apps",
        "description": "Attackers may connect malicious apps to your account.",
        "instructions": "Check third-party app access in your account security settings. Revoke any apps you don't recognize or no longer use.",
        "icon": "🔗",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("credentials_entered", False),
    },
    "verify_sender": {
        "category": "investigation",
        "priority": "medium",
        "title": "Verify the sender through a separate channel",
        "description": "Contact the supposed sender via a known phone number or website — not via info in this email.",
        "instructions": "Call or message the person/company using contact information you already have (not from the email). Ask if they sent this message.",
        "icon": "✅",
        "when": lambda r, s: 25 <= r < 75,
    },

    # ── Prevention ─────────────────────────────────────────────────────────
    "enable_mfa": {
        "category": "prevention",
        "priority": "high",
        "title": "Enable multi-factor authentication (MFA)",
        "description": "MFA prevents account takeover even if your password is stolen.",
        "instructions": "Go to your account security settings and enable MFA. Use an authenticator app (Google Authenticator, Microsoft Authenticator) rather than SMS if possible.",
        "icon": "🔐",
        "when": lambda r, s: r >= 20,
    },
    "update_passwords": {
        "category": "prevention",
        "priority": "medium",
        "title": "Update passwords for all accounts",
        "description": "If you reuse passwords, update them everywhere immediately.",
        "instructions": "Use a password manager to generate unique, strong passwords for each account. Enable MFA on all accounts that support it.",
        "icon": "🔄",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("credentials_entered", False),
    },
    "security_awareness": {
        "category": "prevention",
        "priority": "low",
        "title": "Review phishing awareness tips",
        "description": "Learn to spot the warning signs of phishing attacks.",
        "instructions": "Check the Educational Content section in this analysis for learning resources. Always verify unexpected requests, especially those asking for money or credentials.",
        "icon": "📖",
        "when": lambda r, s: r >= 20,
    },
    "report_to_it": {
        "category": "reporting",
        "priority": "high",
        "title": "Report to your IT / Security team",
        "description": "Your security team needs to analyze this attack to protect others.",
        "instructions": "Forward the email as an attachment to your IT security team. Include this analysis if possible.",
        "icon": "📢",
        "when": lambda r, s: r >= 50,
    },
    "report_apwg": {
        "category": "reporting",
        "priority": "medium",
        "title": "Report to APWG",
        "description": "Help takedown phishing sites and protect others globally.",
        "instructions": "Forward the email to reportphishing@apwg.org. Include the full headers if possible.",
        "icon": "🔬",
        "when": lambda r, s: r >= 50,
    },
    "report_fraud": {
        "category": "reporting",
        "priority": "medium",
        "title": "Report to financial fraud authorities",
        "description": "If this involves payment or financial information, report to authorities.",
        "instructions": "US: FTC at ReportFraud.ftc.gov. UK: Action Fraud. Canada: CAFC. EU: Your local police cybercrime unit.",
        "icon": "⚖️",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("payment_related", False),
    },
    "monitor_credit": {
        "category": "prevention",
        "priority": "low",
        "title": "Monitor your credit report",
        "description": "If personal/financial info was compromised, watch for identity theft.",
        "instructions": "US: Free weekly reports at annualcreditreport.com. Consider a credit freeze or fraud alert if you believe identity theft occurred.",
        "icon": "📊",
        "when": lambda r, s: r >= 50,
    },
}


def _get_actions_for_threat(results: dict, context: dict | None = None) -> list[dict]:
    ctx = context or {}
    score = results.get("risk_score", 0)
    severity = results.get("severity", "LOW")

    # Detect payment/financial threat
    kw = results.get("keyword_matches", {})
    payment_keywords = any(
        kw.get(cat, []) for cat in ("financial", "payment", "invoice")
    ) or any(
        kw.get(cat, []) for cat in ("payment", "invoice", "transfer")
        if isinstance(kw.get(cat), list)
    )
    ctx["payment_related"] = payment_keywords

    matched = []
    for action_id, tmpl in ACTION_TEMPLATES.items():
        try:
            if tmpl["when"](score, severity, ctx):
                matched.append({**tmpl, "id": action_id})
        except TypeError:
            try:
                if tmpl["when"](score, severity):
                    matched.append({**tmpl, "id": action_id})
            except TypeError:
                pass

    # Sort by category order, then priority within category
    cat_order = {k: v[1] for k, v in CATEGORY_LABELS.items()}
    prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matched.sort(key=lambda x: (cat_order.get(x["category"], 99),
                                 prio_order.get(x["priority"], 99)))
    return matched


def get_security_actions(results: dict, context: dict | None = None) -> list[dict]:
    """Get security actions organized by category for the Security Action Center.

    Args:
        results: Analysis results dict from analyze_email()
        context: Optional context dict (clicked_link, credentials_entered,
                 file_downloaded, work_account)

    Returns:
        List of action dicts sorted by category and priority.
    """
    return _get_actions_for_threat(results, context)


def get_incident_plan(results: dict, context: dict | None = None) -> str:
    """Generate a formatted incident response plan text."""
    actions = _get_actions_for_threat(results, context)
    if not actions:
        return "No actions needed — this email appears safe."

    lines = ["## Incident Response Plan", ""]

    current_category = None
    for action in actions:
        cat = action["category"]
        if cat != current_category:
            cat_label = CATEGORY_LABELS.get(cat, (cat.title(), 99))[0]
            lines.append(f"### {cat_label}")
            lines.append("")
            current_category = cat

        prio_label = action["priority"].upper()
        lines.append(f"**{action['icon']} [{prio_label}] {action['title']}**")
        lines.append(f"  {action['description']}")
        lines.append(f"  > {action['instructions']}")
        lines.append("")

    return "\n".join(lines)


def get_action_summary(actions: list[dict]) -> str:
    """Short summary of security actions needed."""
    if not actions:
        return "✅ No critical actions needed"
    critical = [a for a in actions if a.get("priority") == "critical"]
    high = [a for a in actions if a.get("priority") == "high"]
    medium = [a for a in actions if a.get("priority") == "medium"]
    parts = []
    if critical:
        parts.append(f"🔴 {len(critical)} critical")
    if high:
        parts.append(f"🟠 {len(high)} high-priority")
    if medium:
        parts.append(f"🟡 {len(medium)} medium-priority")
    return " | ".join(parts) if parts else "✅ No urgent actions needed"
