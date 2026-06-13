"""What Should I Do? — personalized action recommendations per threat.

Generates specific, actionable steps based on the detected threat type,
severity, and user context. Prioritizes actions and explains why.
"""

from __future__ import annotations

from typing import Any


RECOMMENDATION_LIBRARY = {
    "delete": {
        "action": "Delete immediately",
        "icon": "🗑️",
        "priority": "critical",
        "reason": "This email is confirmed phishing — keeping it in your inbox risks accidental interactions.",
        "when": lambda r, s: s in ("CRITICAL", "HIGH") and r >= 50,
    },
    "ignore": {
        "action": "Ignore this email",
        "icon": "🙅",
        "priority": "low",
        "reason": "No significant threats detected. Proceed normally but stay vigilant.",
        "when": lambda r, s: s == "LOW" and r < 25,
    },
    "block_sender": {
        "action": "Block sender address",
        "icon": "🚫",
        "priority": "high",
        "reason": "The sender's address shows signs of spoofing or impersonation — blocking prevents future contact.",
        "when": lambda r, s: r >= 50 and s in ("HIGH", "CRITICAL"),
    },
    "report_it": {
        "action": "Report to IT / Security team",
        "icon": "📢",
        "priority": "critical",
        "reason": "Your security team needs to analyze this attack and protect other employees.",
        "when": lambda r, s: r >= 50,
    },
    "report_apwg": {
        "action": "Forward to APWG (reportphishing@apwg.org)",
        "icon": "🔬",
        "priority": "medium",
        "reason": "Reporting to APWG helps takedown phishing sites and protect others globally.",
        "when": lambda r, s: r >= 50,
    },
    "change_password": {
        "action": "Change your password immediately",
        "icon": "🔑",
        "priority": "critical",
        "reason": "If you entered credentials on a phishing page, attackers now have your password.",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("credentials_entered", False),
    },
    "enable_mfa": {
        "action": "Enable multi-factor authentication (MFA)",
        "icon": "🔐",
        "priority": "high",
        "reason": "MFA prevents attackers from accessing your account even if they steal your password.",
        "when": lambda r, s: r >= 25,
    },
    "monitor_account": {
        "action": "Monitor your accounts for unusual activity",
        "icon": "👁️",
        "priority": "medium",
        "reason": "Attackers may use stolen credentials later — watch for logins from unknown locations.",
        "when": lambda r, s: r >= 25,
    },
    "scan_device": {
        "action": "Run antivirus / anti-malware scan",
        "icon": "🛡️",
        "priority": "high",
        "reason": "If you downloaded a file or enabled macros, your device may be compromised.",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("file_downloaded", False),
    },
    "contact_it": {
        "action": "Contact IT support for assistance",
        "icon": "📞",
        "priority": "medium",
        "reason": "IT can help check for compromises, reset passwords, and secure your accounts.",
        "when": lambda r, s: r >= 50,
    },
    "quarantine": {
        "action": "Quarantine this email",
        "icon": "🧊",
        "priority": "critical",
        "reason": "Removing the email from your inbox prevents accidental clicks and further risk.",
        "when": lambda r, s: r >= 75 or s == "CRITICAL",
    },
    "do_not_reply": {
        "action": "Do not reply to this email",
        "icon": "🔇",
        "priority": "high",
        "reason": "Replying confirms your email address is active and monitored, inviting more attacks.",
        "when": lambda r, s: r >= 50,
    },
    "verify_sender": {
        "action": "Verify sender through a separate channel",
        "icon": "✅",
        "priority": "medium",
        "reason": "Contact the supposed sender via phone or official website to confirm legitimacy.",
        "when": lambda r, s: 25 <= r < 75,
    },
    "reset_credentials": {
        "action": "Reset credentials for all linked accounts",
        "icon": "🔄",
        "priority": "critical",
        "reason": "If you reuse passwords, attackers may access multiple accounts with the stolen one.",
        "when": lambda r, s, ctx: r >= 50 and ctx.get("credentials_entered", False),
    },
}


def get_recommendations(results: dict, context: dict | None = None) -> list[dict]:
    """Generate prioritized recommendations based on analysis results.

    Args:
        results: The analysis results dict from analyze_email()
        context: Optional dict with user context:
            - clicked_link: bool
            - credentials_entered: bool
            - file_downloaded: bool
            - work_account: bool

    Returns:
        List of recommendation dicts sorted by priority, each with:
            action, icon, priority, reason, id
    """
    ctx = context or {}
    score = results.get("risk_score", 0)
    severity = results.get("severity", "LOW")

    matched = []
    for rec_id, rec in RECOMMENDATION_LIBRARY.items():
        try:
            if rec["when"](score, severity, ctx):
                matched.append({**rec, "id": rec_id})
        except TypeError:
            try:
                if rec["when"](score, severity):
                    matched.append({**rec, "id": rec_id})
            except TypeError:
                try:
                    if rec["when"](score, severity):
                        matched.append({**rec, "id": rec_id})
                except TypeError:
                    pass

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matched.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 99))

    return matched


def render_recommendations_text(recommendations: list[dict]) -> str:
    """Render recommendations as formatted markdown text."""
    if not recommendations:
        return "No specific recommendations at this time."

    lines = []
    for rec in recommendations:
        p = rec.get("priority", "medium")
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(p, "⚪")
        lines.append(f"{emoji} **{rec['icon']} {rec['action']}**")
        lines.append(f"   *{rec.get('reason', '')}*")
        lines.append("")

    return "\n".join(lines)


def get_recommendation_summary(recommendations: list[dict]) -> str:
    """Short summary of recommended actions."""
    if not recommendations:
        return "No action needed."
    critical = [r for r in recommendations if r.get("priority") == "critical"]
    high = [r for r in recommendations if r.get("priority") == "high"]
    if critical:
        return f"⚠️ **{len(critical)} critical** + {len(high)} high-priority actions needed"
    if high:
        return f"⚠️ **{len(high)} high-priority** actions recommended"
    return f"ℹ️ **{len(recommendations)} recommendations** to review"
