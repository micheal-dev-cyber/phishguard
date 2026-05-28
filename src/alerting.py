"""
PhishGuard AI — Real-time Alerting (Slack, Email, Webhook)

Usage:
    send_alert(alert)
    # or configure via app.py UI
"""
import os
import json
import smtplib
import logging
from email.message import EmailMessage
from typing import Optional

logger = logging.getLogger("alerting")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def send_slack(webhook_url: str, message: str, title: str = "PhishGuard Alert") -> dict:
    if not HAS_REQUESTS:
        return {"status": "error", "error": "requests not installed"}
    try:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title},
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": message}},
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"PhishGuard AI • {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
                        }
                    ],
                },
            ]
        }
        resp = requests.post(webhook_url, json=payload, timeout=10)
        return {"status": "ok" if resp.ok else "error", "code": resp.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def send_email(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
               from_addr: str, to_addrs: list, subject: str, body: str) -> dict:
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return {"status": "ok", "sent_to": len(to_addrs)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def send_webhook(url: str, payload: dict) -> dict:
    if not HAS_REQUESTS:
        return {"status": "error", "error": "requests not installed"}
    try:
        resp = requests.post(url, json=payload, timeout=10,
                             headers={"Content-Type": "application/json"})
        return {"status": "ok" if resp.ok else "error", "code": resp.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def format_alert_message(verdict: dict, layers: dict = None) -> str:
    score = verdict.get("risk_score", 0)
    severity = verdict.get("severity", "UNKNOWN")
    ai_prob = verdict.get("ai_written_probability", 0)
    aitm = verdict.get("aitm_confidence", 0)
    lines = [
        f"*Risk Score:* {score}/100",
        f"*Severity:* {severity}",
        f"*AI-written Probability:* {ai_prob:.0%}",
        f"*AitM Confidence:* {aitm:.0%}",
    ]
    if layers:
        heur = layers.get("heuristic", {})
        if heur:
            lines.append(f"*Heuristic:* {heur.get('risk_score', 'N/A')}/100")
        ai = layers.get("ai_text_detection", {})
        if ai:
            lines.append(f"*AI Detection:* {ai.get('probability', 0):.0%}")
        a = layers.get("aitm_detection", {})
        if a:
            lines.append(f"*AitM:* {a.get('confidence', 0):.0%}")
    return "\n".join(lines)


def build_alert(verdict: dict, text_preview: str, layers: dict = None,
                email_subject: str = "", sender: str = "") -> dict:
    return {
        "risk_score": verdict.get("risk_score", 0),
        "severity": verdict.get("severity", "UNKNOWN"),
        "ai_written_probability": verdict.get("ai_written_probability", 0),
        "aitm_confidence": verdict.get("aitm_confidence", 0),
        "text_preview": text_preview[:200],
        "email_subject": email_subject,
        "sender": sender,
        "layers": layers or {},
        "timestamp": __import__("datetime").datetime.now().isoformat(),
    }
