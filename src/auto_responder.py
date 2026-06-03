"""Email Auto-Responder — automatically reply to detected phishing senders."""

import logging
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("auto-responder")


def send_phishing_warning(sender_email: str, recipient_email: str, smtp_config: dict) -> dict:
    smtp_host = smtp_config.get("host", "")
    smtp_port = smtp_config.get("port", 587)
    smtp_user = smtp_config.get("user", "")
    smtp_pass = smtp_config.get("pass", "")
    smtp_from = smtp_config.get("from_addr", smtp_user)

    if not smtp_user or not smtp_pass:
        return {"success": False, "error": "SMTP not configured"}

    subject = "⚠ Security Alert: Suspicious Email Detected"
    body = (
        f"Hello,\n\n"
        f"Our security system detected that an email from {sender_email} sent to "
        f"{recipient_email} contained phishing indicators.\n\n"
        f"This is an automated warning. Do not click any links or download attachments "
        f"from that sender. If you believe this was legitimate, please contact your "
        f"security team.\n\n"
        f"PhishGuard AI — Automated Security Response"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = recipient_email

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info("Warning sent to %s about %s", recipient_email, sender_email)
        return {"success": True}
    except Exception as e:
        logger.error("Auto-responder failed: %s", e)
        return {"success": False, "error": str(e)}
