"""Weekly Auto-Report — scheduled PDF email delivery to executives."""

import logging
import smtplib
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("weekly_report")


def generate_weekly_report(username: str) -> bytes:
    """Generate a weekly PDF summary report."""
    try:
        from src.report_generator import generate_pdf_report
        results = {
            "risk_score": 0,
            "severity": "INFO",
            "total_keyword_hits": 0,
            "suspicious_url_count": 0,
            "urls_found": [],
            "headers": {},
        }
        email_text = f"Weely Security Report — {datetime.now().strftime('%Y-%m-%d')}"
        return generate_pdf_report(results, email_text, white_label=True)
    except Exception as e:
        logger.error("Report generation failed: %s", e)
        return b""


def send_weekly_report(username: str, email: str):
    """Build and email the weekly report."""
    pdf_bytes = generate_weekly_report(username)
    if not pdf_bytes:
        return {"sent": False, "error": "report_generation_failed"}

    try:
        from src.env import ENV
        smtp_host = getattr(ENV, "SMTP_HOST", "") or ""
        smtp_port = int(getattr(ENV, "SMTP_PORT", "587") or "587")
        smtp_user = getattr(ENV, "SMTP_USER", "") or ""
        smtp_pass = getattr(ENV, "SMTP_PASSWORD", "") or ""
        smtp_from = getattr(ENV, "SMTP_FROM", "") or smtp_user

        msg = MIMEMultipart()
        msg["Subject"] = f"PhishGuard Weekly Security Report — {datetime.now().strftime('%b %d, %Y')}"
        msg["From"] = smtp_from
        msg["To"] = email
        msg.attach(MIMEText(
            "Attached is your weekly phishing threat summary.\n\n"
            "Stay vigilant,\nPhishGuard AI", "plain"
        ))

        part = MIMEBase("application", "octet-stream")
        part.set_payload(pdf_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="phishguard_weekly_{datetime.now().strftime("%Y%m%d")}.pdf"')
        msg.attach(part)

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        logger.info("Weekly report sent to %s", email)
        return {"sent": True}
    except Exception as e:
        logger.error("Weekly report send failed: %s", e)
        return {"sent": False, "error": str(e)}


def check_and_send_weekly(username: str, email: str) -> dict:
    """Check if a weekly report is due and send it."""
    from src.db import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS weekly_reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            sent_at     TEXT NOT NULL,
            period_week TEXT NOT NULL
        )
    """)
    week = datetime.now().strftime("%Y-W%W")
    c.execute(
        "SELECT id FROM weekly_reports WHERE username = ? AND period_week = ?",
        (username, week),
    )
    if c.fetchone():
        conn.close()
        return {"sent": False, "reason": "already_sent_this_week"}

    result = send_weekly_report(username, email)
    if result.get("sent"):
        c.execute(
            "INSERT INTO weekly_reports (username, sent_at, period_week) VALUES (?, ?, ?)",
            (username, datetime.now().isoformat(), week),
        )
        conn.commit()
    conn.close()
    return result
