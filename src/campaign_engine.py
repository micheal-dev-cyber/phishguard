"""
PhishGuard AI — Corporate Phishing Simulation (SaaS Campaign Engine)

Architecture:
  Admin creates campaign → selects LLM-generated template → uploads targets
  → Engine sends mock emails via SMTP (same infra as src/alerts.py)
  → Tracks delivery, opens, clicks  → results feed into SOC Dashboard

Database tables:
  campaign_templates  — pre-built + LLM-generated phishing templates
  campaigns           — campaign runs (template + targets + status)
  campaign_results    — per-employee delivery/open/click/response telemetry
"""

import json
import logging
import random
import re
import time
from datetime import datetime, timezone
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from src.db import DB_PATH, get_connection
from src.env import ENV
from src.providers import get_chat_completion

logger = logging.getLogger("campaign-engine")

BUILTIN_TEMPLATES = {
    "fake_invoice": {
        "name": "Fake Invoice — Urgent Payment Due",
        "subject": "Invoice #{n} — Payment Overdue — {company}",
        "body": """Dear {first_name},

This is a reminder that Invoice #{n} for ${amount}.00 is now overdue by {days} days.

Please remit payment immediately to avoid service interruption and a late fee of ${fee}.00.

Click here to view and pay your invoice securely:
https://secure-{company}-billing.com/invoice/{n}

Regards,
{company} Accounts Receivable
{email}""",
        "difficulty": "medium",
        "category": "financial",
    },
    "password_reset": {
        "name": "Password Reset — Security Alert",
        "subject": "⚠ Security Alert: Password Reset Required for {company} Account",
        "body": """Hi {first_name},

We detected unusual sign-in activity on your {company} account from an unrecognized device.

To protect your account, please reset your password immediately:

https://{company}-security-portal.com/reset?token={token}

This link expires in 30 minutes. If you did not request this, please ignore.

{company} Security Team
{email}""",
        "difficulty": "hard",
        "category": "security",
    },
    "shared_document": {
        "name": "Shared Document — Cloud Notification",
        "subject": "{first_name} shared a document with you",
        "body": """Hi,

{first_name} from {company} has shared a document with you:

"Q{quarter}_{year}_{company}_Financial_Report.xlsx"

Click here to view: https://docs-{company}.cloud/view/{doc_id}

This link expires in 7 days.

Best,
{company} Cloud Sharing""",
        "difficulty": "easy",
        "category": "productivity",
    },
    "voicemail": {
        "name": "Voicemail Notification — Missed Call",
        "subject": "New voicemail from {phone}",
        "body": """You have a new voicemail from {phone}.

Duration: 0:{duration}
Received: {time}

Listen to your message: https://vm-{company}.com/message/{n}

This is an automated message from {company} Phone System.""",
        "difficulty": "easy",
        "category": "communication",
    },
    "package_delivery": {
        "name": "Package Delivery — Action Required",
        "subject": "Package #{n} — Delivery Attempt Failed",
        "body": """Hi {first_name},

We attempted to deliver your package #{n} but were unable to complete delivery.

Your package is currently held at our local facility.

Please reschedule delivery here: https://track-{company}-parcel.com/reschedule/{n}

A re-delivery fee of ${fee}.00 may apply if not scheduled within 48 hours.

{company} Logistics""",
        "difficulty": "medium",
        "category": "delivery",
    },
}


def init_campaign_tables():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaign_templates (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            subject     TEXT NOT NULL,
            body        TEXT NOT NULL,
            difficulty  TEXT DEFAULT 'medium',
            category    TEXT DEFAULT 'general',
            is_builtin  INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            template_id     INTEGER NOT NULL,
            template_name   TEXT NOT NULL,
            target_count    INTEGER DEFAULT 0,
            sent_count      INTEGER DEFAULT 0,
            opened_count    INTEGER DEFAULT 0,
            clicked_count   INTEGER DEFAULT 0,
            reported_count  INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'draft',
            created_by      TEXT DEFAULT 'admin',
            created_at      TEXT DEFAULT (datetime('now')),
            launched_at     TEXT,
            completed_at    TEXT,
            FOREIGN KEY (template_id) REFERENCES campaign_templates(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaign_targets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id     INTEGER NOT NULL,
            email           TEXT NOT NULL,
            first_name      TEXT DEFAULT '',
            last_name       TEXT DEFAULT '',
            department      TEXT DEFAULT '',
            company         TEXT DEFAULT '',
            status          TEXT DEFAULT 'pending',
            sent_at         TEXT,
            opened_at       TEXT,
            clicked_at      TEXT,
            reported_at     TEXT,
            risk_score       INTEGER DEFAULT 0,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        )
    """)
    conn.commit()
    conn.close()
    _seed_builtin_templates()


def _seed_builtin_templates():
    conn = get_connection()
    c = conn.cursor()
    existing = c.execute("SELECT COUNT(*) FROM campaign_templates WHERE is_builtin = 1").fetchone()[0]
    if existing >= len(BUILTIN_TEMPLATES):
        conn.close()
        return
    for tid, tpl in BUILTIN_TEMPLATES.items():
        c.execute(
            "INSERT OR IGNORE INTO campaign_templates (name, subject, body, difficulty, category, is_builtin) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (tpl["name"], tpl["subject"], tpl["body"], tpl["difficulty"], tpl["category"]),
        )
    conn.commit()
    conn.close()


def get_templates(category: Optional[str] = None) -> list:
    init_campaign_tables()
    conn = get_connection()
    c = conn.cursor()
    if category:
        c.execute(
            "SELECT id, name, subject, body, difficulty, category, is_builtin FROM campaign_templates WHERE category = ? ORDER BY id",
            (category,),
        )
    else:
        c.execute("SELECT id, name, subject, body, difficulty, category, is_builtin FROM campaign_templates ORDER BY id")
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "name": r[1], "subject": r[2], "body": r[3], "difficulty": r[4], "category": r[5], "is_builtin": bool(r[6])}
        for r in rows
    ]


def generate_llm_template(topic: str = "phishing email") -> dict:
    prompt = (
        f"Create a realistic {topic} template for a security awareness phishing simulation.\n"
        "Include:\n"
        "- subject (attention-grabbing)\n"
        "- body (social engineering, urgency, call to action with a link placeholder)\n"
        "- difficulty (easy/medium/hard)\n"
        "- category (financial/security/productivity/communication/delivery)\n"
        "Use placeholders like {first_name}, {company}, {email}, {n} (random number).\n"
        "Return ONLY valid JSON with keys: name, subject, body, difficulty, category."
    )
    try:
        response = get_chat_completion(prompt, max_tokens=800)
        text = response.get("content", "")
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            tpl = json.loads(json_match.group())
            if all(k in tpl for k in ("name", "subject", "body")):
                return tpl
    except Exception as exc:
        logger.warning("LLM template generation failed: %s", exc)
    return {}


def create_campaign(name: str, template_id: int, targets: list, created_by: str = "admin") -> dict:
    init_campaign_tables()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT name, subject, body FROM campaign_templates WHERE id = ?", (template_id,))
        tpl = c.fetchone()
        if not tpl:
            return {"error": "Template not found"}
        tpl_name, tpl_subject, tpl_body = tpl

        c.execute(
            "INSERT INTO campaigns (name, template_id, template_name, target_count, status, created_by) "
            "VALUES (?, ?, ?, ?, 'draft', ?)",
            (name, template_id, tpl_name, len(targets), created_by),
        )
        campaign_id = c.lastrowid

        for t in targets:
            c.execute(
                "INSERT INTO campaign_targets (campaign_id, email, first_name, last_name, department, company) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (campaign_id, t.get("email", ""), t.get("first_name", ""),
                 t.get("last_name", ""), t.get("department", ""), t.get("company", "")),
            )

        conn.commit()
        return {"campaign_id": campaign_id, "targets_added": len(targets)}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        conn.close()


def launch_campaign(campaign_id: int) -> dict:
    init_campaign_tables()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT status, template_id FROM campaigns WHERE id = ?", (campaign_id,))
        row = c.fetchone()
        if not row:
            return {"error": "Campaign not found"}
        status, template_id = row
        if status != "draft":
            return {"error": f"Cannot launch campaign with status '{status}'"}

        c.execute("SELECT name, subject, body FROM campaign_templates WHERE id = ?", (template_id,))
        tpl = c.fetchone()
        if not tpl:
            return {"error": "Template not found"}
        tpl_name, tpl_subject, tpl_body = tpl

        c.execute(
            "SELECT id, email, first_name, last_name, company FROM campaign_targets WHERE campaign_id = ?",
            (campaign_id,),
        )
        targets = c.fetchall()
        if not targets:
            return {"error": "No targets in campaign"}

        sent = 0
        for t in targets:
            tid, email, first_name, last_name, company = t
            company = company or "PhishGuard"
            first_name = first_name or email.split("@")[0]
            n = random.randint(10000, 99999)
            placeholders = {
                "{first_name}": first_name,
                "{last_name}": last_name or "",
                "{company}": company,
                "{email}": email,
                "{n}": str(n),
                "{amount}": str(random.randint(50, 5000)),
                "{days}": str(random.randint(1, 14)),
                "{fee}": str(random.randint(10, 99)),
                "{token}": secrets_token(32),
                "{doc_id}": secrets_token(12),
                "{quarter}": str(random.randint(1, 4)),
                "{year}": str(datetime.now().year),
                "{phone}": f"+1{random.randint(200,999)}{random.randint(100,999)}{random.randint(1000,9999)}",
                "{duration}": str(random.randint(30, 180)),
                "{time}": datetime.now().strftime("%I:%M %p"),
            }

            subject = _apply_placeholders(tpl_subject, placeholders)
            body = _apply_placeholders(tpl_body, placeholders)

            send_ok = _send_simulation_email(email, subject, body, campaign_id)
            if send_ok:
                c.execute(
                    "UPDATE campaign_targets SET status = 'sent', sent_at = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(), tid),
                )
                sent += 1

        c.execute(
            "UPDATE campaigns SET sent_count = ?, status = 'active', launched_at = ? WHERE id = ?",
            (sent, datetime.now(timezone.utc).isoformat(), campaign_id),
        )
        conn.commit()
        return {"campaign_id": campaign_id, "sent": sent, "total": len(targets)}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        conn.close()


def record_open(campaign_id: int, target_email: str) -> bool:
    init_campaign_tables()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            "UPDATE campaign_targets SET opened_at = COALESCE(opened_at, ?), status = 'opened' "
            "WHERE campaign_id = ? AND email = ? AND opened_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), campaign_id, target_email),
        )
        if c.rowcount > 0:
            c.execute("UPDATE campaigns SET opened_count = opened_count + 1 WHERE id = ?", (campaign_id,))
            conn.commit()
            return True
        return False
    finally:
        conn.close()


def record_click(campaign_id: int, target_email: str) -> bool:
    init_campaign_tables()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            "UPDATE campaign_targets SET clicked_at = COALESCE(clicked_at, ?), status = 'clicked' "
            "WHERE campaign_id = ? AND email = ? AND clicked_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), campaign_id, target_email),
        )
        if c.rowcount > 0:
            c.execute("UPDATE campaigns SET clicked_count = clicked_count + 1 WHERE id = ?", (campaign_id,))
            conn.commit()
            return True
        return False
    finally:
        conn.close()


def get_campaigns(status: Optional[str] = None) -> list:
    init_campaign_tables()
    conn = get_connection()
    c = conn.cursor()
    if status:
        c.execute(
            "SELECT id, name, template_name, target_count, sent_count, opened_count, clicked_count, "
            "reported_count, status, created_by, created_at, launched_at FROM campaigns WHERE status = ? ORDER BY id DESC",
            (status,),
        )
    else:
        c.execute(
            "SELECT id, name, template_name, target_count, sent_count, opened_count, clicked_count, "
            "reported_count, status, created_by, created_at, launched_at FROM campaigns ORDER BY id DESC"
        )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "name": r[1], "template_name": r[2], "target_count": r[3],
            "sent_count": r[4], "opened_count": r[5], "clicked_count": r[6],
            "reported_count": r[7], "status": r[8], "created_by": r[9],
            "created_at": r[10], "launched_at": r[11],
        }
        for r in rows
    ]


def get_campaign_results(campaign_id: int) -> list:
    init_campaign_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT email, first_name, last_name, department, status, sent_at, opened_at, clicked_at, reported_at "
        "FROM campaign_targets WHERE campaign_id = ? ORDER BY id",
        (campaign_id,),
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "email": r[0], "first_name": r[1], "last_name": r[2], "department": r[3],
            "status": r[4], "sent_at": r[5], "opened_at": r[6], "clicked_at": r[7],
            "reported_at": r[8],
        }
        for r in rows
    ]


def _send_simulation_email(to_email: str, subject: str, body: str, campaign_id: int) -> bool:
    smtp_cfg = {
        "host": ENV.SMTP_HOST,
        "port": ENV.SMTP_PORT,
        "username": ENV.SMTP_USER,
        "password": ENV.SMTP_PASS,
        "from": ENV.SMTP_FROM or ENV.SMTP_USER,
    }
    if not smtp_cfg["username"] or not smtp_cfg["password"]:
        logger.warning("SMTP not configured — simulation email logged but not sent (campaign %s)", campaign_id)
        return True  # Log as sent in simulation mode

    track_pixel = (
        f'<img src="https://{ENV.APP_URL or "localhost"}/api/v1/campaign/track/open?'
        f'cid={campaign_id}&email={to_email}" width="1" height="1" />'
    )
    html_body = body.replace("\n", "<br>\n") + track_pixel

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"PhishGuard Simulation <{smtp_cfg['from']}>"
    msg["To"] = to_email
    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        import smtplib
        with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_cfg["username"], smtp_cfg["password"])
            server.sendmail(smtp_cfg["from"], [to_email], msg.as_string())
        return True
    except Exception as exc:
        logger.error("Failed to send simulation email to %s: %s", to_email, exc)
        return False


def _apply_placeholders(text: str, placeholders: dict) -> str:
    for key, val in placeholders.items():
        text = text.replace(key, val)
    return text


def secrets_token(length: int = 32) -> str:
    import secrets
    return secrets.token_hex(length // 2 + 1)[:length]
