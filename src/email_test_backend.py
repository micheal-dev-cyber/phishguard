import json
import logging
import time

from src.db import get_connection
from src.env import ENV

logger = logging.getLogger("email-test-backend")


EMAIL_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS email_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    to_addr     TEXT NOT NULL,
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    template    TEXT,
    created_at  REAL NOT NULL,
    delivered   INTEGER DEFAULT 0
)
"""


def _init_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute(EMAIL_LOG_TABLE)
    conn.commit()
    conn.close()


def store_email(to_addr: str, subject: str, body: str, template: str = None) -> dict:
    _init_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO email_log (to_addr, subject, body, template, created_at, delivered) VALUES (?, ?, ?, ?, ?, 0)",
        (to_addr, subject, body, template, time.time()),
    )
    conn.commit()
    conn.close()
    logger.info("Test email stored for %s: %s", to_addr, subject)
    return {"success": True, "stored": True, "to": to_addr, "subject": subject, "template": template}


def get_all_emails(limit: int = 50) -> list:
    _init_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, to_addr, subject, template, created_at, delivered FROM email_log ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": row[0],
            "to": row[1],
            "subject": row[2],
            "template": row[3],
            "created_at": row[4],
            "delivered": bool(row[5]),
        }
        for row in rows
    ]


def get_email_body(email_id: int) -> str:
    _init_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT body FROM email_log WHERE id = ?", (email_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ""


def clear_email_log():
    _init_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM email_log")
    conn.commit()
    conn.close()


def send_via_backend(to_addr: str, subject: str, html_body: str, template: str = None) -> dict:
    from src.smtp_validation import smtp_configured
    from src.email_templates import send_html_email

    if smtp_configured():
        result = send_html_email(to_addr, subject, html_body)
        if result.get("success"):
            _init_table()
            conn = get_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO email_log (to_addr, subject, body, template, created_at, delivered) VALUES (?, ?, ?, ?, ?, 1)",
                (to_addr, subject, html_body, template, time.time()),
            )
            conn.commit()
            conn.close()
        return result
    else:
        return store_email(to_addr, subject, html_body, template)
