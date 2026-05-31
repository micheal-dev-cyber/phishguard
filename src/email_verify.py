"""Email Verification — token-based email confirmation for new signups."""

import logging
import secrets
import time
import sqlite3
import smtplib
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger("email-verify")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"
VERIFY_TOKEN_TTL = 86400  # 24 hours


def _init_table():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_verifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            email       TEXT NOT NULL,
            token       TEXT UNIQUE NOT NULL,
            expires_at  REAL NOT NULL,
            verified    INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def create_verification(username: str, email: str) -> dict:
    _init_table()
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + VERIFY_TOKEN_TTL
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT INTO email_verifications (username, email, token, expires_at) VALUES (?, ?, ?, ?)",
        (username, email, token, expires_at),
    )
    conn.commit()
    conn.close()
    return {"token": token, "email": email}


def verify_email_token(token: str) -> bool:
    _init_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "SELECT username, expires_at, verified FROM email_verifications WHERE token = ?",
        (token,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    username, expires_at, verified = row
    if verified or time.time() > expires_at:
        conn.close()
        return False
    c.execute("UPDATE email_verifications SET verified = 1 WHERE token = ?", (token,))
    c.execute("UPDATE tenants SET email_verified = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    logger.info("Email verified for %s", username)
    return True


def is_email_verified(username: str) -> bool:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        c = conn.cursor()
        c.execute("SELECT email_verified FROM tenants WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        return bool(row and row[0])
    except Exception as e:
        logger.warning("email_verify: Failed to check verification status for %s: %s", username, e)
        return True


def send_verification_email(email: str, verify_url: str) -> dict:
    from src.email_templates import render_html, send_html_email
    html = render_html("verify", verify_url=verify_url)
    if not html:
        return {"success": False, "error": "Template not found"}
    return send_html_email(email, "PhishGuard — Verify Your Email", html)


def send_welcome_email(email: str, username: str, quota: int, app_url: str) -> dict:
    from src.email_templates import render_html, send_html_email
    html = render_html("welcome", username=username, quota=quota, app_url=app_url)
    if not html:
        return {"success": False, "error": "Template not found"}
    return send_html_email(email, "Welcome to PhishGuard 🛡", html)
