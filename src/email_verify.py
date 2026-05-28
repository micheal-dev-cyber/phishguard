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
    except Exception:
        return True


def send_verification_email(email: str, verify_url: str) -> dict:
    from src.env import ENV
    smtp_host = ENV.SMTP_HOST
    smtp_port = ENV.SMTP_PORT
    smtp_user = ENV.SMTP_USER
    smtp_pass = ENV.SMTP_PASS
    smtp_from = ENV.SMTP_FROM or smtp_user

    if not smtp_user or not smtp_pass:
        return {"success": False, "error": "SMTP not configured"}

    msg = MIMEText(
        f"Welcome to PhishGuard!\n\nPlease verify your email by clicking the link below:\n\n{verify_url}\n\n"
        f"This link expires in 24 hours."
    )
    msg["Subject"] = "PhishGuard — Verify Your Email"
    msg["From"] = smtp_from
    msg["To"] = email

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info("Verification email sent to %s", email)
        return {"success": True}
    except Exception as e:
        logger.error("Failed to send verification email: %s", e)
        return {"success": False, "error": str(e)}
