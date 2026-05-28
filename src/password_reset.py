"""Password Reset — token generation, expiry, email delivery."""

import logging
import secrets
import time
import sqlite3
import smtplib
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger("password-reset")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"
RESET_TOKEN_TTL = 3600  # 1 hour


def _init_table():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            email       TEXT NOT NULL,
            token       TEXT UNIQUE NOT NULL,
            expires_at  REAL NOT NULL,
            used        INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def create_reset_token(username: str, email: str) -> dict:
    _init_table()
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + RESET_TOKEN_TTL
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT INTO password_reset_tokens (username, email, token, expires_at) VALUES (?, ?, ?, ?)",
        (username, email, token, expires_at),
    )
    conn.commit()
    conn.close()
    return {"token": token, "expires_at": expires_at, "email": email}


def verify_reset_token(token: str) -> dict:
    _init_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "SELECT username, email, expires_at, used FROM password_reset_tokens WHERE token = ?",
        (token,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return {"valid": False, "error": "Token not found"}
    username, email, expires_at, used = row
    if used:
        return {"valid": False, "error": "Token already used"}
    if time.time() > expires_at:
        return {"valid": False, "error": "Token expired"}
    return {"valid": True, "username": username, "email": email}


def mark_token_used(token: str):
    _init_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def send_reset_email(email: str, reset_url: str) -> dict:
    from src.env import ENV
    smtp_host = ENV.SMTP_HOST
    smtp_port = ENV.SMTP_PORT
    smtp_user = ENV.SMTP_USER
    smtp_pass = ENV.SMTP_PASS
    smtp_from = ENV.SMTP_FROM or smtp_user

    if not smtp_user or not smtp_pass:
        return {"success": False, "error": "SMTP not configured"}

    msg = MIMEText(
        f"Click the link below to reset your PhishGuard password:\n\n{reset_url}\n\n"
        f"This link expires in 1 hour. If you did not request this, ignore this email."
    )
    msg["Subject"] = "PhishGuard — Password Reset"
    msg["From"] = smtp_from
    msg["To"] = email

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        logger.info("Password reset email sent to %s", email)
        return {"success": True}
    except Exception as e:
        logger.error("Failed to send reset email: %s", e)
        return {"success": False, "error": str(e)}
