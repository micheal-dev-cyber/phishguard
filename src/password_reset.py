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
    from src.email_templates import render_html, send_html_email
    html = render_html("reset", reset_url=reset_url)
    if not html:
        return {"success": False, "error": "Template not found"}
    return send_html_email(email, "PhishGuard — Password Reset", html)
