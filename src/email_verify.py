"""Email Verification — token-based email confirmation for new signups."""

import hashlib
import logging
import secrets
import time

from src.db import get_connection

logger = logging.getLogger("email-verify")
VERIFY_TOKEN_TTL = 86400  # 24 hours


def _init_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_verifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            email       TEXT NOT NULL,
            token_hash  TEXT UNIQUE NOT NULL,
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
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = time.time() + VERIFY_TOKEN_TTL
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO email_verifications (username, email, token_hash, expires_at) VALUES (?, ?, ?, ?)",
        (username, email, token_hash, expires_at),
    )
    conn.commit()
    conn.close()
    return {"token": token, "email": email}


def verify_email_token(token: str) -> bool:
    _init_table()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT username, expires_at, verified FROM email_verifications WHERE token_hash = ?",
        (token_hash,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    username, expires_at, verified = row
    if verified or time.time() > expires_at:
        conn.close()
        return False
    c.execute("UPDATE email_verifications SET verified = 1 WHERE token_hash = ?", (token_hash,))
    c.execute("UPDATE tenants SET email_verified = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    logger.info("Email verified for %s", username)
    return True


def is_email_verified(username: str) -> bool:
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT email_verified FROM tenants WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        return bool(row and row[0])
    except Exception as e:
        logger.warning("email_verify: Failed to check verification status for %s: %s", username, e)
        return True


def send_verification_email(email: str, verify_url: str) -> dict:
    from src.email_templates import render_html
    from src.email_test_backend import send_via_backend
    html = render_html("verify", verify_url=verify_url)
    if not html:
        return {"success": False, "error": "Template not found"}
    return send_via_backend(email, "PhishGuard — Verify Your Email", html, template="verify")


def send_welcome_email(email: str, username: str, quota: int, app_url: str) -> dict:
    from src.email_templates import render_html
    from src.email_test_backend import send_via_backend
    html = render_html("welcome", username=username, quota=quota, app_url=app_url)
    if not html:
        return {"success": False, "error": "Template not found"}
    return send_via_backend(email, "Welcome to PhishGuard 🛡", html, template="welcome")
