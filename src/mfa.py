"""Multi-Factor Authentication — TOTP-based 2FA for admin accounts."""

import base64
import hashlib
import hmac
import logging
import secrets
import struct
import time

from src.db import get_connection

logger = logging.getLogger("mfa")
TOTP_INTERVAL = 30


def _init_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS mfa_secrets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            secret      TEXT NOT NULL,
            enabled     INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def _generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def is_mfa_enabled(username: str) -> bool:
    _init_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT enabled FROM mfa_secrets WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return bool(row and row[0])


def setup_mfa(username: str) -> dict:
    _init_table()
    secret = _generate_secret()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO mfa_secrets (username, secret, enabled) VALUES (?, ?, 0)",
        (username, secret),
    )
    conn.commit()
    conn.close()

    issuer = "PhishGuard AI"
    uri = f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period={TOTP_INTERVAL}"
    return {"secret": secret, "uri": uri}


def enable_mfa(username: str, code: str) -> bool:
    if not verify_totp(username, code):
        return False
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE mfa_secrets SET enabled = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    logger.info("MFA enabled for %s", username)
    return True


def disable_mfa(username: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM mfa_secrets WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    logger.info("MFA disabled for %s", username)


_mfa_attempts: dict = {}


def verify_totp(username: str, code: str) -> bool:
    now = time.time()
    attempts = _mfa_attempts.get(username, [])
    attempts = [t for t in attempts if t > now - 30]
    if len(attempts) >= 5:
        return False
    attempts.append(now)
    _mfa_attempts[username] = attempts

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT secret FROM mfa_secrets WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    secret = row[0]
    expected = _compute_totp(secret)
    return hmac.compare_digest(code, expected)


def _compute_totp(secret: str) -> str:
    counter = int(time.time()) // TOTP_INTERVAL
    msg = struct.pack(">Q", counter)
    key = base64.b32decode(secret)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1000000:06d}"
