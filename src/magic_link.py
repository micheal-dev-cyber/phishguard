import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.db import DB_PATH, get_connection

logger = logging.getLogger("magic-link")


def init_magic_links():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS magic_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            used_at TEXT,
            ip_address TEXT
        )
    """)
    conn.commit()
    conn.close()


def generate_magic_link(email: str, expiry_minutes: int = 15) -> str:
    init_magic_links()
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)).isoformat()

    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO magic_links (email, token_hash, expires_at) VALUES (?, ?, ?)",
        (email, token_hash, expires_at),
    )
    conn.commit()
    conn.close()

    return token


def verify_magic_link(email: str, token: str, ip_address: Optional[str] = None) -> bool:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, expires_at, used_at FROM magic_links WHERE email=? AND token_hash=? ORDER BY created_at DESC LIMIT 1",
        (email, token_hash),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return False

    link_id, expires_at, used_at = row
    if used_at:
        conn.close()
        return False

    expires = datetime.fromisoformat(expires_at)
    if datetime.now(timezone.utc) > expires:
        conn.close()
        return False

    c.execute(
        "UPDATE magic_links SET used_at=datetime('now'), ip_address=? WHERE id=?",
        (ip_address, link_id),
    )
    conn.commit()
    conn.close()
    return True


def cleanup_expired_links():
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM magic_links WHERE expires_at < datetime('now') AND used_at IS NULL")
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted:
        logger.info("Cleaned up %d expired magic links", deleted)
