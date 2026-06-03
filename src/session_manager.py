"""Session Management — track and revoke active sessions."""

import hashlib
import logging
import time

from src.db import get_connection

logger = logging.getLogger("session-mgr")
SESSION_TTL = 1800


def init_sessions_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT UNIQUE NOT NULL,
            username    TEXT NOT NULL,
            ip_address  TEXT DEFAULT '',
            user_agent  TEXT DEFAULT '',
            created_at  REAL NOT NULL,
            last_seen   REAL NOT NULL,
            is_active   INTEGER DEFAULT 1
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (username)")
    conn.commit()
    conn.close()


def create_session(username: str, ip_address: str = "", user_agent: str = "") -> str:
    init_sessions_table()
    raw = f"{username}{time.time()}{ip_address}"
    session_id = hashlib.sha256(raw.encode()).hexdigest()[:24]
    now = time.time()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO sessions (session_id, username, ip_address, user_agent, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, username, ip_address, user_agent, now, now),
    )
    conn.commit()
    conn.close()
    return session_id


def touch_session(session_id: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sessions SET last_seen = ? WHERE session_id = ? AND is_active = 1",
              (time.time(), session_id))
    conn.commit()
    conn.close()


def revoke_session(session_id: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sessions SET is_active = 0 WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()


def revoke_all_sessions(username: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sessions SET is_active = 0 WHERE username = ? AND is_active = 1", (username,))
    conn.commit()
    conn.close()


def list_sessions(username: str) -> list:
    init_sessions_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, session_id, ip_address, user_agent, created_at, last_seen, is_active FROM sessions "
        "WHERE username = ? ORDER BY last_seen DESC LIMIT 20",
        (username,),
    )
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "session_id": r[1][:12] + "...", "ip": r[2], "ua": r[3],
         "created_at": r[4], "last_seen": r[5], "is_active": bool(r[6])}
        for r in rows
    ]


def cleanup_expired():
    init_sessions_table()
    cutoff = time.time() - SESSION_TTL
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sessions SET is_active = 0 WHERE last_seen < ? AND is_active = 1", (cutoff,))
    conn.commit()
    conn.close()
