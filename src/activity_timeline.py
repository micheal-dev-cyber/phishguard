"""
User activity timeline — per-user audit trail for compliance and monitoring.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from src.db import DB_PATH, get_connection

logger = logging.getLogger("activity_timeline")
ACTIVITY_TABLE = "activity_timeline"


def init_activity_timeline():
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {ACTIVITY_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            severity TEXT DEFAULT 'info',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute(f"CREATE INDEX IF NOT EXISTS idx_activity_username ON {ACTIVITY_TABLE}(username)")
    c.execute(f"CREATE INDEX IF NOT EXISTS idx_activity_created ON {ACTIVITY_TABLE}(created_at)")
    conn.commit()
    conn.close()


def record_activity(username: str, action: str, detail: str = "",
                    ip_address: str = "", user_agent: str = "",
                    severity: str = "info"):
    init_activity_timeline()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"INSERT INTO {ACTIVITY_TABLE} (username, action, detail, ip_address, user_agent, severity) VALUES (?, ?, ?, ?, ?, ?)",
        (username, action, detail[:500], ip_address[:64], user_agent[:256], severity),
    )
    conn.commit()
    conn.close()


def get_activity(username: str, limit: int = 50, offset: int = 0,
                 action_filter: Optional[str] = None) -> list[dict]:
    init_activity_timeline()
    conn = get_connection()
    c = conn.cursor()
    if action_filter:
        c.execute(
            f"SELECT * FROM {ACTIVITY_TABLE} WHERE username=? AND action=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (username, action_filter, limit, offset),
        )
    else:
        c.execute(
            f"SELECT * FROM {ACTIVITY_TABLE} WHERE username=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (username, limit, offset),
        )
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def get_all_activity(limit: int = 100, offset: int = 0,
                     severity: Optional[str] = None) -> list[dict]:
    init_activity_timeline()
    conn = get_connection()
    c = conn.cursor()
    if severity:
        c.execute(
            f"SELECT * FROM {ACTIVITY_TABLE} WHERE severity=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (severity, limit, offset),
        )
    else:
        c.execute(
            f"SELECT * FROM {ACTIVITY_TABLE} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def get_activity_summary(username: str, days: int = 30) -> dict:
    init_activity_timeline()
    cutoff = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"SELECT action, COUNT(*) as cnt FROM {ACTIVITY_TABLE} "
        f"WHERE username=? AND created_at >= datetime('now', ? || ' days') "
        f"GROUP BY action ORDER BY cnt DESC",
        (username, f"-{days}"),
    )
    rows = c.fetchall()
    conn.close()
    return {r[0]: r[1] for r in rows}
