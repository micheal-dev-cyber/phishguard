"""Notification Center — in-app notification history."""

import logging

from src.db import get_connection

logger = logging.getLogger("notifications")


def init_notifications_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            title       TEXT NOT NULL,
            message     TEXT NOT NULL,
            severity    TEXT DEFAULT 'info' CHECK(severity IN ('info','warning','critical','success')),
            is_read     INTEGER DEFAULT 0,
            link        TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications (username, is_read)")
    conn.commit()
    conn.close()


def push_notification(username: str, title: str, message: str, severity: str = "info", link: str = ""):
    init_notifications_table()
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO notifications (username, title, message, severity, link) VALUES (?, ?, ?, ?, ?)",
            (username, title, message, severity, link),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Failed to push notification: %s", e)


def get_notifications(username: str, limit: int = 50) -> list:
    init_notifications_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, title, message, severity, is_read, link, created_at FROM notifications "
        "WHERE username = ? ORDER BY created_at DESC LIMIT ?",
        (username, limit),
    )
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "title": r[1], "message": r[2], "severity": r[3],
         "is_read": bool(r[4]), "link": r[5], "created_at": r[6]}
        for r in rows
    ]


def mark_read(notification_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
    conn.commit()
    conn.close()


def mark_all_read(username: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE notifications SET is_read = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def unread_count(username: str) -> int:
    init_notifications_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM notifications WHERE username = ? AND is_read = 0", (username,))
    count = c.fetchone()[0]
    conn.close()
    return count
