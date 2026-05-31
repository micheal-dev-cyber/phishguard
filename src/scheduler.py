"""
Scheduled / recurring scan system.

Uses the task queue to schedule periodic email analysis for connected mailboxes.
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from src.db import DB_PATH, get_connection

logger = logging.getLogger("scheduler")
SCHEDULE_TABLE = "scan_schedules"


def init_scheduler():
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {SCHEDULE_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            mailbox TEXT NOT NULL DEFAULT 'inbox',
            interval_minutes INTEGER NOT NULL DEFAULT 60,
            max_per_run INTEGER NOT NULL DEFAULT 10,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(username, mailbox)
        )
    """)
    conn.commit()
    conn.close()


def create_schedule(username: str, mailbox: str = "inbox",
                    interval_minutes: int = 60, max_per_run: int = 10) -> int:
    init_scheduler()
    next_run = (datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)).isoformat()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"INSERT OR REPLACE INTO {SCHEDULE_TABLE} "
        "(username, mailbox, interval_minutes, max_per_run, enabled, next_run) "
        "VALUES (?, ?, ?, ?, 1, ?)",
        (username, mailbox, interval_minutes, max_per_run, next_run),
    )
    conn.commit()
    schedule_id = c.lastrowid
    conn.close()
    logger.info("Created scan schedule #%d for %s (every %d min)", schedule_id, username, interval_minutes)
    return schedule_id


def delete_schedule(schedule_id: int) -> bool:
    init_scheduler()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"DELETE FROM {SCHEDULE_TABLE} WHERE id=?", (schedule_id,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def list_schedules(username: Optional[str] = None) -> list[dict]:
    init_scheduler()
    conn = get_connection()
    c = conn.cursor()
    if username:
        c.execute(f"SELECT * FROM {SCHEDULE_TABLE} WHERE username=? ORDER BY created_at DESC", (username,))
    else:
        c.execute(f"SELECT * FROM {SCHEDULE_TABLE} ORDER BY username, created_at DESC")
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def toggle_schedule(schedule_id: int, enabled: bool) -> bool:
    init_scheduler()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"UPDATE {SCHEDULE_TABLE} SET enabled=? WHERE id=?", (1 if enabled else 0, schedule_id))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def get_due_schedules() -> list[dict]:
    init_scheduler()
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"SELECT * FROM {SCHEDULE_TABLE} WHERE enabled=1 AND (next_run IS NULL OR next_run <= ?) ORDER BY next_run ASC",
        (now,),
    )
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def mark_run(schedule_id: int, interval_minutes: int):
    now = datetime.now(timezone.utc)
    next_run = (now + timedelta(minutes=interval_minutes)).isoformat()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE {SCHEDULE_TABLE} SET last_run=?, next_run=? WHERE id=?",
        (now.isoformat(), next_run, schedule_id),
    )
    conn.commit()
    conn.close()


def run_due_scans():
    due = get_due_schedules()
    for s in due:
        try:
            from src.task_queue import enqueue
            enqueue("scan_mailbox", {
                "username": s["username"],
                "mailbox": s["mailbox"],
                "max_per_run": s["max_per_run"],
            }, delay_seconds=0)
            mark_run(s["id"], s["interval_minutes"])
            logger.info("Scheduled scan for %s (%s)", s["username"], s["mailbox"])
        except Exception as e:
            logger.error("Failed to schedule scan for %s: %s", s["username"], e)
