import sqlite3
import threading
import time
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("task-queue")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"

_registry: dict[str, Callable] = {}


def register_task(name: str, func: Callable):
    _registry[name] = func


def init_task_queue():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS task_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT NOT NULL,
            payload TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT (datetime('now')),
            scheduled_for TEXT,
            started_at TEXT,
            completed_at TEXT,
            error TEXT,
            retry_count INTEGER DEFAULT 0,
            max_retries INTEGER DEFAULT 3
        )
    """)
    conn.commit()
    conn.close()


def enqueue(task_name: str, payload: Optional[dict] = None,
            delay_seconds: int = 0, max_retries: int = 3) -> int:
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    scheduled = (datetime.utcnow() + timedelta(seconds=delay_seconds)).isoformat()
    c.execute(
        "INSERT INTO task_queue (task_name, payload, status, scheduled_for, max_retries) VALUES (?, ?, 'pending', ?, ?)",
        (task_name, json.dumps(payload or {}), scheduled, max_retries),
    )
    conn.commit()
    task_id = c.lastrowid
    conn.close()
    logger.info("Enqueued task %s #%d scheduled at %s", task_name, task_id, scheduled)
    return task_id


def _worker():
    while True:
        try:
            conn = sqlite3.connect(str(DB_PATH))
            c = conn.cursor()
            c.execute(
                """UPDATE task_queue SET status='running', started_at=datetime('now')
                   WHERE id IN (
                       SELECT id FROM task_queue
                       WHERE status='pending' AND scheduled_for <= datetime('now')
                       ORDER BY created_at ASC LIMIT 1
                   ) RETURNING id, task_name, payload""",
            )
            row = c.fetchone()
            if row:
                task_id, task_name, payload_json = row
                conn.commit()
                conn.close()

                payload = json.loads(payload_json) if payload_json else {}
                handler = _registry.get(task_name)
                if handler:
                    try:
                        handler(payload)
                        _update_status(task_id, "completed")
                        logger.info("Task #%d (%s) completed", task_id, task_name)
                    except Exception as e:
                        logger.error("Task #%d (%s) failed: %s", task_id, task_name, e)
                        _handle_failure(task_id, str(e))
                else:
                    _update_status(task_id, "failed")
                    _set_error(task_id, f"No handler registered for '{task_name}'")
            else:
                conn.close()
        except Exception as e:
            logger.error("Task queue worker error: %s", e)
            try:
                conn.close()
            except Exception:
                pass
        time.sleep(2)


def _update_status(task_id: int, status: str):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "UPDATE task_queue SET status=?, completed_at=datetime('now') WHERE id=?",
        (status, task_id),
    )
    conn.commit()
    conn.close()


def _set_error(task_id: int, error: str):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("UPDATE task_queue SET error=? WHERE id=?", (error, task_id))
    conn.commit()
    conn.close()


def _handle_failure(task_id: int, error: str):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "SELECT retry_count, max_retries FROM task_queue WHERE id=?",
        (task_id,),
    )
    row = c.fetchone()
    if row:
        retry_count, max_retries = row
        if retry_count < max_retries:
            c.execute(
                "UPDATE task_queue SET status='pending', retry_count=retry_count+1, error=?, scheduled_for=datetime('now', '+30 seconds') WHERE id=?",
                (error, task_id),
            )
        else:
            c.execute(
                "UPDATE task_queue SET status='failed', error=?, completed_at=datetime('now') WHERE id=?",
                (error, task_id),
            )
    conn.commit()
    conn.close()


_thread = None


def start_worker():
    global _thread
    if _thread and _thread.is_alive():
        return
    init_task_queue()
    _thread = threading.Thread(target=_worker, daemon=True, name="task-queue-worker")
    _thread.start()
    logger.info("Task queue worker started")


def get_pending_count() -> int:
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM task_queue WHERE status='pending'")
    count = c.fetchone()[0]
    conn.close()
    return count


def get_failed_tasks(limit: int = 20) -> list:
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "SELECT id, task_name, error, created_at, retry_count FROM task_queue WHERE status='failed' ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = c.fetchall()
    conn.close()
    return rows
