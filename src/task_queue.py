import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from src.db import get_connection

logger = logging.getLogger("task-queue")

_registry: dict[str, Callable] = {}


def register_task(name: str, func: Callable):
    _registry[name] = func


def init_task_queue():
    conn = get_connection()
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
    conn = get_connection()
    c = conn.cursor()
    scheduled = (datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)).strftime("%Y-%m-%d %H:%M:%S")
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
            conn = get_connection()
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
            except Exception as e:
                logger.warning("task_queue: Failed to close connection: %s", e)
        time.sleep(2)


def _update_status(task_id: int, status: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "UPDATE task_queue SET status=?, completed_at=datetime('now') WHERE id=?",
        (status, task_id),
    )
    conn.commit()
    conn.close()


def _set_error(task_id: int, error: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE task_queue SET error=? WHERE id=?", (error, task_id))
    conn.commit()
    conn.close()


def _handle_failure(task_id: int, error: str):
    conn = get_connection()
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
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM task_queue WHERE status='pending'")
    count = c.fetchone()[0]
    conn.close()
    return count


def get_task_status(task_id: int) -> Optional[str]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT status FROM task_queue WHERE id=?", (task_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


def wait_for_completion(task_id: int, timeout: float = 10.0, poll_interval: float = 0.5) -> Optional[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = get_task_status(task_id)
        if status in ("completed", "failed"):
            return status
        time.sleep(poll_interval)
    return None


def get_failed_tasks(limit: int = 20) -> list:
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, task_name, error, created_at, retry_count FROM task_queue WHERE status='failed' ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = c.fetchall()
    conn.close()
    return rows


def get_tasks(limit: int = 50, status: Optional[str] = None) -> list:
    conn = get_connection()
    c = conn.cursor()
    if status:
        c.execute(
            "SELECT id, task_name, status, error, created_at, started_at, completed_at, retry_count FROM task_queue WHERE status=? ORDER BY id DESC LIMIT ?",
            (status, limit),
        )
    else:
        c.execute(
            "SELECT id, task_name, status, error, created_at, started_at, completed_at, retry_count FROM task_queue ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


_RESULTS_TABLE = "task_results"


def _init_results():
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {_RESULTS_TABLE} (
            task_id INTEGER PRIMARY KEY,
            result TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def store_result(task_id: int, result: dict):
    _init_results()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"INSERT OR REPLACE INTO {_RESULTS_TABLE} (task_id, result) VALUES (?, ?)",
        (task_id, json.dumps(result)),
    )
    conn.commit()
    conn.close()


def get_task_result(task_id: int) -> Optional[dict]:
    _init_results()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"SELECT result FROM {_RESULTS_TABLE} WHERE task_id=?", (task_id,))
    row = c.fetchone()
    conn.close()
    return json.loads(row[0]) if row else None
