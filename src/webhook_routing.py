"""
Granular webhook routing — per-event-type webhook URLs.

Allows users to configure different webhook URLs for different event types
(e.g., critical_alerts, daily_digest, new_threat_intel, scan_complete).
"""
import logging
from typing import Optional

from src.db import get_connection

logger = logging.getLogger("webhook_routing")
ROUTES_TABLE = "webhook_routes"

EVENT_TYPES = [
    "critical_alert",
    "high_alert",
    "scan_complete",
    "daily_digest",
    "weekly_report",
    "new_threat_intel",
    "system_notification",
    "quarantine_event",
    "user_login",
    "api_key_created",
]


def init_webhook_routes():
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {ROUTES_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            event_type TEXT NOT NULL,
            webhook_url TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(username, event_type)
        )
    """)
    conn.commit()
    conn.close()


def set_webhook_route(username: str, event_type: str, webhook_url: str) -> bool:
    init_webhook_routes()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            f"INSERT OR REPLACE INTO {ROUTES_TABLE} (username, event_type, webhook_url, enabled) VALUES (?, ?, ?, 1)",
            (username, event_type, webhook_url),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error("Failed to set webhook route: %s", e)
        return False
    finally:
        conn.close()


def delete_webhook_route(username: str, event_type: str) -> bool:
    init_webhook_routes()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"DELETE FROM {ROUTES_TABLE} WHERE username=? AND event_type=?", (username, event_type))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def get_webhook_routes(username: Optional[str] = None) -> list[dict]:
    init_webhook_routes()
    conn = get_connection()
    c = conn.cursor()
    if username:
        c.execute(f"SELECT * FROM {ROUTES_TABLE} WHERE username=? ORDER BY event_type", (username,))
    else:
        c.execute(f"SELECT * FROM {ROUTES_TABLE} ORDER BY username, event_type")
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def get_webhook_url(username: str, event_type: str) -> Optional[str]:
    init_webhook_routes()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"SELECT webhook_url FROM {ROUTES_TABLE} WHERE username=? AND event_type=? AND enabled=1",
        (username, event_type),
    )
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


def dispatch_event(username: str, event_type: str, payload: dict):
    url = get_webhook_url(username, event_type)
    if not url:
        return
    try:
        from src.webhook_gateway import send_alert
        send_alert(url, payload=payload)
    except Exception as e:
        logger.error("Failed to dispatch %s for %s: %s", event_type, username, e)


def enable_route(route_id: int, enabled: bool) -> bool:
    init_webhook_routes()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"UPDATE {ROUTES_TABLE} SET enabled=? WHERE id=?", (1 if enabled else 0, route_id))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0
