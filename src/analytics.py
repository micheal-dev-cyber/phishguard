"""
PhishGuard AI — Product Analytics
Tracks key user events for conversion, activation, retention, and revenue.
"""
import logging
import time
from datetime import datetime

from src.db import get_connection

logger = logging.getLogger("analytics")

EVENT_TABLE = "product_events"


def init_analytics_db():
    """Create the analytics events table if it doesn't exist."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {EVENT_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            username TEXT DEFAULT '',
            session_id TEXT DEFAULT '',
            metadata TEXT DEFAULT '{{}}',
            ip_address TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            timestamp REAL NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute(f"""
        CREATE INDEX IF NOT EXISTS idx_events_event ON {EVENT_TABLE} (event)
    """)
    c.execute(f"""
        CREATE INDEX IF NOT EXISTS idx_events_username ON {EVENT_TABLE} (username)
    """)
    c.execute(f"""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON {EVENT_TABLE} (timestamp)
    """)
    conn.commit()
    conn.close()


def track_event(
    event: str,
    username: str = "",
    session_id: str = "",
    metadata: dict = None,
    ip_address: str = "",
    user_agent: str = "",
):
    """Track a product event."""
    import json
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute(f"""
            INSERT INTO {EVENT_TABLE}
            (event, username, session_id, metadata, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event,
            username,
            session_id,
            json.dumps(metadata or {}),
            ip_address,
            user_agent,
            time.time(),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("Failed to track event %s: %s", event, e)


# ── Convenience wrappers ────────────────────────────────────

def track_page_view(page: str, username: str = "", **kwargs):
    track_event("page_view", username, metadata={"page": page, **kwargs})


def track_signup(username: str, **kwargs):
    track_event("signup", username, metadata=kwargs)


def track_verification(username: str, **kwargs):
    track_event("email_verified", username, metadata=kwargs)


def track_login(username: str, **kwargs):
    track_event("login", username, metadata=kwargs)


def track_first_scan(username: str, **kwargs):
    track_event("first_scan", username, metadata=kwargs)


def track_scan(username: str, risk_score: int = 0, severity: str = "", **kwargs):
    track_event("scan", username, metadata={"risk_score": risk_score, "severity": severity, **kwargs})


def track_demo_scan(**kwargs):
    track_event("demo_scan", metadata=kwargs)


def track_pdf_download(username: str, **kwargs):
    track_event("pdf_download", username, metadata=kwargs)


def track_upgrade_click(username: str, plan: str = "", **kwargs):
    track_event("upgrade_click", username, metadata={"plan": plan, **kwargs})


def track_subscription(username: str, plan: str = "", status: str = "", **kwargs):
    track_event("subscription", username, metadata={"plan": plan, "status": status, **kwargs})


# ── Analytics queries ────────────────────────────────────────

def get_analytics_summary(days: int = 30) -> dict:
    """Get a summary of key metrics for the given period."""
    conn = get_connection()
    c = conn.cursor()
    cutoff = time.time() - (days * 86400)

    result = {}

    # Total events
    c.execute(f"SELECT COUNT(*) FROM {EVENT_TABLE} WHERE timestamp >= ?", (cutoff,))
    result["total_events"] = c.fetchone()[0]

    # Event breakdown
    c.execute(f"""
        SELECT event, COUNT(*) as cnt FROM {EVENT_TABLE}
        WHERE timestamp >= ?
        GROUP BY event ORDER BY cnt DESC
    """, (cutoff,))
    result["events_by_type"] = dict(c.fetchall())

    # Unique users
    c.execute(f"""
        SELECT COUNT(DISTINCT username) FROM {EVENT_TABLE}
        WHERE timestamp >= ? AND username != ''
    """, (cutoff,))
    result["active_users"] = c.fetchone()[0]

    # Daily active users (last 7 days)
    week_cutoff = time.time() - 604800
    c.execute(f"""
        SELECT DATE(created_at) as day, COUNT(DISTINCT username) as dau
        FROM {EVENT_TABLE}
        WHERE timestamp >= ? AND username != ''
        GROUP BY day ORDER BY day
    """, (week_cutoff,))
    result["dau_trend"] = [{"date": r[0], "users": r[1]} for r in c.fetchall()]

    # Conversion funnel (last 30 days)
    c.execute(f"""
        SELECT
            COUNT(DISTINCT CASE WHEN event='signup' THEN username END) as signups,
            COUNT(DISTINCT CASE WHEN event='email_verified' THEN username END) as verified,
            COUNT(DISTINCT CASE WHEN event='login' THEN username END) as logged_in,
            COUNT(DISTINCT CASE WHEN event='first_scan' THEN username END) as first_scan
        FROM {EVENT_TABLE}
        WHERE timestamp >= ?
    """, (cutoff,))
    row = c.fetchone()
    result["funnel"] = {
        "signups": row[0],
        "verified": row[1],
        "logged_in": row[2],
        "first_scan": row[3],
    }

    # Signup → verify conversion
    if result["funnel"]["signups"] > 0:
        result["funnel"]["verify_rate"] = round(
            result["funnel"]["verified"] / result["funnel"]["signups"] * 100, 1
        )
    else:
        result["funnel"]["verify_rate"] = 0

    # Verify → first scan conversion
    if result["funnel"]["verified"] > 0:
        result["funnel"]["activation_rate"] = round(
            result["funnel"]["first_scan"] / result["funnel"]["verified"] * 100, 1
        )
    else:
        result["funnel"]["activation_rate"] = 0

    conn.close()
    return result


def get_top_events(limit: int = 50):
    """Get most recent events."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        SELECT event, username, metadata, timestamp, created_at
        FROM {EVENT_TABLE}
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_retention_cohort(days: int = 60) -> dict:
    """Calculate user retention: how many users return after their first scan."""
    conn = get_connection()
    c = conn.cursor()

    # Get users who signed up in the window
    cutoff = time.time() - (days * 86400)
    c.execute(f"""
        SELECT DISTINCT username FROM {EVENT_TABLE}
        WHERE event = 'first_scan' AND timestamp >= ?
    """, (cutoff,))
    first_scan_users = [r[0] for r in c.fetchall()]

    if not first_scan_users:
        conn.close()
        return {"users_with_first_scan": 0, "returned_day_1": 0, "returned_day_7": 0}

    # Check who returned after day 1 and day 7
    returned_d1 = 0
    returned_d7 = 0
    for user in first_scan_users:
        c.execute(f"""
            SELECT timestamp FROM {EVENT_TABLE}
            WHERE username = ? AND event = 'scan'
            ORDER BY timestamp ASC LIMIT 1
        """, (user,))
        first = c.fetchone()
        if not first:
            continue
        first_ts = first[0]

        # Day 1: 24h-48h after first scan
        d1_start = first_ts + 86400
        d1_end = first_ts + 172800
        c.execute(f"""
            SELECT COUNT(*) FROM {EVENT_TABLE}
            WHERE username = ? AND event IN ('scan', 'page_view')
            AND timestamp BETWEEN ? AND ?
        """, (user, d1_start, d1_end))
        if c.fetchone()[0] > 0:
            returned_d1 += 1

        # Day 7: 7-8 days after
        d7_start = first_ts + 604800
        d7_end = first_ts + 691200
        c.execute(f"""
            SELECT COUNT(*) FROM {EVENT_TABLE}
            WHERE username = ? AND event IN ('scan', 'page_view', 'login')
            AND timestamp BETWEEN ? AND ?
        """, (user, d7_start, d7_end))
        if c.fetchone()[0] > 0:
            returned_d7 += 1

    conn.close()
    return {
        "users_with_first_scan": len(first_scan_users),
        "returned_day_1": returned_d1,
        "returned_day_7": returned_d7,
        "day_1_retention_pct": round(returned_d1 / len(first_scan_users) * 100, 1) if first_scan_users else 0,
        "day_7_retention_pct": round(returned_d7 / len(first_scan_users) * 100, 1) if first_scan_users else 0,
    }
