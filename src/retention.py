"""Data Retention Policies — auto-purge old scans and logs."""

import logging
from datetime import datetime, timedelta

from src.db import get_connection

logger = logging.getLogger("retention")


def init_retention_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS retention_policies (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL UNIQUE,
            analysis_days INTEGER DEFAULT 90,
            audit_days    INTEGER DEFAULT 365,
            alert_days    INTEGER DEFAULT 180,
            enabled        INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


def get_retention_policy(username: str) -> dict:
    init_retention_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT analysis_days, audit_days, alert_days, enabled FROM retention_policies WHERE username = ?",
        (username,),
    )
    row = c.fetchone()
    conn.close()
    if row:
        return {"analysis_days": row[0], "audit_days": row[1], "alert_days": row[2], "enabled": bool(row[3])}
    return {"analysis_days": 90, "audit_days": 365, "alert_days": 180, "enabled": True}


def set_retention_policy(username: str, analysis_days: int, audit_days: int, alert_days: int):
    init_retention_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO retention_policies (username, analysis_days, audit_days, alert_days, enabled) VALUES (?, ?, ?, ?, 1)",
        (username, analysis_days, audit_days, alert_days),
    )
    conn.commit()
    conn.close()


def purge_old_data(username: str) -> dict:
    policy = get_retention_policy(username)
    if not policy["enabled"]:
        return {"purged": False, "reason": "Retention policy disabled"}
    cutoff_analysis = (datetime.now() - timedelta(days=policy["analysis_days"])).isoformat()
    cutoff_audit = (datetime.now() - timedelta(days=policy["audit_days"])).isoformat()
    cutoff_alerts = (datetime.now() - timedelta(days=policy["alert_days"])).isoformat()

    conn = get_connection()
    c = conn.cursor()
    counts = {}
    try:
        c.execute("DELETE FROM analyses WHERE timestamp < ?", (cutoff_analysis,))
        counts["analyses"] = c.rowcount
    except Exception as e:
        logger.warning("retention: Failed to purge analyses: %s", e)
        counts["analyses"] = 0
    try:
        c.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff_audit,))
        counts["audit"] = c.rowcount
    except Exception as e:
        logger.warning("retention: Failed to purge audit_log: %s", e)
        counts["audit"] = 0
    try:
        c.execute("DELETE FROM alert_log WHERE sent_at < ?", (cutoff_alerts,))
        counts["alerts"] = c.rowcount
    except Exception as e:
        logger.warning("retention: Failed to purge alert_log: %s", e)
        counts["alerts"] = 0
    conn.commit()
    conn.close()
    counts["purged"] = True
    logger.info("Purged %s for %s", counts, username)
    return counts
