"""Employee Auto-Training — assign training campaigns to at-risk users."""

import logging
from datetime import datetime

logger = logging.getLogger("auto_training")


def assign_training(username: str, risk_score: int, severity: str) -> dict:
    """Assign a training campaign to a user based on scan results."""
    if severity in ("CRITICAL",) and risk_score >= 80:
        return _create_training_campaign(username, "advanced_phishing_awareness", priority="high")
    elif severity == "HIGH" and risk_score >= 60:
        return _create_training_campaign(username, "phishing_basics", priority="medium")
    elif risk_score >= 40:
        return _create_training_campaign(username, "security_refresher", priority="low")
    return {"assigned": False, "reason": "risk_below_threshold"}


def _create_training_campaign(username: str, template_name: str, priority: str) -> dict:
    try:
        import sqlite3
        from pathlib import Path
        db = Path(__file__).parent.parent / "data" / "phishguard.db"
        conn = sqlite3.connect(str(db))
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS auto_training_assignments (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT NOT NULL,
                template_name   TEXT NOT NULL,
                priority        TEXT DEFAULT 'medium',
                status          TEXT DEFAULT 'pending',
                assigned_at     TEXT DEFAULT (datetime('now')),
                completed_at    TEXT,
                score           REAL DEFAULT 0
            )
        """)

        c.execute(
            "SELECT id FROM auto_training_assignments WHERE username = ? AND template_name = ? AND status = 'pending'",
            (username, template_name),
        )
        if c.fetchone():
            conn.close()
            return {"assigned": False, "reason": "already_assigned"}

        c.execute(
            "INSERT INTO auto_training_assignments (username, template_name, priority) VALUES (?, ?, ?)",
            (username, template_name, priority),
        )
        conn.commit()
        conn.close()
        logger.info("Assigned training %s to %s (priority=%s)", template_name, username, priority)
        return {"assigned": True, "template": template_name, "priority": priority}
    except Exception as e:
        logger.error("Training assignment failed: %s", e)
        return {"assigned": False, "error": str(e)}


def get_training_status(username: str) -> list:
    try:
        import sqlite3
        from pathlib import Path
        db = Path(__file__).parent.parent / "data" / "phishguard.db"
        conn = sqlite3.connect(str(db))
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS auto_training_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                template_name TEXT NOT NULL,
                priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'pending',
                assigned_at TEXT DEFAULT (datetime('now')),
                completed_at TEXT,
                score REAL DEFAULT 0
            )
        """)
        c.execute(
            "SELECT template_name, priority, status, assigned_at, completed_at, score "
            "FROM auto_training_assignments WHERE username = ? ORDER BY assigned_at DESC",
            (username,),
        )
        rows = c.fetchall()
        conn.close()
        return [{
            "template": r[0], "priority": r[1], "status": r[2],
            "assigned_at": r[3], "completed_at": r[4], "score": r[5],
        } for r in rows]
    except Exception as e:
        logger.error("Training status fetch failed: %s", e)
        return []
