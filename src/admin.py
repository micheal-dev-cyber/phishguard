# src/admin.py
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def _connect():
    """Open connection with row_factory for safety."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def get_all_analyses(limit: int = 100) -> list:
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute(
            """
            SELECT id, timestamp, risk_score, severity, keyword_hits,
                   suspicious_urls, email_preview
            FROM analyses
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        return c.fetchall()
    finally:
        conn.close()


def get_stats() -> dict:
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM analyses")
        total = c.fetchone()[0]

        c.execute("SELECT severity, COUNT(*) FROM analyses GROUP BY severity")
        severity_counts_raw = c.fetchall()
        severity_counts = {row[0]: row[1] for row in severity_counts_raw}

        c.execute("SELECT AVG(risk_score) FROM analyses")
        avg_score = c.fetchone()[0] or 0

        today = datetime.now().strftime("%Y-%m-%d")
        c.execute("SELECT COUNT(*) FROM analyses WHERE timestamp LIKE ?", (today + "%",))
        today_count = c.fetchone()[0]

        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        c.execute("SELECT COUNT(*) FROM analyses WHERE timestamp > ?", (week_ago,))
        week_count = c.fetchone()[0]

        c.execute(
            "SELECT severity, COUNT(*) as cnt FROM analyses "
            "GROUP BY severity ORDER BY cnt DESC LIMIT 1"
        )
        top_severity = c.fetchone()

        c.execute("SELECT COUNT(*) FROM analyses WHERE severity = 'CRITICAL'")
        critical_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM analyses WHERE severity = 'HIGH'")
        high_count = c.fetchone()[0]

        return {
            "total_analyses": total,
            "today_analyses": today_count,
            "week_analyses": week_count,
            "avg_risk_score": round(avg_score, 1),
            "severity_counts": severity_counts,
            "critical_count": critical_count,
            "high_count": high_count,
            "top_severity": top_severity["severity"] if top_severity else "N/A",
        }
    finally:
        conn.close()


def get_recent_threats(limit: int = 10) -> list:
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute(
            """
            SELECT timestamp, risk_score, severity, keyword_hits,
                   suspicious_urls, email_preview
            FROM analyses
            WHERE severity IN ('CRITICAL', 'HIGH')
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        return c.fetchall()
    finally:
        conn.close()


def get_daily_counts(days: int = 14) -> list:
    conn = _connect()
    try:
        c = conn.cursor()
        results = []
        for i in range(days - 1, -1, -1):
            date = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            c.execute(
                "SELECT COUNT(*) FROM analyses WHERE timestamp LIKE ?",
                (date + "%",)
            )
            count = c.fetchone()[0]
            results.append({"date": date, "count": count})
        return results
    finally:
        conn.close()


def get_severity_trend() -> list:
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT timestamp, risk_score, severity FROM analyses ORDER BY id DESC LIMIT 50"
        )
        rows = c.fetchall()
        return list(reversed(rows))
    finally:
        conn.close()
