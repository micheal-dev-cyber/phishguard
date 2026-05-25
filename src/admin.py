import sqlite3
from datetime import datetime, timedelta
import os

DB_PATH = os.path.join("/tmp", "phishguard.db")


def get_all_analyses(limit: int = 100) -> list:
    """Get all analyses from database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, timestamp, risk_score, severity,
               keyword_hits, suspicious_urls, email_preview
        FROM analyses
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_stats() -> dict:
    """Get overall platform statistics."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Total analyses
    c.execute("SELECT COUNT(*) FROM analyses")
    total = c.fetchone()[0]

    # Severity breakdown
    c.execute("""
        SELECT severity, COUNT(*) 
        FROM analyses 
        GROUP BY severity
    """)
    severity_counts = dict(c.fetchall())

    # Average risk score
    c.execute("SELECT AVG(risk_score) FROM analyses")
    avg_score = c.fetchone()[0] or 0

    # Analyses today
    today = datetime.now().strftime("%Y-%m-%d")
    c.execute("""
        SELECT COUNT(*) FROM analyses 
        WHERE timestamp LIKE ?
    """, (f"{today}%",))
    today_count = c.fetchone()[0]

    # Analyses this week
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    c.execute("""
        SELECT COUNT(*) FROM analyses 
        WHERE timestamp > ?
    """, (week_ago,))
    week_count = c.fetchone()[0]

    # Most common severity
    c.execute("""
        SELECT severity, COUNT(*) as cnt 
        FROM analyses 
        GROUP BY severity 
        ORDER BY cnt DESC LIMIT 1
    """)
    top_severity = c.fetchone()

    # Critical threats
    c.execute("""
        SELECT COUNT(*) FROM analyses 
        WHERE severity = 'CRITICAL'
    """)
    critical_count = c.fetchone()[0]

    # High risk
    c.execute("""
        SELECT COUNT(*) FROM analyses 
        WHERE severity = 'HIGH'
    """)
    high_count = c.fetchone()[0]

    conn.close()

    return {
        "total_analyses":  total,
        "today_analyses":  today_count,
        "week_analyses":   week_count,
        "avg_risk_score":  round(avg_score, 1),
        "severity_counts": severity_counts,
        "critical_count":  critical_count,
        "high_count":      high_count,
        "top_severity":    top_severity[0] if top_severity else "N/A",
    }


def get_recent_threats(limit: int = 10) -> list:
    """Get most recent high/critical threats."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, risk_score, severity, 
               keyword_hits, suspicious_urls, email_preview
        FROM analyses
        WHERE severity IN ('CRITICAL', 'HIGH')
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_daily_counts(days: int = 14) -> list:
    """Get analysis counts per day for the last N days."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    results = []

    for i in range(days - 1, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        c.execute("""
            SELECT COUNT(*) FROM analyses 
            WHERE timestamp LIKE ?
        """, (f"{date}%",))
        count = c.fetchone()[0]
        results.append({"date": date, "count": count})

    conn.close()
    return results


def get_severity_trend() -> list:
    """Get last 50 analyses for trend chart."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, risk_score, severity
        FROM analyses
        ORDER BY id DESC LIMIT 50
    """)
    rows = c.fetchall()
    conn.close()
    return list(reversed(rows))