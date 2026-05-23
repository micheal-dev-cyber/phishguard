import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            risk_score INTEGER,
            severity TEXT,
            keyword_hits INTEGER,
            suspicious_urls INTEGER,
            email_preview TEXT,
            ai_report TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_analysis(results: dict, email_text: str, ai_report: str = ""):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO analyses
        (timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview, ai_report)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        results["risk_score"],
        results["severity"],
        results["total_keyword_hits"],
        results["suspicious_url_count"],
        email_text[:200],
        ai_report
    ))
    conn.commit()
    conn.close()


def get_history(limit: int = 20) -> list:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview
        FROM analyses
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows