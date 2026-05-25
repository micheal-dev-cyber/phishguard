# src/admin.py
import sqlite3
import pandas as pd
from src.database import DB_PATH

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Using IFNULL to prevent errors if the database is completely empty
    c.execute("SELECT COUNT(*) FROM analyses")
    total_scans = c.fetchone()[0] or 0
    
    c.execute("SELECT COUNT(*) FROM analyses WHERE severity IN ('High', 'Critical')")
    threats = c.fetchone()[0] or 0
    
    conn.close()
    return {"total_scans": total_scans, "threats_blocked": threats}

def get_all_analyses(limit=100):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview FROM analyses ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_recent_threats(limit=5):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, severity, email_preview FROM analyses WHERE severity IN ('High', 'Critical') ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_daily_counts():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT date(timestamp) as date, COUNT(*) as count FROM analyses GROUP BY date(timestamp) ORDER BY date DESC LIMIT 7", conn)
    except Exception:
        # Return empty dataframe if table is missing/empty
        df = pd.DataFrame(columns=['date', 'count'])
    conn.close()
    return df