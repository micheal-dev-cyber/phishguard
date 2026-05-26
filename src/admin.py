# src/admin.py
import sqlite3
import pandas as pd
import random
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

import random

def get_threat_map_data():
    """Simulates geolocation data for the global threat map."""
    # In a production app, you would extract this from your OSINT IP geolocation data
    return [
        {"lat": 55.75, "lon": 37.61, "city": "Moscow", "country": "Russia", "threats": random.randint(15, 60)},
        {"lat": 39.90, "lon": 116.40, "city": "Beijing", "country": "China", "threats": random.randint(20, 80)},
        {"lat": 6.52, "lon": 3.37, "city": "Lagos", "country": "Nigeria", "threats": random.randint(10, 40)},
        {"lat": 40.71, "lon": -74.00, "city": "New York", "country": "USA", "threats": random.randint(5, 20)},
        {"lat": -23.55, "lon": -46.63, "city": "Sao Paulo", "country": "Brazil", "threats": random.randint(10, 35)},
        {"lat": 48.85, "lon": 2.35, "city": "Paris", "country": "France", "threats": random.randint(2, 12)},
        {"lat": 28.61, "lon": 77.20, "city": "New Delhi", "country": "India", "threats": random.randint(15, 50)},
    ]

def get_attack_vectors():
    """Simulates vector distribution for the radar chart."""
    return {
        "Credential Harvesting": random.randint(50, 90),
        "Malware Delivery": random.randint(20, 60),
        "Brand Impersonation": random.randint(40, 80),
        "Spear Phishing": random.randint(15, 45),
        "Extortion/Sextortion": random.randint(5, 25)
    }