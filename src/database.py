import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path
import os

# Create a 'data' folder in your project root to store the DB safely
# __file__ gets the current path (src/database.py), so we go up one level to the root
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True) # Creates the folder if it doesn't exist

DB_PATH = os.path.join(DATA_DIR, "phishguard.db")

def init_db():
    """Initialize database tables for metrics telemetry and user provisioning."""
    conn = sqlite3.connect(DB_PATH)
# ... [Keep the rest of your init_db and other functions exactly the same] ...

def init_db():
    """Initialize database tables for metrics telemetry and user provisioning."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 1. Historical Analysis Logs Table
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
    
    # 2. Dynamic SaaS User Accounts Table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            email TEXT,
            paddle_order_id TEXT UNIQUE,
            status TEXT,
            role TEXT,
            created_at TEXT
        )
    """)
    
    # Pre-provision master admin access key if empty to avoid system lockouts
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        admin_pass = "phishguard2026"
        hashed = hashlib.sha256(admin_pass.encode()).hexdigest()
        c.execute("""
            INSERT INTO users (username, password_hash, email, paddle_order_id, status, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ('admin', hashed, 'admin@phishguard.ai', 'SYSTEM_MASTER', 'active', 'admin', datetime.now().isoformat()))
        
    conn.commit()
    conn.close()

def save_analysis(results: dict, email_text: str, ai_report: str = ""):
    """Logs historical scanning metrics data for user telemetry dashboards."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    preview = email_text[:100].replace("\n", " ") + "..."
    c.execute("""
        INSERT INTO analyses (timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview, ai_report)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), results.get("risk_score", 0), results.get("severity", "LOW"),
          results.get("total_keyword_hits", 0), results.get("suspicious_url_count", 0), preview, ai_report))
    conn.commit()
    conn.close()

def get_history(limit=20):
    """Retrieve history log records for global administration view templates."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview FROM analyses ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def verify_user_login(username, password):
    """Authenticates users via standard database records using SHA-256 validation."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    c.execute("SELECT role, status FROM users WHERE username = ? AND password_hash = ?", (username, hashed))
    user = c.fetchone()
    conn.close()
    if user and user[1] == 'active':
        return {"authenticated": True, "role": user[0]}
    return {"authenticated": False, "role": None}

def register_premium_user(username, password, email, order_id):
    """Inserts verified premium buyers into the local relational data ledger."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        c.execute("""
            INSERT INTO users (username, password_hash, email, paddle_order_id, status, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed, email, order_id, 'active', 'client', datetime.now().isoformat()))
        conn.commit()
        return True, "Account successfully activated! Please proceed to login."
    except sqlite3.IntegrityError:
        return False, "Registration failed: Username or Paddle Order ID already activated."
    finally:
        conn.close()