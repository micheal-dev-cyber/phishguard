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
    
    # 3. Gamified Leaderboard Table
    c.execute("""
        CREATE TABLE IF NOT EXISTS leaderboard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            department TEXT DEFAULT 'General',
            total_scans INTEGER DEFAULT 0,
            threats_reported INTEGER DEFAULT 0,
            critical_reports INTEGER DEFAULT 0,
            high_reports INTEGER DEFAULT 0,
            medium_reports INTEGER DEFAULT 0,
            total_points INTEGER DEFAULT 0,
            last_active TEXT,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    """)

    # 4. Leaderboard points history (audit trail)
    c.execute("""
        CREATE TABLE IF NOT EXISTS leaderboard_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            points INTEGER NOT NULL,
            reason TEXT NOT NULL,
            scan_id INTEGER,
            timestamp TEXT DEFAULT (datetime('now'))
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

def save_analysis(risk_score, severity, keyword_hits, suspicious_urls, email_preview, ai_report=""):
    """Saves a scan result to the database, including the AI SecOps report."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO analyses (timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview, ai_report)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), risk_score, severity, keyword_hits, suspicious_urls, email_preview, ai_report))
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

# ── Leaderboard functions ──────────────────────────────────────────────────

LEADERBOARD_SCORING = {
    "scan": 10,
    "medium_report": 15,
    "high_report": 25,
    "critical_report": 50,
    "daily_login": 2,
}


def ensure_leaderboard_entry(username: str, department: str = "General"):
    """Create a leaderboard entry for a user if one doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT OR IGNORE INTO leaderboard (username, department, total_scans, total_points, last_active) "
            "VALUES (?, ?, 0, 0, datetime('now'))",
            (username, department),
        )
        conn.commit()
    finally:
        conn.close()


def award_points(username: str, points: int, reason: str, scan_id: int = None):
    """Award points to a user and record in history."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "UPDATE leaderboard SET total_points = total_points + ?, last_active = datetime('now') "
            "WHERE username = ?",
            (points, username),
        )
        c.execute(
            "INSERT INTO leaderboard_history (username, points, reason, scan_id) VALUES (?, ?, ?, ?)",
            (username, points, reason, scan_id),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


def record_scan(username: str, severity: str, score: int, scan_id: int = None):
    """Record a scan and award appropriate points."""
    ensure_leaderboard_entry(username)

    base_points = LEADERBOARD_SCORING["scan"]
    reason = "Email scan completed"

    # Bonus points for threat reports
    if severity == "CRITICAL":
        base_points += LEADERBOARD_SCORING["critical_report"]
        reason = "Critical threat reported"
    elif severity == "HIGH":
        base_points += LEADERBOARD_SCORING["high_report"]
        reason = "High-risk threat reported"
    elif severity == "MEDIUM":
        base_points += LEADERBOARD_SCORING["medium_report"]
        reason = "Medium-risk threat reported"

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "UPDATE leaderboard SET "
            "total_scans = total_scans + 1, "
            "total_points = total_points + ?, "
            "threats_reported = threats_reported + ? "
            "WHERE username = ?",
            (base_points, 1 if severity in ("HIGH", "CRITICAL") else 0, username),
        )
        if severity == "CRITICAL":
            c.execute(
                "UPDATE leaderboard SET critical_reports = critical_reports + 1 WHERE username = ?",
                (username,),
            )
        elif severity == "HIGH":
            c.execute(
                "UPDATE leaderboard SET high_reports = high_reports + 1 WHERE username = ?",
                (username,),
            )
        elif severity == "MEDIUM":
            c.execute(
                "UPDATE leaderboard SET medium_reports = medium_reports + 1 WHERE username = ?",
                (username,),
            )
        c.execute(
            "INSERT INTO leaderboard_history (username, points, reason, scan_id) VALUES (?, ?, ?, ?)",
            (username, base_points, reason, scan_id),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


def get_leaderboard(limit: int = 20) -> list:
    """Get the top reporters by total points."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT username, department, total_scans, threats_reported,
               critical_reports, high_reports, total_points, last_active
        FROM leaderboard
        ORDER BY total_points DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_user_rank(username: str) -> dict:
    """Get a user's rank and stats."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT l.username, l.department, l.total_scans, l.threats_reported,
               l.critical_reports, l.high_reports, l.total_points, l.last_active
        FROM leaderboard l
        WHERE l.username = ?
    """, (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {}

    # Calculate rank
    c.execute("""
        SELECT COUNT(*) + 1 FROM leaderboard
        WHERE total_points > (SELECT total_points FROM leaderboard WHERE username = ?)
    """, (username,))
    rank = c.fetchone()[0]
    conn.close()

    return {
        "rank": rank,
        "username": row[0],
        "department": row[1],
        "total_scans": row[2],
        "threats_reported": row[3],
        "critical_reports": row[4],
        "high_reports": row[5],
        "total_points": row[6],
        "last_active": row[7],
    }