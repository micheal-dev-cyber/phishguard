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

    # 5. STIX 2.1 Threat Intelligence Sharing
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id TEXT PRIMARY KEY,
            stix_id TEXT UNIQUE NOT NULL,
            indicator_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            linguistic_hash TEXT,
            sender_domain TEXT,
            severity TEXT,
            risk_score INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            is_active INTEGER DEFAULT 1,
            broadcast_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # 6. Sender Behavioral Profiles
    c.execute("""
        CREATE TABLE IF NOT EXISTS sender_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT UNIQUE NOT NULL,
            sender_domain TEXT NOT NULL,
            display_name TEXT,
            first_contact TEXT,
            last_contact TEXT,
            total_emails INTEGER DEFAULT 0,
            total_attachments INTEGER DEFAULT 0,
            avg_response_hours REAL,
            common_salutations TEXT DEFAULT '[]',
            common_subjects TEXT DEFAULT '[]',
            common_tone_tags TEXT DEFAULT '[]',
            avg_urgency_score REAL DEFAULT 0,
            avg_risk_score REAL DEFAULT 0,
            trust_score REAL DEFAULT 50.0,
            linguistic_baseline_hash TEXT,
            profile_version INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # 7. Sender Communication Log (rolling 90-day window)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sender_communications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT NOT NULL,
            recipient_email TEXT,
            subject TEXT,
            body_hash TEXT,
            word_count INTEGER,
            sentiment_score REAL,
            urgency_score REAL,
            risk_score INTEGER,
            has_attachment INTEGER DEFAULT 0,
            response_time_hours REAL,
            salutation TEXT,
            tone_tags TEXT DEFAULT '[]',
            timestamp TEXT,
            FOREIGN KEY (sender_email) REFERENCES sender_profiles(sender_email)
        )
    """)

    # 8. URL Sandbox Results
    c.execute("""
        CREATE TABLE IF NOT EXISTS url_sandbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_url TEXT NOT NULL,
            final_url TEXT,
            redirect_chain TEXT DEFAULT '[]',
            screenshot_path TEXT,
            page_title TEXT,
            detected_login_form INTEGER DEFAULT 0,
            detected_brand TEXT,
            llm_verdict TEXT,
            llm_confidence REAL,
            html_hash TEXT,
            dom_checksum TEXT,
            risk_score INTEGER,
            verdict TEXT,
            analysis_time_ms INTEGER,
            timestamp TEXT DEFAULT (datetime('now'))
        )
    """)

    # 9. Homograph attack log
    c.execute("""
        CREATE TABLE IF NOT EXISTS homograph_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_domain TEXT NOT NULL,
            decoded_punycode TEXT,
            ascii_domain TEXT,
            homograph_type TEXT,
            visual_lookalike_of TEXT,
            risk_score INTEGER,
            found_in_email TEXT,
            timestamp TEXT DEFAULT (datetime('now'))
        )
    """)

    # 10. Collective intelligence broadcast log
    c.execute("""
        CREATE TABLE IF NOT EXISTS intel_broadcasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stix_id TEXT,
            broadcast_type TEXT,
            target_tenants TEXT,
            payload_size INTEGER,
            status TEXT,
            error_message TEXT,
            timestamp TEXT DEFAULT (datetime('now'))
        )
    """)

    # 11. OCR extraction log
    c.execute("""
        CREATE TABLE IF NOT EXISTS ocr_extractions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER,
            extracted_text TEXT,
            detected_urls TEXT DEFAULT '[]',
            detected_emails TEXT DEFAULT '[]',
            homograph_urls TEXT DEFAULT '[]',
            ocr_confidence REAL,
            processing_time_ms INTEGER,
            timestamp TEXT DEFAULT (datetime('now'))
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

def save_analysis(results, email_text, ai_report=""):
    """Save analysis results from the detector dict format."""
    if isinstance(results, dict):
        risk_score = results.get("risk_score", 0)
        severity = results.get("severity", "LOW")
        keyword_hits = results.get("total_keyword_hits", 0)
        suspicious_urls = results.get("suspicious_url_count", 0)
        email_preview = (email_text or "")[:100]
    else:
        risk_score, severity, keyword_hits, suspicious_urls, email_preview = results, email_text, 0, 0, ""

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