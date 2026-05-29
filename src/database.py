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

    # 12. Campaign simulation tables
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaign_templates (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            subject     TEXT NOT NULL,
            body        TEXT NOT NULL,
            difficulty  TEXT DEFAULT 'medium',
            category    TEXT DEFAULT 'general',
            is_builtin  INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            template_id     INTEGER NOT NULL,
            template_name   TEXT NOT NULL,
            target_count    INTEGER DEFAULT 0,
            sent_count      INTEGER DEFAULT 0,
            opened_count    INTEGER DEFAULT 0,
            clicked_count   INTEGER DEFAULT 0,
            reported_count  INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'draft',
            created_by      TEXT DEFAULT 'admin',
            created_at      TEXT DEFAULT (datetime('now')),
            launched_at     TEXT,
            completed_at    TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaign_targets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id     INTEGER NOT NULL,
            email           TEXT NOT NULL,
            first_name      TEXT DEFAULT '',
            last_name       TEXT DEFAULT '',
            department      TEXT DEFAULT '',
            company         TEXT DEFAULT '',
            status          TEXT DEFAULT 'pending',
            sent_at         TEXT,
            opened_at       TEXT,
            clicked_at      TEXT,
            reported_at     TEXT,
            risk_score      INTEGER DEFAULT 0
        )
    """)

    # 13. API key management & usage
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash    TEXT UNIQUE NOT NULL,
            key_prefix  TEXT NOT NULL,
            username    TEXT NOT NULL,
            tier        TEXT NOT NULL DEFAULT 'free',
            is_active   INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT (datetime('now')),
            last_used   TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash    TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            timestamp   REAL NOT NULL,
            risk_score  INTEGER DEFAULT 0
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_usage_key_time ON api_usage (key_hash, timestamp)")

    # 14. Reported phish telemetry (Outlook/Gmail add-in webhook)
    c.execute("""
        CREATE TABLE IF NOT EXISTS reported_phish (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_email  TEXT NOT NULL,
            raw_headers     TEXT,
            raw_body        TEXT,
            subject         TEXT,
            sender          TEXT,
            recipients      TEXT,
            risk_score      INTEGER DEFAULT 0,
            severity        TEXT DEFAULT 'UNKNOWN',
            ai_probability  REAL DEFAULT 0,
            aitm_confidence INTEGER DEFAULT 0,
            dna_match       INTEGER DEFAULT 0,
            source          TEXT DEFAULT 'webhook',
            reported_at     TEXT DEFAULT (datetime('now'))
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

    # 15. Scan consumption metering per user
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_consumption (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            scans_used  INTEGER DEFAULT 0,
            scans_limit INTEGER DEFAULT 100,
            period_start TEXT,
            period_end  TEXT,
            UNIQUE(username, period_start)
        )
    """)

    # 16. Spending caps
    c.execute("""
        CREATE TABLE IF NOT EXISTS spending_caps (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            hard_cap_usd REAL DEFAULT 0,
            current_spend REAL DEFAULT 0,
            paused      INTEGER DEFAULT 0
        )
    """)

    # 17. Referral codes
    c.execute("""
        CREATE TABLE IF NOT EXISTS referral_codes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            code        TEXT UNIQUE NOT NULL,
            created_at  TEXT DEFAULT (datetime('now')),
            is_active   INTEGER DEFAULT 1
        )
    """)

    # 18. Referral redemptions
    c.execute("""
        CREATE TABLE IF NOT EXISTS referral_redemptions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer    TEXT NOT NULL,
            referred    TEXT NOT NULL,
            code        TEXT NOT NULL,
            referrer_credited INTEGER DEFAULT 0,
            referred_credited INTEGER DEFAULT 0,
            redeemed_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # 19. M&A Valuation Metrics Telemetry
    c.execute("""
        CREATE TABLE IF NOT EXISTS valuation_metrics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            session_id      TEXT NOT NULL,
            scan_latency_ms INTEGER NOT NULL,
            risk_score      INTEGER NOT NULL,
            severity        TEXT NOT NULL,
            threat_category TEXT NOT NULL,
            user_tier       TEXT NOT NULL DEFAULT 'trial',
            username        TEXT DEFAULT 'anonymous',
            source          TEXT DEFAULT 'web',
            created_at      TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_valuation_ts ON valuation_metrics (timestamp)
    """)
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_valuation_session ON valuation_metrics (session_id)
    """)

    conn.commit()
    conn.close()


# ── Consumption Metering ──────────────────────────────────────────────────

def ensure_scan_consumption(username: str, scans_limit: int = 100):
    """Ensure a scan consumption record exists for the current month."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()
    period_start = now.strftime("%Y-%m-01")
    period_end = now.strftime("%Y-%m-%d")
    c.execute(
        "INSERT OR IGNORE INTO scan_consumption (username, scans_used, scans_limit, period_start, period_end) "
        "VALUES (?, 0, ?, ?, ?)",
        (username, scans_limit, period_start, period_end),
    )
    conn.commit()
    conn.close()


def consume_scan(username: str) -> dict:
    """Mark one scan as used. Returns remaining or error."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()
    period_start = now.strftime("%Y-%m-01")
    c.execute(
        "SELECT scans_used, scans_limit FROM scan_consumption "
        "WHERE username = ? AND period_start = ?",
        (username, period_start),
    )
    row = c.fetchone()
    if not row:
        ensure_scan_consumption(username)
        c.execute(
            "SELECT scans_used, scans_limit FROM scan_consumption "
            "WHERE username = ? AND period_start = ?",
            (username, period_start),
        )
        row = c.fetchone()
    used, limit = row
    if used >= limit:
        conn.close()
        return {"allowed": False, "used": used, "limit": limit, "remaining": 0}
    c.execute(
        "UPDATE scan_consumption SET scans_used = scans_used + 1 "
        "WHERE username = ? AND period_start = ?",
        (username, period_start),
    )
    conn.commit()
    conn.close()
    return {"allowed": True, "used": used + 1, "limit": limit, "remaining": limit - (used + 1)}


def check_scan_quota(username: str) -> dict:
    """Check current scan usage without consuming."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()
    period_start = now.strftime("%Y-%m-01")
    c.execute(
        "SELECT scans_used, scans_limit FROM scan_consumption "
        "WHERE username = ? AND period_start = ?",
        (username, period_start),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        ensure_scan_consumption(username)
        return {"used": 0, "limit": 100, "remaining": 100, "allowed": True}
    used, limit = row
    return {"used": used, "limit": limit, "remaining": limit - used, "allowed": used < limit}


def buy_credits(username: str, additional: int):
    """Add prepaid scan credits to the user's current limit."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()
    period_start = now.strftime("%Y-%m-01")
    c.execute(
        "INSERT OR IGNORE INTO scan_consumption (username, scans_used, scans_limit, period_start, period_end) "
        "VALUES (?, 0, 0, ?, ?)",
        (username, period_start, now.strftime("%Y-%m-%d")),
    )
    c.execute(
        "UPDATE scan_consumption SET scans_limit = scans_limit + ? "
        "WHERE username = ? AND period_start = ?",
        (additional, username, period_start),
    )
    conn.commit()
    conn.close()


# ── Spending Caps ─────────────────────────────────────────────────────────

def get_spending_cap(username: str) -> dict:
    """Get the user's hard spending cap configuration."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT hard_cap_usd, current_spend, paused FROM spending_caps WHERE username = ?",
        (username,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return {"hard_cap_usd": 0, "current_spend": 0, "paused": False}
    return {"hard_cap_usd": row[0], "current_spend": row[1], "paused": bool(row[2])}


def set_spending_cap(username: str, hard_cap_usd: float):
    """Set or update the user's hard spending cap."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO spending_caps (username, hard_cap_usd, current_spend, paused) "
        "VALUES (?, ?, COALESCE((SELECT current_spend FROM spending_caps WHERE username = ?), 0), 0)",
        (username, hard_cap_usd, username),
    )
    conn.commit()
    conn.close()


def record_spend(username: str, amount_usd: float) -> dict:
    """Record a spend and check if cap is hit."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cap = get_spending_cap(username)
    if cap["paused"]:
        conn.close()
        return {"allowed": False, "reason": "PAUSED", "cap": cap}
    new_spend = cap["current_spend"] + amount_usd
    if cap["hard_cap_usd"] > 0 and new_spend > cap["hard_cap_usd"]:
        c.execute(
            "UPDATE spending_caps SET paused = 1 WHERE username = ?",
            (username,),
        )
        conn.commit()
        conn.close()
        return {"allowed": False, "reason": "CAP_REACHED", "cap": {**cap, "current_spend": new_spend}}
    c.execute(
        "UPDATE spending_caps SET current_spend = ? WHERE username = ?",
        (new_spend, username),
    )
    conn.commit()
    conn.close()
    return {"allowed": True, "cap": {**cap, "current_spend": new_spend}}


# ── M&A Valuation Telemetry ──────────────────────────────────────────────

import uuid
import time


def record_valuation_metric(
    scan_latency_ms: int,
    risk_score: int,
    severity: str,
    threat_category: str,
    username: str = "anonymous",
    user_tier: str = "trial",
    source: str = "web",
) -> dict:
    """Record a scan event for M&A valuation / ARR calculations."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    session_id = str(uuid.uuid4())[:8]
    ts = datetime.now().isoformat()
    c.execute(
        "INSERT INTO valuation_metrics "
        "(timestamp, session_id, scan_latency_ms, risk_score, severity, "
        "threat_category, user_tier, username, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, session_id, scan_latency_ms, risk_score, severity,
         threat_category, user_tier, username, source),
    )
    conn.commit()
    conn.close()
    return {"session_id": session_id, "timestamp": ts}


def get_valuation_summary() -> dict:
    """Aggregate valuation metrics for M&A diligence dashboard."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM valuation_metrics")
    total_scans = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT session_id) FROM valuation_metrics")
    unique_sessions = c.fetchone()[0]
    c.execute("SELECT AVG(scan_latency_ms) FROM valuation_metrics")
    avg_latency = c.fetchone()[0] or 0
    c.execute("SELECT AVG(risk_score) FROM valuation_metrics")
    avg_risk = c.fetchone()[0] or 0
    c.execute(
        "SELECT user_tier, COUNT(*) as cnt FROM valuation_metrics "
        "GROUP BY user_tier ORDER BY cnt DESC"
    )
    tier_distribution = dict(c.fetchall())
    c.execute(
        "SELECT DATE(timestamp) as day, COUNT(*) as cnt "
        "FROM valuation_metrics GROUP BY day ORDER BY day"
    )
    daily_activity = [{"date": r[0], "count": r[1]} for r in c.fetchall()]
    c.execute("SELECT COUNT(DISTINCT username) FROM valuation_metrics")
    unique_users = c.fetchone()[0] or 0
    conn.close()

    # ARR calculation (conservative: assume avg $99/mo per active user)
    estimated_arr = unique_users * 99 * 12 * 0.7  # 70% conversion assumption
    sde = estimated_arr * 2.5  # 2.5x SDE multiple for early-stage SaaS

    return {
        "total_scans": total_scans,
        "unique_sessions": unique_sessions,
        "unique_users": unique_users,
        "avg_latency_ms": round(avg_latency, 1),
        "avg_risk_score": round(avg_risk, 1),
        "tier_distribution": tier_distribution,
        "daily_activity": daily_activity,
        "estimated_arr": round(estimated_arr, 2),
        "estimated_sde": round(sde, 2),
        "valuation_range": f"${round(sde * 0.7):,} - ${round(sde * 1.5):,}",
    }


def get_valuation_logs(limit: int = 100) -> list:
    """Get raw valuation metrics logs."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, session_id, scan_latency_ms, risk_score, "
        "severity, threat_category, user_tier, username, source "
        "FROM valuation_metrics ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = c.fetchall()
    conn.close()
    return rows


# ── B2B Referral System ───────────────────────────────────────────────────

def _generate_code(username: str) -> str:
    """Generate a unique referral code."""
    import random, string
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"REF-{username[:4].upper()}{suffix}"


def generate_referral_code(username: str) -> str:
    """Create a referral code for a user if none exists, or return existing."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT code FROM referral_codes WHERE username = ? AND is_active = 1", (username,))
    row = c.fetchone()
    if row:
        conn.close()
        return row[0]
    code = _generate_code(username)
    c.execute(
        "INSERT INTO referral_codes (username, code) VALUES (?, ?)",
        (username, code),
    )
    conn.commit()
    conn.close()
    return code


def apply_referral_code(referrer_code: str, referred_username: str) -> dict:
    """Apply a referral code. Credits both parties with $20 in scan credits."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM referral_codes WHERE code = ? AND is_active = 1", (referrer_code,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "error": "Invalid or inactive referral code."}
    referrer = row[0]
    if referrer == referred_username:
        conn.close()
        return {"status": "error", "error": "Cannot use your own referral code."}
    c.execute(
        "SELECT id FROM referral_redemptions WHERE referrer = ? AND referred = ?",
        (referrer, referred_username),
    )
    if c.fetchone():
        conn.close()
        return {"status": "error", "error": "Referral already used."}
    # Credit both with 20 additional scan credits
    for user in [referrer, referred_username]:
        now = datetime.now()
        period_start = now.strftime("%Y-%m-01")
        c.execute(
            "INSERT OR IGNORE INTO scan_consumption (username, scans_used, scans_limit, period_start, period_end) "
            "VALUES (?, 0, 0, ?, ?)",
            (user, period_start, now.strftime("%Y-%m-%d")),
        )
        c.execute(
            "UPDATE scan_consumption SET scans_limit = scans_limit + 20 "
            "WHERE username = ? AND period_start = ?",
            (user, period_start),
        )
    c.execute(
        "INSERT INTO referral_redemptions (referrer, referred, code, referrer_credited, referred_credited) "
        "VALUES (?, ?, ?, 1, 1)",
        (referrer, referred_username, referrer_code),
    )
    conn.commit()
    conn.close()
    return {"status": "ok", "referrer": referrer, "credit": 20}


def get_referral_balance(username: str) -> dict:
    """Get referral stats for a user."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    code = generate_referral_code(username)
    c.execute(
        "SELECT COUNT(*) FROM referral_redemptions WHERE referrer = ?",
        (username,),
    )
    total_refs = c.fetchone()[0]
    c.execute(
        "SELECT COALESCE(SUM(referrer_credited * 20), 0) FROM referral_redemptions WHERE referrer = ?",
        (username,),
    )
    total_credits = c.fetchone()[0]
    conn.close()
    return {"code": code, "total_referrals": total_refs, "total_credits_earned": total_credits}

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