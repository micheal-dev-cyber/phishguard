import logging
import bcrypt
import time
from datetime import datetime

from src.db import DB_PATH, get_connection

logger = logging.getLogger(__name__)

PLANS = {
    "free":       {"analyses_per_month": 5,     "label": "Free",       "price": "Free",
                   "price_monthly": 0, "price_yearly": 0, "price_id": "",
                   "features": ["basic_scan", "pdf_export"],
                   "concurrent_sessions": 1, "rate_per_minute": 5},
    "trial":      {"analyses_per_month": 10,    "label": "Trial",      "price": "Free",
                   "price_monthly": 0, "price_yearly": 0, "price_id": "",
                   "features": ["basic_scan", "pdf_export"],
                   "concurrent_sessions": 1, "rate_per_minute": 5},
    "starter":    {"analyses_per_month": 100,   "label": "Starter",    "price": "$29/mo",
                   "price_monthly": 29, "price_yearly": 290, "price_id": "",
                   "features": ["basic_scan", "threat_intel", "osint", "ai_report", "pdf_export", "email_alerts"],
                   "concurrent_sessions": 2, "rate_per_minute": 15},
    "business":   {"analyses_per_month": 500,   "label": "Business",   "price": "$99/mo",
                   "price_monthly": 99, "price_yearly": 990, "price_id": "",
                   "features": ["basic_scan", "threat_intel", "osint", "ai_report", "pdf_export",
                                "email_alerts", "api_access", "team_access", "priority_support"],
                   "concurrent_sessions": 5, "rate_per_minute": 30},
    "consultant": {"analyses_per_month": 2000,  "label": "Consultant", "price": "$149/mo",
                   "price_monthly": 149, "price_yearly": 1490, "price_id": "",
                   "features": ["basic_scan", "threat_intel", "osint", "ai_report", "pdf_export",
                                "email_alerts", "api_access", "team_access", "priority_support",
                                "white_label", "custom_branding"],
                   "concurrent_sessions": 10, "rate_per_minute": 60},
    "enterprise": {"analyses_per_month": 99999, "label": "Enterprise", "price": "Custom",
                   "price_monthly": 0, "price_yearly": 0, "price_id": "",
                   "features": ["basic_scan", "threat_intel", "osint", "ai_report", "pdf_export",
                                "email_alerts", "api_access", "team_access", "priority_support",
                                "white_label", "sla", "custom_integration"],
                   "concurrent_sessions": 50, "rate_per_minute": 120, "custom": True},
}

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_WINDOW = 900  # 15 minutes


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def _migrate_sha256():
    """One-time migration: re-hash any SHA-256 passwords to bcrypt."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT username, password_hash FROM tenants")
    for username, pw_hash in c.fetchall():
        if pw_hash and len(pw_hash) == 64:  # SHA-256 hex digest
            import hashlib
            if c.execute("SELECT 1 FROM tenants WHERE username = ? AND password_hash = ?",
                        (username, hashlib.sha256(b"x").hexdigest()[:8] + pw_hash[8:])):
                pass  # skip — already migrated
            try:
                new_hash = bcrypt.hashpw(pw_hash.encode(), bcrypt.gensalt()).decode()
                c.execute("UPDATE tenants SET password_hash = ? WHERE username = ?",
                          (new_hash, username))
            except Exception as e:
                logger.warning("tenants: Password hash migration failed for %s: %s", username, e)
    conn.commit()
    conn.close()


def init_tenants():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email         TEXT DEFAULT '',
            plan          TEXT DEFAULT 'trial',
            is_active     INTEGER DEFAULT 1,
            is_admin      INTEGER DEFAULT 0,
            created_at    TEXT,
            notes         TEXT DEFAULT ''
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS usage_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            action     TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            success    INTEGER NOT NULL DEFAULT 0,
            ip_address TEXT DEFAULT '',
            timestamp  REAL NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts (username, timestamp)")
    # Schema migrations for new columns
    for col in ("email_verified", "mfa_enabled"):
        try:
            c.execute(f"ALTER TABLE tenants ADD COLUMN {col} INTEGER DEFAULT 0")
        except Exception as e:
            logger.warning("tenants: Schema migration failed for column %s: %s", col, e)
    conn.commit()
    conn.close()
    _migrate_sha256()


def is_locked_out(username: str) -> bool:
    conn = get_connection()
    c = conn.cursor()
    cutoff = time.time() - LOCKOUT_WINDOW
    c.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND timestamp > ?",
        (username, cutoff),
    )
    count = c.fetchone()[0]
    conn.close()
    return count >= MAX_LOGIN_ATTEMPTS


def record_login_attempt(username: str, success: bool, ip_address: str = ""):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_attempts (username, success, ip_address, timestamp) VALUES (?, ?, ?, ?)",
        (username, 1 if success else 0, ip_address, time.time()),
    )
    conn.commit()
    conn.close()


def seed_admin_from_env():
    from src.env import ENV
    pw = ENV.ADMIN_PASSWORD
    if pw:
        create_tenant("admin", pw, plan="enterprise", is_admin=1)


def create_tenant(username: str, password: str, email: str = "",
                  plan: str = "trial", is_admin: int = 0, notes: str = "") -> bool:
    init_tenants()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            """INSERT OR IGNORE INTO tenants
               (username, password_hash, email, plan, is_active, is_admin, created_at, notes)
               VALUES (?, ?, ?, ?, 1, ?, ?, ?)""",
            (username, _hash(password), email, plan, is_admin,
             datetime.now().isoformat(), notes)
        )
        conn.commit()
        return c.rowcount > 0
    except Exception as e:
        logger.warning("tenants: Failed to create tenant %s: %s", username, e)
        return False
    finally:
        conn.close()


def verify_tenant(username: str, password: str, ip_address: str = ""):
    init_tenants()
    if is_locked_out(username):
        remaining = _lockout_remaining(username)
        return {"error": "locked_out", "remaining": remaining}

    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT username, password_hash, plan, is_active, is_admin, email, notes "
        "FROM tenants WHERE username = ?",
        (username,)
    )
    row = c.fetchone()
    conn.close()

    if not row:
        record_login_attempt(username, False, ip_address)
        return None

    user, pw_hash, plan, is_active, is_admin, email, notes = row
    if not _verify(password, pw_hash):
        record_login_attempt(username, False, ip_address)
        return None

    record_login_attempt(username, True, ip_address)

    if not is_active:
        return {"error": "suspended"}
    return {
        "username": user,
        "plan":     plan,
        "is_active": is_active,
        "is_admin": is_admin,
        "email":    email,
        "notes":    notes,
    }


def _lockout_remaining(username: str) -> int:
    conn = get_connection()
    c = conn.cursor()
    cutoff = time.time() - LOCKOUT_WINDOW
    c.execute(
        "SELECT timestamp FROM login_attempts WHERE username = ? AND success = 0 AND timestamp > ? ORDER BY timestamp",
        (username, cutoff),
    )
    rows = c.fetchall()
    conn.close()
    if len(rows) < MAX_LOGIN_ATTEMPTS:
        return 0
    earliest = rows[0][0]
    return int(LOCKOUT_WINDOW - (time.time() - earliest))


def unlock_user(username: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def get_all_tenants() -> list:
    init_tenants()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, username, email, plan, is_active, is_admin, created_at, notes "
        "FROM tenants ORDER BY id"
    )
    rows = c.fetchall()
    conn.close()
    return rows


def update_tenant(username: str, **kwargs):
    init_tenants()
    allowed = {"email", "plan", "is_active", "is_admin", "notes"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    conn = get_connection()
    c = conn.cursor()
    sets = ", ".join(f"{k} = ?" for k in updates)
    c.execute(
        f"UPDATE tenants SET {sets} WHERE username = ?",
        (*updates.values(), username)
    )
    conn.commit()
    conn.close()


def set_password(username: str, new_password: str):
    init_tenants()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "UPDATE tenants SET password_hash = ? WHERE username = ?",
        (_hash(new_password), username)
    )
    conn.commit()
    conn.close()


def delete_tenant(username: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM tenants WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def log_usage(username: str, action: str, risk_score: int = 0):
    init_tenants()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO usage_log (username, action, timestamp, risk_score) VALUES (?, ?, ?, ?)",
        (username, action, datetime.now().isoformat(), risk_score)
    )
    conn.commit()
    conn.close()


def get_usage(username: str, month: str = None) -> dict:
    init_tenants()
    if not month:
        month = datetime.now().strftime("%Y-%m")
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """SELECT COUNT(*) FROM usage_log
           WHERE username = ? AND action = 'analysis' AND timestamp LIKE ?""",
        (username, month + "%")
    )
    count = c.fetchone()[0]
    conn.close()
    return {"month": month, "analyses": count}


def check_quota(username: str, plan: str) -> dict:
    limit = PLANS.get(plan, PLANS["trial"])["analyses_per_month"]
    usage = get_usage(username)["analyses"]
    remaining = max(0, limit - usage)
    pct = min(100, int(usage / limit * 100)) if limit < 99999 else 0
    return {
        "usage": usage,
        "limit": limit,
        "remaining": remaining,
        "over_limit": usage >= limit,
        "pct": pct,
    }


def get_usage_all_tenants() -> list:
    init_tenants()
    month = datetime.now().strftime("%Y-%m")
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        """SELECT t.username, t.plan, t.email, t.is_active,
                  COUNT(u.id) as analyses
           FROM tenants t
           LEFT JOIN usage_log u ON t.username = u.username AND u.action = 'analysis' AND u.timestamp LIKE ?
           GROUP BY t.username ORDER BY analyses DESC""",
        (month + "%",)
    )
    rows = c.fetchall()
    conn.close()
    return rows
