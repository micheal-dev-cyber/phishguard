# src/tenants.py
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"

PLANS = {
    "trial":      {"analyses_per_month": 10,    "label": "Trial",      "price": "Free"},
    "starter":    {"analyses_per_month": 100,   "label": "Starter",    "price": "$29/mo"},
    "business":   {"analyses_per_month": 500,   "label": "Business",   "price": "$99/mo"},
    "enterprise": {"analyses_per_month": 99999, "label": "Enterprise", "price": "Custom"},
}


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def init_tenants():
    conn = sqlite3.connect(DB_PATH)
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
    conn.commit()
    conn.close()


def seed_admin_from_env():
    """Seed the admin tenant from ENV.ADMIN_PASSWORD on first run."""
    from src.env import ENV
    pw = ENV.ADMIN_PASSWORD
    if pw:
        create_tenant("admin", pw, plan="enterprise", is_admin=1)


def create_tenant(username: str, password: str, email: str = "",
                  plan: str = "trial", is_admin: int = 0, notes: str = "") -> bool:
    init_tenants()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT OR IGNORE INTO tenants
            (username, password_hash, email, plan, is_active, is_admin, created_at, notes)
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (username, _hash(password), email, plan, is_admin,
             datetime.now().isoformat(), notes)
        )
        conn.commit()
        return c.rowcount > 0
    except Exception:
        return False
    finally:
        conn.close()


def verify_tenant(username: str, password: str):
    init_tenants()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        SELECT username, plan, is_active, is_admin, email, notes
        FROM tenants WHERE username = ? AND password_hash = ?
        """,
        (username, _hash(password))
    )
    row = c.fetchone()
    conn.close()
    if row and row[2] == 1:
        return {
            "username": row[0],
            "plan":     row[1],
            "is_active": row[2],
            "is_admin": row[3],
            "email":    row[4],
            "notes":    row[5],
        }
    return None


def get_all_tenants() -> list:
    init_tenants()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        SELECT id, username, email, plan, is_active, is_admin, created_at, notes
        FROM tenants ORDER BY id
        """
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE tenants SET password_hash = ? WHERE username = ?",
        (_hash(new_password), username)
    )
    conn.commit()
    conn.close()


def delete_tenant(username: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM tenants WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def log_usage(username: str, action: str, risk_score: int = 0):
    init_tenants()
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        SELECT COUNT(*) FROM usage_log
        WHERE username = ? AND action = 'analysis' AND timestamp LIKE ?
        """,
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        SELECT t.username, t.plan, t.email, t.is_active,
               COUNT(u.id) as analyses
        FROM tenants t
        LEFT JOIN usage_log u
          ON t.username = u.username
         AND u.action = 'analysis'
         AND u.timestamp LIKE ?
        GROUP BY t.username
        ORDER BY analyses DESC
        """,
        (month + "%",)
    )
    rows = c.fetchall()
    conn.close()
    return rows