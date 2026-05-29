"""GDPR Compliance Tools — data export, account deletion, consent records."""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("gdpr")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def init_gdpr_table():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS gdpr_consent (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            consent_type TEXT NOT NULL DEFAULT 'data_processing',
            granted     INTEGER DEFAULT 1,
            ip_address  TEXT DEFAULT '',
            granted_at  TEXT DEFAULT (datetime('now')),
            UNIQUE(username, consent_type)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS gdpr_export_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            requested_at TEXT DEFAULT (datetime('now')),
            completed_at TEXT,
            status      TEXT DEFAULT 'pending' CHECK(status IN ('pending','completed','failed')),
            data_file   TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


def record_consent(username: str, consent_type: str = "data_processing", ip: str = ""):
    init_gdpr_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO gdpr_consent (username, consent_type, granted, ip_address) VALUES (?, ?, 1, ?)",
        (username, consent_type, ip),
    )
    conn.commit()
    conn.close()


def revoke_consent(username: str, consent_type: str = "data_processing"):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("UPDATE gdpr_consent SET granted = 0 WHERE username = ? AND consent_type = ?",
              (username, consent_type))
    conn.commit()
    conn.close()


def check_consent(username: str) -> bool:
    init_gdpr_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT granted FROM gdpr_consent WHERE username = ? AND consent_type = 'data_processing'",
              (username,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return True
    return bool(row[0])


def export_user_data(username: str) -> dict:
    init_gdpr_table()
    data = {"username": username, "exported_at": datetime.now().isoformat()}
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM tenants WHERE username = ?", (username,))
        row = c.fetchone()
        if row:
            data["account"] = {
                "username": row[1], "email": row[3], "plan": row[4],
                "is_active": bool(row[5]), "is_admin": bool(row[6]),
                "created_at": row[8], "notes": row[9],
            }
        for table in ["analyses", "login_attempts", "audit_log", "notifications", "custom_rules"]:
            try:
                c.execute(f"SELECT * FROM {table} WHERE username = ?", (username,))
                cols = [desc[0] for desc in c.description]
                data[table] = [dict(zip(cols, r)) for r in c.fetchall()]
            except Exception:
                data[table] = []
        c.execute(
            "INSERT INTO gdpr_export_requests (username, status, completed_at, data_file) VALUES (?, 'completed', datetime('now'), ?)",
            (username, "in-memory"),
        )
        conn.commit()
    finally:
        conn.close()
    return data


def delete_user_data(username: str) -> dict:
    init_gdpr_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    deleted = {}
    for table in ["analyses", "login_attempts", "audit_log", "notifications",
                   "custom_rules", "gdpr_consent", "gdpr_export_requests",
                   "api_keys", "api_usage", "ip_allowlist", "sessions",
                   "workspace_members", "mfa_secrets", "email_verifications",
                   "password_reset_tokens"]:
        try:
            c.execute(f"DELETE FROM {table} WHERE username = ?", (username,))
            deleted[table] = c.rowcount
        except Exception:
            deleted[table] = 0
    c.execute("DELETE FROM tenants WHERE username = ?", (username,))
    deleted["tenants"] = c.rowcount
    conn.commit()
    conn.close()
    return deleted
