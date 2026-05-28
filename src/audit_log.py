"""Audit Log — track admin actions for compliance and forensics."""

import logging
import sqlite3
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("audit")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def init_audit_table():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            actor       TEXT NOT NULL,
            action      TEXT NOT NULL,
            target      TEXT DEFAULT '',
            detail      TEXT DEFAULT '',
            ip_address  TEXT DEFAULT ''
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log (actor)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log (timestamp)")
    conn.commit()
    conn.close()


def log_action(actor: str, action: str, target: str = "", detail: str = "", ip_address: str = ""):
    init_audit_table()
    try:
        conn = sqlite3.connect(str(DB_PATH))
        c = conn.cursor()
        c.execute(
            "INSERT INTO audit_log (timestamp, actor, action, target, detail, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), actor, action, target, detail, ip_address),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Audit log write failed: %s", e)


def get_audit_log(limit: int = 100, actor: str = "") -> list:
    init_audit_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    if actor:
        c.execute(
            "SELECT timestamp, actor, action, target, detail, ip_address FROM audit_log WHERE actor = ? ORDER BY id DESC LIMIT ?",
            (actor, limit),
        )
    else:
        c.execute(
            "SELECT timestamp, actor, action, target, detail, ip_address FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    rows = c.fetchall()
    conn.close()
    return [
        {"timestamp": r[0], "actor": r[1], "action": r[2], "target": r[3], "detail": r[4], "ip": r[5]}
        for r in rows
    ]
