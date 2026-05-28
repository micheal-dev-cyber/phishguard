"""Custom Detection Rules — per-tenant keyword/header/regex detection rules."""

import logging
import re
import sqlite3
from pathlib import Path

logger = logging.getLogger("custom-rules")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def init_rules_table():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS custom_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            name        TEXT NOT NULL,
            rule_type   TEXT NOT NULL CHECK(rule_type IN ('keyword','header','regex','url_pattern')),
            pattern     TEXT NOT NULL,
            risk_boost  INTEGER DEFAULT 10,
            is_active   INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_custom_rules_user ON custom_rules (username)")
    conn.commit()
    conn.close()


def add_rule(username: str, name: str, rule_type: str, pattern: str, risk_boost: int = 10):
    init_rules_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT INTO custom_rules (username, name, rule_type, pattern, risk_boost) VALUES (?, ?, ?, ?, ?)",
        (username, name, rule_type, pattern.lower(), risk_boost),
    )
    conn.commit()
    conn.close()
    logger.info("Custom rule '%s' added for %s", name, username)


def remove_rule(rule_id: int):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


def list_rules(username: str) -> list:
    init_rules_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "SELECT id, name, rule_type, pattern, risk_boost, is_active, created_at FROM custom_rules WHERE username = ? ORDER BY id",
        (username,),
    )
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "name": r[1], "rule_type": r[2], "pattern": r[3],
         "risk_boost": r[4], "is_active": bool(r[5]), "created_at": r[6]}
        for r in rows
    ]


def toggle_rule(rule_id: int):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("UPDATE custom_rules SET is_active = CASE WHEN is_active THEN 0 ELSE 1 END WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


def apply_custom_rules(username: str, email_text: str, header_text: str = "") -> dict:
    rules = list_rules(username)
    matches = []
    total_boost = 0
    for r in rules:
        if not r["is_active"]:
            continue
        target = header_text if r["rule_type"] == "header" else email_text
        try:
            if re.search(r["pattern"], target, re.IGNORECASE):
                matches.append({"rule": r["name"], "type": r["rule_type"], "boost": r["risk_boost"]})
                total_boost += r["risk_boost"]
        except re.error:
            continue
    return {"matches": matches, "total_boost": min(total_boost, 50)}
