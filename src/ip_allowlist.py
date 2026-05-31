"""IP Allowlist — per-tenant IP-based access restrictions."""

import ipaddress
import logging

from src.db import DB_PATH, get_connection

logger = logging.getLogger("ip-allowlist")


def init_allowlist_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_allowlist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            cidr        TEXT NOT NULL,
            label       TEXT DEFAULT '',
            is_active   INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_ipallow_user ON ip_allowlist (username)")
    conn.commit()
    conn.close()


def add_ip_rule(username: str, cidr: str, label: str = ""):
    init_allowlist_table()
    ipaddress.ip_network(cidr, strict=False)
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO ip_allowlist (username, cidr, label) VALUES (?, ?, ?)",
        (username, cidr, label),
    )
    conn.commit()
    conn.close()
    logger.info("IP rule %s added for %s", cidr, username)


def remove_ip_rule(rule_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM ip_allowlist WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()


def list_ip_rules(username: str) -> list:
    init_allowlist_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, cidr, label, is_active, created_at FROM ip_allowlist WHERE username = ? ORDER BY id",
        (username,),
    )
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "cidr": r[1], "label": r[2], "is_active": bool(r[3]), "created_at": r[4]} for r in rows]


def is_ip_allowed(username: str, ip_str: str) -> bool:
    rules = list_ip_rules(username)
    if not rules:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        for r in rules:
            if r["is_active"] and ipaddress.ip_address(ip_str) in ipaddress.ip_network(r["cidr"], strict=False):
                return True
    except ValueError:
        return True
    return False
