"""
Custom email domain verification (DKIM/SPF) for sender authentication.

Verifies that sending domains have proper DKIM and SPF records.
"""
import hmac
import logging
import re
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger("domain_verify")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"
DOMAIN_TABLE = "verified_domains"


def init_domain_verify():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {DOMAIN_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            domain TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            verification_token TEXT DEFAULT '',
            spf_status TEXT DEFAULT 'unknown',
            dkim_status TEXT DEFAULT 'unknown',
            dmarc_status TEXT DEFAULT 'unknown',
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(username, domain)
        )
    """)
    conn.commit()
    conn.close()


def add_domain(username: str, domain: str) -> str:
    import secrets
    init_domain_verify()
    token = secrets.token_urlsafe(16)
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        f"INSERT OR REPLACE INTO {DOMAIN_TABLE} (username, domain, verified, verification_token) VALUES (?, ?, 0, ?)",
        (domain.lower().strip(), domain.lower().strip(), token),
    )
    conn.commit()
    conn.close()
    return token


def verify_domain(username: str, domain: str, token: str) -> bool:
    init_domain_verify()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        f"SELECT verification_token FROM {DOMAIN_TABLE} WHERE username=? AND domain=?",
        (username, domain),
    )
    row = c.fetchone()
    if not row or not hmac.compare_digest(str(row[0] or ""), token):
        conn.close()
        return False
    c.execute(f"UPDATE {DOMAIN_TABLE} SET verified=1 WHERE username=? AND domain=?", (username, domain))
    conn.commit()
    conn.close()
    return True


def check_dns_records(domain: str) -> dict:
    """Check SPF, DKIM, DMARC DNS records."""
    result = {"domain": domain, "spf": "not_found", "dkim": "not_found", "dmarc": "not_found", "errors": []}
    try:
        import socket
        spf_queried = False
        for record_type in ["TXT", "TXT"]:
            try:
                answers = socket.getaddrinfo(f"_dmarc.{domain}", 0)
                result["dmarc"] = "found"
            except Exception as e:
                logger.warning("domain_verify: DMARC lookup failed for %s: %s", domain, e)
            try:
                import dns.resolver
                for rtype, key in [("TXT", "spf"), ("TXT", "dkim")]:
                    try:
                        answers = dns.resolver.resolve(domain, rtype)
                        for ans in answers:
                            txt = str(ans).lower()
                            if "v=spf1" in txt:
                                result["spf"] = "found"
                            if "v=dkim1" in txt or "k=rsa" in txt:
                                result["dkim"] = "found"
                    except Exception as e:
                        logger.warning("domain_verify: DNS lookup failed for %s: %s", domain, e)
            except ImportError:
                result["errors"].append("dns.resolver not available; install dnspython")
                break
    except Exception as e:
        result["errors"].append(str(e))
    if not result["spf"] == "found" and not result["errors"]:
        result["spf"] = "missing"
    if not result["dkim"] == "found" and not result["errors"]:
        result["dkim"] = "missing"
    if not result["dmarc"] == "found" and not result["errors"]:
        result["dmarc"] = "missing"
    return result


def get_user_domains(username: str) -> list[dict]:
    init_domain_verify()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(f"SELECT id, domain, verified, created_at FROM {DOMAIN_TABLE} WHERE username=? ORDER BY created_at DESC", (username,))
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def delete_domain(username: str, domain: str) -> bool:
    init_domain_verify()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(f"DELETE FROM {DOMAIN_TABLE} WHERE username=? AND domain=?", (username, domain))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0
