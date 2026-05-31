"""
PhishGuard AI — Tiered API Key Management & Rate-Limiting Middleware

Tiers:
  Free:        5 scans/day
  Pro:      5000 scans/month
  Enterprise:  Unlimited

Usage from api_proxy.py:
    from src.api_keys import authenticate_request, QuotaExceeded
    user = authenticate_request(headers)
    # user = {"username": "...", "tier": "...", "remaining": N, "allowed": True}
"""

import sqlite3
import hashlib
import secrets
import time
import logging
from datetime import datetime, timezone
from typing import Optional

from src.db import DB_PATH, get_connection

logger = logging.getLogger("api-keys")

TIERS = {
    "free": {
        "label": "Free",
        "daily_limit": 5,
        "monthly_limit": None,
        "features": ["basic_scan"],
        "rate_per_minute": 10,
    },
    "pro": {
        "label": "Pro",
        "daily_limit": None,
        "monthly_limit": 5000,
        "features": ["basic_scan", "ai_text_detection", "aitm_detection", "osint", "vt_reputation"],
        "rate_per_minute": 60,
    },
    "enterprise": {
        "label": "Enterprise",
        "daily_limit": None,
        "monthly_limit": None,
        "features": ["basic_scan", "ai_text_detection", "aitm_detection", "osint", "vt_reputation",
                     "campaign_simulation", "report_phish", "export_stix", "priority_support"],
        "rate_per_minute": 300,
    },
}


def init_api_keys_table():
    conn = get_connection()
    c = conn.cursor()
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
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_usage_key_time
        ON api_usage (key_hash, timestamp)
    """)
    conn.commit()
    conn.close()


def generate_api_key(username: str, tier: str = "free") -> dict:
    init_api_keys_table()
    raw_key = f"pg_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key_bcrypt(raw_key)
    key_prefix = raw_key[:14]

    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, username, tier) VALUES (?, ?, ?, ?)",
            (key_hash, key_prefix, username, tier),
        )
        conn.commit()
        logger.info("Generated %s API key for %s (prefix=%s)", tier, username, key_prefix)
        return {"api_key": raw_key, "prefix": key_prefix, "tier": tier}
    except sqlite3.IntegrityError:
        return {"error": "Key already exists for this configuration"}
    finally:
        conn.close()


def authenticate_request(headers: dict) -> dict:
    init_api_keys_table()
    raw_key = ""
    for k, v in headers.items():
        if k.lower() == "x-phishguard-key":
            raw_key = v.strip()
            break
    if not raw_key:
        return {"allowed": False, "status": 401, "error": "Missing X-PhishGuard-Key header"}

    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            "SELECT key_hash, username, tier, is_active FROM api_keys WHERE is_active=1",
        )
        rows = c.fetchall()
        matched_row = None
        for kh, uname, tier, active in rows:
            try:
                import bcrypt as _bcrypt
                if _bcrypt.checkpw(raw_key.encode(), kh.encode()):
                    matched_row = (kh, uname, tier, active)
                    break
            except (ImportError, ValueError):
                # Fallback to SHA-256
                if kh == hashlib.sha256(raw_key.encode()).hexdigest():
                    matched_row = (kh, uname, tier, active)
                    break

        if not matched_row:
            return {"allowed": False, "status": 401, "error": "Invalid API key"}

        key_hash, username, tier, is_active = matched_row
        if not is_active:
            return {"allowed": False, "status": 403, "error": "API key is deactivated"}

        tier_config = TIERS.get(tier)
        if not tier_config:
            return {"allowed": False, "status": 403, "error": f"Unknown tier: {tier}"}

        remaining, limited = _check_and_record_usage(key_hash, tier, tier_config)
        if limited:
            return {
                "allowed": False,
                "status": 429,
                "error": f"Quota exceeded. Upgrade from {tier_config['label']} to increase limit.",
                "tier": tier,
                "remaining": 0,
            }

        c.execute(
            "UPDATE api_keys SET last_used = ? WHERE key_hash = ?",
            (datetime.now(timezone.utc).isoformat(), key_hash),
        )
        conn.commit()

        return {
            "allowed": True,
            "status": 200,
            "username": username,
            "tier": tier,
            "tier_label": tier_config["label"],
            "remaining": remaining,
        }
    finally:
        conn.close()


def _check_and_record_usage(key_hash: str, tier: str, tier_config: dict) -> tuple:
    now = time.time()
    conn = get_connection()
    c = conn.cursor()
    try:
        daily_limit = tier_config.get("daily_limit")
        monthly_limit = tier_config.get("monthly_limit")

        if daily_limit:
            day_start = now - 86400
            c.execute(
                "SELECT COUNT(*) FROM api_usage WHERE key_hash = ? AND timestamp > ?",
                (key_hash, day_start),
            )
            count = c.fetchone()[0]
            if count >= daily_limit:
                return 0, True

        if monthly_limit:
            month_start = now - 2592000
            c.execute(
                "SELECT COUNT(*) FROM api_usage WHERE key_hash = ? AND timestamp > ?",
                (key_hash, month_start),
            )
            count = c.fetchone()[0]
            if count >= monthly_limit:
                return 0, True

        remaining = (daily_limit or monthly_limit or 999999) - count if (daily_limit or monthly_limit) else 999999

        c.execute(
            "INSERT INTO api_usage (key_hash, endpoint, timestamp) VALUES (?, ?, ?)",
            (key_hash, "api_proxy", now),
        )
        conn.commit()
        return remaining, False
    finally:
        conn.close()


def get_usage_stats(key_hash: str) -> dict:
    init_api_keys_table()
    now = time.time()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT username, tier FROM api_keys WHERE key_hash = ?", (key_hash,))
        row = c.fetchone()
        if not row:
            return {"error": "Key not found"}
        username, tier = row
        tier_config = TIERS.get(tier, {})

        day_start = now - 86400
        month_start = now - 2592000
        c.execute("SELECT COUNT(*) FROM api_usage WHERE key_hash = ? AND timestamp > ?", (key_hash, day_start))
        daily = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM api_usage WHERE key_hash = ? AND timestamp > ?", (key_hash, month_start))
        monthly = c.fetchone()[0]

        return {
            "username": username,
            "tier": tier,
            "tier_label": tier_config.get("label", tier),
            "daily_limit": tier_config.get("daily_limit"),
            "monthly_limit": tier_config.get("monthly_limit"),
            "daily_usage": daily,
            "monthly_usage": monthly,
            "remaining": (tier_config.get("daily_limit") or tier_config.get("monthly_limit") or 999999) - (daily or monthly),
        }
    finally:
        conn.close()


def delete_api_key(key_hash: str) -> bool:
    init_api_keys_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM api_keys WHERE key_hash = ?", (key_hash,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _hash_key_bcrypt(raw: str) -> str:
    try:
        import bcrypt as _bcrypt
        return _bcrypt.hashpw(raw.encode(), _bcrypt.gensalt()).decode()
    except ImportError:
        return _hash_key(raw)
