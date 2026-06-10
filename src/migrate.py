"""
PhishGuard Data Migration CLI.

Usage:
    python -m src.migrate to-postgres [--drop]

Migrates all tables from the SQLite database to PostgreSQL.
Uses environment variables PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD.
"""

import logging
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.db import DB_PATH

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("migrate")

TABLES_TO_MIGRATE = [
    # Core application
    "analyses", "users", "tenants", "api_keys", "api_usage",
    # Billing
    "billing_subscriptions", "webhook_events", "paddle_subscriptions",
    # Security & auth
    "login_attempts", "totp_secrets", "user_permissions", "magic_links",
    # Leaderboard & gamification
    "leaderboard", "leaderboard_history",
    # Threat detection
    "threat_intel", "reported_phish", "url_sandbox", "homograph_alerts",
    "intel_broadcasts", "ocr_extractions",
    # Sender intelligence
    "sender_profiles", "sender_communications",
    # Campaigns
    "campaigns", "campaign_templates", "campaign_targets",
    # Scan metering & caps
    "scan_consumption", "spending_caps",
    # Referrals
    "referral_codes", "referral_redemptions",
    # Telemetry & valuation
    "valuation_metrics", "activity_timeline",
    # A/B testing
    "ab_tests", "ab_test_results",
    # Other
    "analysis_plugins", "brand_protection", "email_verifications",
    "health_checks", "notification_channels", "scan_schedules",
    "task_queue", "usage_log", "webhook_routes",
]


def _get_pg_conn():
    try:
        import psycopg2
    except ImportError:
        logger.error("psycopg2 not installed. Run: pip install psycopg2-binary")
        sys.exit(1)

    conn = psycopg2.connect(
        host=os.getenv("PGHOST", "localhost"),
        port=int(os.getenv("PGPORT", 5432)),
        dbname=os.getenv("PGDATABASE", "phishguard"),
        user=os.getenv("PGUSER", "postgres"),
        password=os.getenv("PGPASSWORD", ""),
        sslmode="require",
    )
    conn.autocommit = False
    return conn


def _get_sqlite_schema(table: str) -> str:
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=? AND sql IS NOT NULL", (table,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return row[0]


def _to_pg_type(sqlite_type: str) -> str:
    mapping = {
        "INTEGER": "INTEGER",
        "TEXT": "TEXT",
        "REAL": "DOUBLE PRECISION",
        "BLOB": "BYTEA",
        "NUMERIC": "NUMERIC",
    }
    return mapping.get(sqlite_type.upper(), "TEXT")


def _translate_schema(sqlite_sql: str) -> str:
    import re
    sqlite_sql = re.sub(
        r"\bINTEGER\s+PRIMARY\s+KEY(?:\s+AUTOINCREMENT)?\b",
        "SERIAL PRIMARY KEY",
        sqlite_sql,
        flags=re.IGNORECASE,
    )
    sqlite_sql = sqlite_sql.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
    sqlite_sql = sqlite_sql.replace("datetime('now')", "CURRENT_TIMESTAMP")
    return sqlite_sql


def migrate_to_postgres(drop_first: bool = False):
    logger.info("Connecting to PostgreSQL...")
    pg_conn = _get_pg_conn()
    pg_c = pg_conn.cursor()

    import sqlite3
    sqlite_conn = sqlite3.connect(DB_PATH)
    sqlite_c = sqlite_conn.cursor()

    for table in TABLES_TO_MIGRATE:
        schema = _get_sqlite_schema(table)
        if not schema:
            logger.info("  Skipping %s (not found in SQLite)", table)
            continue

        pg_schema = _translate_schema(schema)
        if drop_first:
            pg_c.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
            logger.info("  Dropped %s", table)

        try:
            pg_c.execute(pg_schema)
            pg_conn.commit()
            logger.info("  Created %s", table)
        except Exception as e:
            pg_conn.rollback()
            logger.warning("  Could not create %s: %s", table, e)
            continue

        # Copy data
        sqlite_c.execute(f"SELECT * FROM {table}")
        rows = sqlite_c.fetchall()
        if not rows:
            continue
        columns = [desc[0] for desc in sqlite_c.description]
        placeholders = ",".join(["%s"] * len(columns))
        col_names = ",".join(columns)
        insert_sql = f"INSERT INTO {table} ({col_names}) VALUES ({placeholders})"

        batch = []
        for row in rows:
            batch.append(tuple(row))

        try:
            for row in batch:
                pg_c.execute(insert_sql, row)
            pg_conn.commit()
            logger.info("  Migrated %d rows to %s", len(batch), table)
        except Exception as e:
            pg_conn.rollback()
            logger.warning("  Failed to insert rows into %s: %s", table, e)

    sqlite_conn.close()
    pg_c.close()
    pg_conn.close()
    logger.info("Migration complete.")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] != "to-postgres":
        print("Usage: python -m src.migrate to-postgres [--drop]")
        sys.exit(1)
    drop_first = "--drop" in args
    migrate_to_postgres(drop_first)
