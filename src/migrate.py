"""
PhishGuard Data Migration CLI.

Usage:
    python -m src.migrate to-postgres [--drop]

Migrates all tables from the SQLite database to PostgreSQL.
Uses environment variables PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD.
"""

import sys
import os
import logging

from src.db import DB_PATH, get_connection

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("migrate")

TABLES_TO_MIGRATE = [
    "analyses", "users", "tenants", "api_keys", "audit_log",
    "notifications", "sessions", "custom_rules", "ip_allowlist",
    "retention_policies", "workspaces", "workspace_members",
    "gdpr_consent", "integrations", "task_queue", "magic_links",
    "perf_metrics", "campaigns", "campaign_results", "honeypot_tokens",
    "phishing_dna_signatures", "stix_bundles", "compliance_reports",
    "quota_usage", "spending_caps", "rate_limits",
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
    )
    conn.autocommit = False
    return conn


def _get_sqlite_schema(table: str) -> str:
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name=? AND sql IS NOT NULL", (table,))
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
    sqlite_sql = sqlite_sql.replace("AUTOINCREMENT", "").replace("autoincrement", "")
    sqlite_sql = sqlite_sql.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
    for stype, pgtype in [("INTEGER", "INTEGER"), ("TEXT", "TEXT"),
                          ("REAL", "DOUBLE PRECISION"), ("BLOB", "BYTEA")]:
        sqlite_sql = sqlite_sql.replace(f" {stype}", f" {pgtype}")
    return sqlite_sql


def migrate_to_postgres(drop_first: bool = False):
    logger.info("Connecting to PostgreSQL...")
    pg_conn = _get_pg_conn()
    pg_c = pg_conn.cursor()

    sqlite_conn = get_connection()
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
            from psycopg2.extras import execute_values
            execute_values(pg_c, insert_sql, batch)
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
