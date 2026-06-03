"""PostgreSQL connection pool and migration path from SQLite.

Usage:
    from src.postgres import pg, migrate_sqlite_to_postgres
    if pg.enabled:
        rows = pg.query("SELECT * FROM analyses LIMIT 10")
"""

import logging
from pathlib import Path

from src.db import DB_PATH, get_connection

logger = logging.getLogger("postgres")


class PostgreSQLPool:
    """Minimal PostgreSQL connection pool via psycopg2."""

    def __init__(self):
        self._conn = None
        self.enabled = False
        self._init_from_env()

    def _init_from_env(self):
        from src.env import ENV
        pg_host = getattr(ENV, "PGHOST", "") or ""
        pg_port = getattr(ENV, "PGPORT", "5432") or "5432"
        pg_db = getattr(ENV, "PGDATABASE", "phishguard") or "phishguard"
        pg_user = getattr(ENV, "PGUSER", "") or ""
        pg_pass = getattr(ENV, "PGPASSWORD", "") or ""
        if pg_host and pg_user:
            self._dsn = f"host={pg_host} port={pg_port} dbname={pg_db} user={pg_user} password={pg_pass}"
            self.enabled = True
        else:
            self._dsn = ""
            self.enabled = False

    def _connect(self):
        if not self.enabled:
            return None
        if self._conn and self._conn.closed == 0:
            return self._conn
        try:
            import psycopg2
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = True
            return self._conn
        except ImportError:
            logger.warning("psycopg2 not installed — PostgreSQL unavailable")
            self.enabled = False
            return None
        except Exception as e:
            logger.error("PostgreSQL connect failed: %s", e)
            self.enabled = False
            return None

    def query(self, sql: str, params: tuple = ()) -> list:
        conn = self._connect()
        if not conn:
            return []
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                if cur.description:
                    cols = [d[0] for d in cur.description]
                    return [dict(zip(cols, row)) for row in cur.fetchall()]
                return []
        except Exception as e:
            logger.error("PostgreSQL query failed: %s", e)
            return []

    def execute(self, sql: str, params: tuple = ()):
        conn = self._connect()
        if not conn:
            return
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
        except Exception as e:
            logger.error("PostgreSQL execute failed: %s", e)

    def close(self):
        if self._conn and self._conn.closed == 0:
            self._conn.close()


pg = PostgreSQLPool()


def migrate_sqlite_to_postgres():
    """One-shot migration: copy all SQLite tables to PostgreSQL."""
    if not Path(DB_PATH).exists():
        logger.info("No SQLite DB found — nothing to migrate")
        return
    if not pg.enabled:
        logger.info("PostgreSQL not configured — skipping migration")
        return
    sq = get_connection()
    tables = [
        "analyses", "users", "leaderboard", "leaderboard_history",
        "threat_intel", "sender_profiles", "sender_communications",
        "url_sandbox", "homograph_alerts", "intel_broadcasts",
        "ocr_extractions", "campaign_templates", "campaigns",
        "campaign_targets", "api_keys", "api_usage", "reported_phish",
        "scan_consumption", "spending_caps", "referral_codes",
        "referral_redemptions", "tenants", "usage_log", "login_attempts",
    ]
    for table in tables:
        try:
            rows = sq.execute(f"SELECT * FROM {table}").fetchall()
            if not rows:
                continue
            cols = [d[0] for d in sq.execute(f"PRAGMA table_info({table})").fetchall()]
            placeholders = ", ".join(["%s"] * len(cols))
            col_names = ", ".join(cols)
            for row in rows:
                values = [row[c] for c in cols]
                pg.execute(
                    f"INSERT INTO {table} ({col_names}) VALUES ({placeholders}) ON CONFLICT DO NOTHING",
                    tuple(values),
                )
            logger.info("Migrated %d rows to %s", len(rows), table)
        except Exception as e:
            logger.warning("Migration skipped for %s: %s", table, e)
    sq.close()
    logger.info("Migration complete")
