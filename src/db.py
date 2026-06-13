import contextlib
import logging
import os
import re
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = str(DATA_DIR / "phishguard.db")

logger = logging.getLogger("db")

# ── PostgreSQL support ────────────────────────────────────────────────────


def _pg_config():
    """Read PostgreSQL config from env (lazy, so .env has been loaded)."""
    host = os.getenv("PGHOST", "")
    user = os.getenv("PGUSER", "")
    if not (host and user):
        return None
    return {
        "host": host,
        "port": int(os.getenv("PGPORT", "5432")),
        "dbname": os.getenv("PGDATABASE", "phishguard"),
        "user": user,
        "password": os.getenv("PGPASSWORD", ""),
        "sslmode": "require",
    }


def _get_pg_connection():
    """Return a psycopg2 connection wrapped for sqlite3-compatible interface."""
    cfg = _pg_config()
    if not cfg:
        return None
    import psycopg2
    conn = psycopg2.connect(**cfg)
    conn.autocommit = False
    return _PgConnection(conn)


class _PgConnection:
    """Wraps a psycopg2 connection to be drop-in compatible with sqlite3."""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return _PgCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


class _PgCursor:
    """Wraps a psycopg2 cursor, translating ? → %s params and AUTOINCREMENT."""

    def __init__(self, cursor):
        self._c = cursor

    def __getattr__(self, name):
        """Forward unknown attribute access to the real cursor (e.g., rowcount)."""
        if name == "_c":
            raise AttributeError(name)
        return getattr(self._c, name)

    def execute(self, sql, params=None):
        # Track whether we need ON CONFLICT for INSERT OR IGNORE/REPLACE
        needs_on_conflict = False
        orig_sql = sql

        # Translate ? placeholders → %s for psycopg2
        if params is not None:
            sql = sql.replace("?", "%s")

        # Replace INTEGER PRIMARY KEY (with optional AUTOINCREMENT) → SERIAL PRIMARY KEY
        sql = re.sub(
            r"\bINTEGER\s+PRIMARY\s+KEY(?:\s+AUTOINCREMENT)?\b",
            "SERIAL PRIMARY KEY",
            sql,
            flags=re.IGNORECASE,
        )

        # Translate SQLite datetime('now') → PostgreSQL CURRENT_TIMESTAMP
        sql = sql.replace("datetime('now')", "CURRENT_TIMESTAMP")

        # Make ADD COLUMN idempotent for PostgreSQL
        sql = re.sub(r"\b(ADD\s+COLUMN)\b", "ADD COLUMN IF NOT EXISTS", sql, flags=re.IGNORECASE)

        # Handle INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
        if re.search(r"\bINSERT\s+OR\s+IGNORE\b", sql, re.IGNORECASE):
            sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\b", "INSERT", sql, flags=re.IGNORECASE)
            needs_on_conflict = True

        # Handle INSERT OR REPLACE → INSERT ... ON CONFLICT DO NOTHING
        # (full upsert is complex; DO NOTHING is safe for billing tables)
        if re.search(r"\bINSERT\s+OR\s+REPLACE\b", sql, re.IGNORECASE):
            sql = re.sub(r"\bINSERT\s+OR\s+REPLACE\b", "INSERT", sql, flags=re.IGNORECASE)
            needs_on_conflict = True

        # Append ON CONFLICT DO NOTHING after the VALUES clause
        if needs_on_conflict:
            # Find the last VALUES (...) and append conflict clause
            sql = re.sub(
                r"(VALUES\s*\([^)]*\))\s*$",
                r"\1 ON CONFLICT DO NOTHING",
                sql,
                flags=re.IGNORECASE | re.DOTALL,
            )

        # Strip PRAGMA statements (PostgreSQL doesn't support them)
        if re.match(r"^\s*PRAGMA\b", sql, re.IGNORECASE):
            return self

        try:
            self._c.execute(sql, params)
        except Exception as e:
            logger.warning("PG query failed: %s — SQL: %.200s", e, sql)
            raise
        return self

    def executemany(self, sql, seq_of_params):
        if seq_of_params:
            sql = sql.replace("?", "%s")
        sql = re.sub(
            r"\bINTEGER\s+PRIMARY\s+KEY(?:\s+AUTOINCREMENT)?\b",
            "SERIAL PRIMARY KEY",
            sql,
            flags=re.IGNORECASE,
        )
        sql = sql.replace("datetime('now')", "CURRENT_TIMESTAMP")
        from psycopg2.extras import execute_batch
        return execute_batch(self._c, sql, seq_of_params)

    def fetchone(self):
        return self._c.fetchone()

    def fetchall(self):
        return self._c.fetchall()

    @property
    def description(self):
        return self._c.description

    def __iter__(self):
        return iter(self._c)


def get_connection():
    """Get a database connection — PostgreSQL if configured, else SQLite."""
    if _pg_config():
        try:
            pg = _get_pg_connection()
            if pg:
                return pg
        except Exception as e:
            logger.error("PostgreSQL connection failed: %s — falling back to SQLite", e)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextlib.contextmanager
def using_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
