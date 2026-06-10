# src/billing/migrations.py
"""
Database migration for billing tables.

Adds the billing_subscriptions and webhook_events tables used by the
new billing abstraction layer.  Does NOT modify or remove existing
Paddle tables for backward compatibility.
"""
import logging

from src.db import get_connection

logger = logging.getLogger(__name__)


_MIGRATIONS = [
    # Migration 1: Create billing_subscriptions table
    """CREATE TABLE IF NOT EXISTS billing_subscriptions (
        id                        INTEGER PRIMARY KEY AUTOINCREMENT,
        username                  TEXT UNIQUE NOT NULL,
        plan_name                 TEXT NOT NULL DEFAULT 'free',
        status                    TEXT NOT NULL DEFAULT 'unknown',
        billing_cycle             TEXT DEFAULT '',
        billing_provider          TEXT DEFAULT 'gumroad',
        provider_subscription_id  TEXT DEFAULT '',
        provider_sale_id          TEXT DEFAULT '',
        last_payment_date         TEXT DEFAULT '',
        next_billing_date         TEXT DEFAULT '',
        created_at                TEXT DEFAULT (datetime('now')),
        updated_at                TEXT DEFAULT (datetime('now'))
    )""",

    # Migration 2: Create webhook_events table for audit trail
    """CREATE TABLE IF NOT EXISTS webhook_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type  TEXT NOT NULL,
        provider    TEXT DEFAULT '',
        payload     TEXT DEFAULT '{}',
        processed   INTEGER DEFAULT 0,
        error       TEXT DEFAULT '',
        created_at  TEXT DEFAULT (datetime('now'))
    )""",

    # Migration 3: Create index on billing_subscriptions username
    """CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_username
       ON billing_subscriptions (username)""",

    # Migration 4: Create index on webhook_events event_type
    """CREATE INDEX IF NOT EXISTS idx_webhook_events_type
       ON webhook_events (event_type)""",
]


def run_migrations():
    """Execute all pending migrations idempotently."""
    conn = get_connection()
    c = conn.cursor()

    # Track which migrations have been applied
    c.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE NOT NULL,
            applied_at  TEXT DEFAULT (datetime('now'))
        )
    """)

    for i, sql in enumerate(_MIGRATIONS):
        name = f"billing_migration_{i:03d}"
        c.execute("SELECT 1 FROM schema_migrations WHERE name = ?", (name,))
        if c.fetchone():
            continue  # Already applied
        try:
            c.execute(sql)
            c.execute(
                "INSERT INTO schema_migrations (name) VALUES (?)",
                (name,),
            )
            conn.commit()
            logger.info("billing: Applied migration %s", name)
        except Exception as e:
            logger.warning("billing: Migration %s failed: %s", name, e)
            conn.rollback()

    conn.close()


def needs_migration() -> bool:
    """Check if any billing migrations are pending."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            applied_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()

    for i in range(len(_MIGRATIONS)):
        name = f"billing_migration_{i:03d}"
        c.execute("SELECT 1 FROM schema_migrations WHERE name = ?", (name,))
        if not c.fetchone():
            conn.close()
            return True
    conn.close()
    return False
