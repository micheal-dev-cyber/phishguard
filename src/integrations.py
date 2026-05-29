"""Integration Marketplace — registry of one-click connectors."""

import json
import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger("integrations")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"

REGISTRY = {
    "slack": {
        "name": "Slack",
        "icon": "💬",
        "description": "Send threat alerts to a Slack channel via Incoming Webhook.",
        "fields": [{"key": "webhook_url", "label": "Slack Webhook URL", "type": "password"}],
        "enabled": True,
    },
    "teams": {
        "name": "Microsoft Teams",
        "icon": "🔵",
        "description": "Post security notifications to a Teams channel.",
        "fields": [{"key": "webhook_url", "label": "Teams Webhook URL", "type": "password"}],
        "enabled": True,
    },
    "jira": {
        "name": "Jira",
        "icon": "🔶",
        "description": "Auto-create Jira issues for HIGH/CRITICAL threats.",
        "fields": [
            {"key": "base_url", "label": "Jira Base URL", "type": "text"},
            {"key": "email", "label": "Email", "type": "text"},
            {"key": "api_token", "label": "API Token", "type": "password"},
            {"key": "project_key", "label": "Project Key", "type": "text"},
        ],
        "enabled": True,
    },
    "pagerduty": {
        "name": "PagerDuty",
        "icon": "🔴",
        "description": "Page on-call engineers for CRITICAL threats.",
        "fields": [{"key": "routing_key", "label": "Routing Key", "type": "password"}],
        "enabled": True,
    },
    "splunk": {
        "name": "Splunk HEC",
        "icon": "📡",
        "description": "Forward scan results to Splunk via HTTP Event Collector.",
        "fields": [
            {"key": "hec_url", "label": "HEC URL", "type": "text"},
            {"key": "hec_token", "label": "HEC Token", "type": "password"},
        ],
        "enabled": True,
    },
}


def init_integrations_table():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS integrations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            provider    TEXT NOT NULL,
            config      TEXT NOT NULL DEFAULT '{}',
            is_active   INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT (datetime('now')),
            UNIQUE(username, provider)
        )
    """)
    conn.commit()
    conn.close()


def list_integrations(username: str) -> list:
    init_integrations_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT provider, config, is_active, created_at FROM integrations WHERE username = ?", (username,))
    rows = c.fetchall()
    conn.close()
    result = []
    for r in rows:
        result.append({
            "provider": r[0], "config": json.loads(r[1]) if r[1] else {},
            "is_active": bool(r[2]), "created_at": r[3],
            "meta": REGISTRY.get(r[0], {}),
        })
    return result


def save_integration(username: str, provider: str, config: dict):
    init_integrations_table()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO integrations (username, provider, config, is_active) VALUES (?, ?, ?, 1)",
        (username, provider, json.dumps(config)),
    )
    conn.commit()
    conn.close()


def remove_integration(username: str, provider: str):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM integrations WHERE username = ? AND provider = ?", (username, provider))
    conn.commit()
    conn.close()


def get_available_providers() -> dict:
    return {k: v for k, v in REGISTRY.items() if v["enabled"]}
