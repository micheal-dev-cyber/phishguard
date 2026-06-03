"""
Notification channel connectors — Slack, Teams, Discord, PagerDuty.

Unified interface for sending alerts to external collaboration platforms.
"""
import json
import logging
from typing import Optional
from urllib.request import Request, urlopen

from src.db import get_connection

logger = logging.getLogger("notification_channels")
CHANNELS_TABLE = "notification_channels"

SUPPORTED_CHANNELS = ["slack", "teams", "discord", "pagerduty"]


def init_channels():
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {CHANNELS_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            channel_type TEXT NOT NULL,
            webhook_url TEXT NOT NULL,
            display_name TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            notify_on TEXT DEFAULT 'critical,high',
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(username, channel_type)
        )
    """)
    conn.commit()
    conn.close()


def set_channel(username: str, channel_type: str, webhook_url: str,
                display_name: str = "", notify_on: str = "critical,high") -> bool:
    init_channels()
    if channel_type not in SUPPORTED_CHANNELS:
        logger.error("Unsupported channel type: %s", channel_type)
        return False
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            f"INSERT OR REPLACE INTO {CHANNELS_TABLE} "
            "(username, channel_type, webhook_url, display_name, notify_on) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, channel_type, webhook_url.strip(), display_name, notify_on),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error("Failed to set channel: %s", e)
        return False
    finally:
        conn.close()


def delete_channel(username: str, channel_type: str) -> bool:
    init_channels()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"DELETE FROM {CHANNELS_TABLE} WHERE username=? AND channel_type=?", (username, channel_type))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def get_channels(username: Optional[str] = None) -> list[dict]:
    init_channels()
    conn = get_connection()
    c = conn.cursor()
    if username:
        c.execute(f"SELECT * FROM {CHANNELS_TABLE} WHERE username=? ORDER BY channel_type", (username,))
    else:
        c.execute(f"SELECT * FROM {CHANNELS_TABLE} ORDER BY username, channel_type")
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def enable_channel(username: str, channel_type: str, enabled: bool) -> bool:
    init_channels()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE {CHANNELS_TABLE} SET enabled=? WHERE username=? AND channel_type=?",
        (1 if enabled else 0, username, channel_type),
    )
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def send_slack(webhook_url: str, message: str, severity: str = "info") -> dict:
    color = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#44aa44", "info": "#4488ff"}
    payload = {
        "attachments": [{
            "color": color.get(severity, "#94a3b8"),
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": message}}],
        }]
    }
    return _send_webhook(webhook_url, payload)


def send_teams(webhook_url: str, message: str, severity: str = "info") -> dict:
    color_map = {"critical": "ff4444", "high": "ff8800", "medium": "ffcc00", "low": "44aa44", "info": "4488ff"}
    theme_color = color_map.get(severity, "94a3b8")
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": "PhishGuard Alert",
        "sections": [{"text": message}],
    }
    return _send_webhook(webhook_url, payload)


def send_discord(webhook_url: str, message: str, severity: str = "info") -> dict:
    color_map = {"critical": 0xff4444, "high": 0xff8800, "medium": 0xffcc00, "low": 0x44aa44, "info": 0x4488ff}
    payload = {
        "embeds": [{
            "title": "🛡 PhishGuard Alert",
            "description": message,
            "color": color_map.get(severity, 0x94a3b8),
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }]
    }
    return _send_webhook(webhook_url, payload)


def send_pagerduty(webhook_url: str, message: str, severity: str = "info") -> dict:
    severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}
    payload = {
        "routing_key": webhook_url.split("/")[-1],
        "event_action": "trigger",
        "payload": {
            "summary": message[:120],
            "severity": severity_map.get(severity, "info"),
            "source": "PhishGuard",
        },
    }
    return _send_webhook(webhook_url, payload, content_type="application/json")


def _send_webhook(url: str, payload: dict, content_type: str = "application/json") -> dict:
    try:
        data = json.dumps(payload).encode()
        req = Request(url, data=data, headers={
            "Content-Type": content_type,
            "User-Agent": "PhishGuard/1.0",
        })
        resp = urlopen(req, timeout=10)
        return {"success": True, "status": resp.status}
    except Exception as e:
        logger.error("Webhook send failed: %s", e)
        return {"success": False, "error": str(e)}


def dispatch_to_channels(username: str, message: str, severity: str) -> list[dict]:
    results = []
    channels = get_channels(username)
    for ch in channels:
        if not ch["enabled"]:
            continue
        if severity not in ch.get("notify_on", "critical,high"):
            continue
        try:
            sender = {
                "slack": send_slack,
                "teams": send_teams,
                "discord": send_discord,
                "pagerduty": send_pagerduty,
            }.get(ch["channel_type"])
            if sender:
                result = sender(ch["webhook_url"], message, severity)
                results.append({"channel": ch["channel_type"], **result})
        except Exception as e:
            results.append({"channel": ch["channel_type"], "success": False, "error": str(e)})
    return results
