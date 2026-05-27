import json
import logging
import re
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

SLACK_PAYLOAD_TEMPLATE = {
    "blocks": [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🚨 PhishGuard Alert — High Risk Email Detected"}
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": "*Hazard Rating:*\n<SEVERITY> (<SCORE>/100)"},
                {"type": "mrkdwn", "text": "*Detected Triggers:*\n<TRIGGERS>"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Email Snippet:*\n<SNIPPET>"}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Action:*\n<ACTION>"}
        },
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": "🛡 *PhishGuard AI* | SecOpsNode AI"}
            ]
        }
    ]
}

TEAMS_PAYLOAD_TEMPLATE = {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "<COLOR>",
    "title": "🚨 PhishGuard Alert — High Risk Email Detected",
    "sections": [
        {
            "facts": [
                {"name": "Hazard Rating", "value": "<SEVERITY> (<SCORE>/100)"},
                {"name": "Psychological Triggers", "value": "<TRIGGERS>"},
                {"name": "Email Snippet", "value": "<SNIPPET>"},
                {"name": "Recommended Action", "value": "<ACTION>"},
            ],
            "markdown": True,
        }
    ],
    "potentialAction": [
        {
            "@type": "OpenUri",
            "name": "Open PhishGuard Dashboard",
            "targets": [{"os": "default", "uri": "<DASHBOARD_URL>"}]
        }
    ]
}


def _validate_webhook_url(url: str) -> bool:
    """Basic validation of a webhook URL before sending."""
    if not url or not url.startswith(("https://hooks.slack.com/", "https://outlook.office.com/webhook/")):
        return False
    try:
        parsed = urlparse(url)
        return all([parsed.scheme == "https", parsed.netloc, parsed.path])
    except Exception:
        return False


def _truncate(text: str, max_len: int = 200) -> str:
    """Safe truncation with ellipsis."""
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len] + "..." if len(text) > max_len else text


def _map_severity_color(severity: str) -> str:
    """Map severity label to hex color for Teams card."""
    return {"CRITICAL": "FF0000", "HIGH": "FF6600", "MEDIUM": "FFAA00", "LOW": "00AA00"}.get(severity.upper(), "808080")


def _render_slack_payload(
    score: int, severity: str, triggers: list, snippet: str, action: str
) -> dict:
    """Render the Slack Block Kit payload with actual values."""
    payload = json.loads(json.dumps(SLACK_PAYLOAD_TEMPLATE))
    trigger_text = ", ".join(triggers[:5]) if triggers else "None detected"
    severity_label = f"*{severity}* ({score}/100)"

    for block in payload["blocks"]:
        if block.get("type") == "section" and block.get("fields"):
            for field in block["fields"]:
                if "<SEVERITY>" in field["text"]:
                    field["text"] = field["text"].replace("<SEVERITY>", severity_label)
                    field["text"] = field["text"].replace("<SCORE>", str(score))
                if "<TRIGGERS>" in field["text"]:
                    field["text"] = field["text"].replace("<TRIGGERS>", trigger_text)
        if block.get("type") == "section" and "<SNIPPET>" in block.get("text", {}).get("text", ""):
            block["text"]["text"] = block["text"]["text"].replace("<SNIPPET>", _truncate(snippet))
        if block.get("type") == "section" and "<ACTION>" in block.get("text", {}).get("text", ""):
            block["text"]["text"] = block["text"]["text"].replace("<ACTION>", action)

    return payload


def _render_teams_payload(
    score: int, severity: str, triggers: list, snippet: str, action: str, dashboard_url: str = ""
) -> dict:
    """Render the Teams actionable message card with actual values."""
    payload = json.loads(json.dumps(TEAMS_PAYLOAD_TEMPLATE))
    trigger_text = ", ".join(triggers[:5]) if triggers else "None detected"
    payload["themeColor"] = _map_severity_color(severity)

    severity_label = f"{severity} ({score}/100)"
    snippet_text = _truncate(snippet)

    for section in payload.get("sections", []):
        for fact in section.get("facts", []):
            if "<SEVERITY>" in fact["value"]:
                fact["value"] = fact["value"].replace("<SEVERITY>", severity_label)
                fact["value"] = fact["value"].replace("<SCORE>", str(score))
            if "<TRIGGERS>" in fact["value"]:
                fact["value"] = fact["value"].replace("<TRIGGERS>", trigger_text)
            if "<SNIPPET>" in fact["value"]:
                fact["value"] = fact["value"].replace("<SNIPPET>", snippet_text)
            if "<ACTION>" in fact["value"]:
                fact["value"] = fact["value"].replace("<ACTION>", action)

    for action_block in payload.get("potentialAction", []):
        for target in action_block.get("targets", []):
            target["uri"] = target["uri"].replace("<DASHBOARD_URL>", dashboard_url or "https://phishguard.ai")

    return payload


def send_slack_alert(
    webhook_url: str,
    score: int,
    severity: str,
    triggers: Optional[list] = None,
    snippet: str = "",
    action: str = "Investigate and quarantine immediately.",
) -> Dict[str, Any]:
    """Send a richly formatted alert to a Slack channel via Incoming Webhook."""
    if not _validate_webhook_url(webhook_url):
        return {"success": False, "error": "Invalid Slack webhook URL. Must start with https://hooks.slack.com/"}

    payload = _render_slack_payload(score, severity, triggers or [], snippet, action)

    try:
        resp = requests.post(
            webhook_url,
            json=payload,
            timeout=15,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code not in (200, 201, 204):
            logger.error("Slack webhook returned %s: %s", resp.status_code, resp.text[:200])
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        return {"success": True, "status_code": resp.status_code}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Slack webhook request timed out after 15s"}
    except requests.exceptions.ConnectionError as exc:
        return {"success": False, "error": f"Connection error: {exc}"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def send_teams_alert(
    webhook_url: str,
    score: int,
    severity: str,
    triggers: Optional[list] = None,
    snippet: str = "",
    action: str = "Investigate and quarantine immediately.",
    dashboard_url: str = "https://phishguard.ai",
) -> Dict[str, Any]:
    """Send a formatted actionable message card to Microsoft Teams via Incoming Webhook."""
    if not _validate_webhook_url(webhook_url):
        return {"success": False, "error": "Invalid Teams webhook URL. Must start with https://outlook.office.com/webhook/"}

    payload = _render_teams_payload(score, severity, triggers or [], snippet, action, dashboard_url)

    try:
        resp = requests.post(
            webhook_url,
            json=payload,
            timeout=15,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code not in (200, 201, 204):
            logger.error("Teams webhook returned %s: %s", resp.status_code, resp.text[:200])
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        return {"success": True, "status_code": resp.status_code}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Teams webhook request timed out after 15s"}
    except requests.exceptions.ConnectionError as exc:
        return {"success": False, "error": f"Connection error: {exc}"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def send_alert(
    webhook_url: str,
    score: int,
    severity: str,
    triggers: Optional[list] = None,
    snippet: str = "",
    action: str = "Investigate and quarantine immediately.",
    dashboard_url: str = "https://phishguard.ai",
) -> Dict[str, Any]:
    """Auto-detect webhook type (Slack or Teams) and route accordingly."""
    if webhook_url.startswith("https://hooks.slack.com/"):
        return send_slack_alert(webhook_url, score, severity, triggers, snippet, action)
    elif webhook_url.startswith("https://outlook.office.com/webhook/"):
        return send_teams_alert(webhook_url, score, severity, triggers, snippet, action, dashboard_url)
    else:
        return {"success": False, "error": "Unrecognised webhook URL. Must be a Slack or Teams incoming webhook."}
