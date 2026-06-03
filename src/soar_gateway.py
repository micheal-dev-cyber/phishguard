"""Active Containment & SOAR Gateway — Mock AD, Cisco, and Slack remediation.

Simulates enterprise SOAR (Security Orchestration, Automation and Response)
actions: Active Directory account disable, Cisco firewall host quarantine,
and Slack/SOAR channel broadcast. In production, these would call real APIs.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("soar-gateway")

# ── In-memory mock state ──────────────────────────────────────────────────

_quarantined_hosts: list[dict] = []
_disabled_accounts: list[dict] = []
_broadcast_log: list[dict] = []


@dataclass
class SoarActionResult:
    action: str
    target: str
    success: bool
    message: str
    duration_ms: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: dict = field(default_factory=dict)


def quarantine_host(host_ip: str, reason: str = "Phishing threat detected") -> SoarActionResult:
    """Mock quarantine of a host IP via Cisco Firewall/ISE."""
    start = time.time()
    _validate_ip(host_ip)
    _simulate_network_delay(150, 400)
    entry = {"host_ip": host_ip, "reason": reason, "quarantined_at": datetime.now().isoformat()}
    _quarantined_hosts.append(entry)
    elapsed = int((time.time() - start) * 1000)
    logger.info("SOAR: Quarantined host %s — %s", host_ip, reason)
    return SoarActionResult(
        action="quarantine_host",
        target=host_ip,
        success=True,
        message=f"Host {host_ip} quarantined via Cisco Firewall. All non-whitelisted traffic blocked.",
        duration_ms=elapsed,
        details={"acl_rule": f"DENY_ALL_{host_ip.replace('.','_')}", "firewall": "Cisco Firepower 4100"},
    )


def disable_ad_account(account_name: str, domain: str = "CORP") -> SoarActionResult:
    """Mock disable of a compromised Active Directory account."""
    start = time.time()
    _simulate_network_delay(200, 600)
    upn = f"{account_name}@{domain}.local"
    entry = {"account": upn, "disabled_at": datetime.now().isoformat()}
    _disabled_accounts.append(entry)
    elapsed = int((time.time() - start) * 1000)
    logger.info("SOAR: Disabled AD account %s", upn)
    return SoarActionResult(
        action="disable_ad_account",
        target=upn,
        success=True,
        message=f"Account {upn} disabled in Active Directory. All sessions terminated.",
        duration_ms=elapsed,
        details={"domain_controller": f"dc01.{domain}.local", "groups_removed": ["Domain Users", "VPN Access"]},
    )


def broadcast_slack_channel(channel: str = "#secops-alerts", message: str = "") -> SoarActionResult:
    """Mock broadcast to a SecOps Slack/MSTeams channel."""
    start = time.time()
    _simulate_network_delay(100, 300)
    entry = {"channel": channel, "message_preview": message[:80], "sent_at": datetime.now().isoformat()}
    _broadcast_log.append(entry)
    elapsed = int((time.time() - start) * 1000)
    logger.info("SOAR: Broadcast to %s — %.80s", channel, message)
    return SoarActionResult(
        action="slack_broadcast",
        target=channel,
        success=True,
        message=f"Alert broadcast to {channel}. All on-call engineers notified.",
        duration_ms=elapsed,
        details={"integrations": ["Slack Webhook", "PagerDuty", "OpsGenie"]},
    )


def get_soar_status() -> dict:
    """Return current SOAR state summary."""
    return {
        "quarantined_hosts": len(_quarantined_hosts),
        "recent_quarantines": _quarantined_hosts[-10:],
        "disabled_accounts": len(_disabled_accounts),
        "recent_disabled": _disabled_accounts[-10:],
        "broadcasts_sent": len(_broadcast_log),
        "recent_broadcasts": _broadcast_log[-10:],
    }


def _validate_ip(ip: str):
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        raise ValueError(f"Invalid IP address: {ip}")


def _simulate_network_delay(min_ms: int = 50, max_ms: int = 300):
    import random
    delay = random.randint(min_ms, max_ms) / 1000
    time.sleep(delay)
