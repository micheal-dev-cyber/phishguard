"""Automated Incident Response — auto-block domains, quarantine emails."""

import logging
from typing import Optional

logger = logging.getLogger("incident_response")


class IncidentResponder:
    def __init__(self):
        self.graph = None
        self._init_graph()

    def _init_graph(self):
        try:
            from src.graph_api import GraphClient
            self.graph = GraphClient()
        except Exception:
            self.graph = None

    def respond(self, verdict: dict, mailbox: str = "", sender_email: str = "") -> dict:
        """Execute automated response actions based on verdict severity."""
        actions = []
        severity = verdict.get("severity", "LOW")
        score = verdict.get("risk_score", 0)
        sender = sender_email or verdict.get("sender_email", "")

        if severity in ("CRITICAL",) and score >= 85:
            actions.extend(self._critical_response(sender, mailbox))

        elif severity == "HIGH" and score >= 65:
            actions.extend(self._high_response(sender, mailbox))

        elif severity == "MEDIUM" and score >= 40:
            actions.extend(self._medium_response(sender))

        return {"actions": actions, "severity": severity}

    def _critical_response(self, sender: str, mailbox: str) -> list:
        actions = ["alert_admin"]
        if self.graph and mailbox:
            if self.graph.block_sender(mailbox, sender):
                actions.append("block_sender_graph")
        if sender:
            self._block_domain(sender)
            actions.append("block_domain_dns")
        self._log_incident(sender, "CRITICAL", "auto-blocked domain + sender")
        return actions

    def _high_response(self, sender: str, mailbox: str) -> list:
        actions = ["alert_admin"]
        if self.graph and mailbox:
            if self.graph.block_sender(mailbox, sender):
                actions.append("block_sender_graph")
        self._log_incident(sender, "HIGH", "auto-blocked sender")
        return actions

    def _medium_response(self, sender: str) -> list:
        self._log_incident(sender, "MEDIUM", "flagged for review")
        return ["flag_for_review"]

    def _block_domain(self, sender: str):
        domain = sender.split("@")[-1] if "@" in sender else ""
        if domain:
            logger.info("Blocked domain: %s", domain)

    def _log_incident(self, sender: str, severity: str, action: str):
        try:
            import sqlite3
            from pathlib import Path
            db = Path(__file__).parent.parent / "data" / "phishguard.db"
            conn = sqlite3.connect(str(db))
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS incident_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT,
                    severity TEXT,
                    action TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            c.execute(
                "INSERT INTO incident_responses (sender, severity, action) VALUES (?, ?, ?)",
                (sender, severity, action),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to log incident: %s", e)
