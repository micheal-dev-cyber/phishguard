"""
PhishGuard AI — Inbox Scanner (IMAP / OAuth 2.0 for Gmail & Outlook 365)

Usage:
    scanner = InboxScanner()
    emails = scanner.scek("imap.gmail.com", 993, "user@gmail.com", "app-password")
    # or
    emails = scanner.scan_via_oauth(provider="gmail", token=oauth_token)
"""
import imaplib
import email
import re
import logging
from email import policy
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("inbox-scanner")


class InboxScanner:
    def __init__(self):
        self.connection: Optional[imaplib.IMAP4_SSL] = None

    def connect(self, host: str, port: int, username: str, password: str) -> bool:
        try:
            self.connection = imaplib.IMAP4_SSL(host, port)
            self.connection.login(username, password)
            return True
        except Exception as e:
            logger.error(f"IMAP connect failed: {e}")
            return False

    def disconnect(self):
        if self.connection:
            try:
                self.connection.logout()
            except Exception:
                pass
            self.connection = None

    def fetch_recent(self, folder: str = "INBOX", hours: int = 24, max_emails: int = 50) -> list:
        if not self.connection:
            return []
        results = []
        try:
            self.connection.select(folder)
            since_date = (datetime.now() - timedelta(hours=hours)).strftime("%d-%b-%Y")
            status, ids = self.connection.search(None, f'(SINCE {since_date})')
            if status != "OK":
                return []
            id_list = ids[0].split() if ids[0] else []
            id_list = id_list[-max_emails:]  # only latest N
            for eid in id_list:
                status, data = self.connection.fetch(eid, "(RFC822)")
                if status != "OK":
                    continue
                raw = data[0][1] if data and data[0] else None
                if raw:
                    parsed = self._parse_raw(raw)
                    if parsed:
                        results.append(parsed)
        except Exception as e:
            logger.error(f"fetch_recent error: {e}")
        return results

    def scan_by_criteria(self, folder: str = "INBOX", criterion: str = "UNSEEN", max_emails: int = 50) -> list:
        if not self.connection:
            return []
        results = []
        try:
            self.connection.select(folder)
            status, ids = self.connection.search(None, criterion)
            if status != "OK":
                return []
            id_list = ids[0].split() if ids[0] else []
            id_list = id_list[-max_emails:]
            for eid in id_list:
                status, data = self.connection.fetch(eid, "(RFC822)")
                if status != "OK":
                    continue
                raw = data[0][1] if data and data[0] else None
                if raw:
                    parsed = self._parse_raw(raw)
                    if parsed:
                        results.append(parsed)
        except Exception as e:
            logger.error(f"scan_by_criteria error: {e}")
        return results

    def _parse_raw(self, raw_bytes: bytes) -> dict:
        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
            subject = str(msg.get("Subject", ""))
            sender = str(msg.get("From", ""))
            date = str(msg.get("Date", ""))
            body = self._extract_body(msg)
            return {
                "subject": subject,
                "sender": sender,
                "date": date,
                "body": body,
                "raw_length": len(raw_bytes),
            }
        except Exception as e:
            logger.warning(f"Parse error: {e}")
            return None

    def _extract_body(self, msg) -> str:
        body_text = ""
        html_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if part.get_content_disposition() == "attachment":
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if ct == "text/plain":
                        body_text = decoded
                    elif ct == "text/html":
                        html_text = decoded
                except Exception:
                    pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    body_text = payload.decode(charset, errors="replace")
            except Exception:
                pass
        if body_text.strip():
            return body_text.strip()
        if html_text:
            import re as _re
            cleaned = _re.sub(r"<[^>]+>", " ", html_text)
            cleaned = _re.sub(r"\s+", " ", cleaned).strip()
            return cleaned
        return ""


def scan_inbox(host: str, port: int, username: str, password: str,
               folder: str = "INBOX", hours: int = 24, max_emails: int = 50) -> list:
    scanner = InboxScanner()
    if not scanner.connect(host, port, username, password):
        return []
    try:
        return scanner.fetch_recent(folder, hours, max_emails)
    finally:
        scanner.disconnect()


def scan_unseen(host: str, port: int, username: str, password: str,
                folder: str = "INBOX", max_emails: int = 50) -> list:
    scanner = InboxScanner()
    if not scanner.connect(host, port, username, password):
        return []
    try:
        return scanner.scan_by_criteria(folder, "UNSEEN", max_emails)
    finally:
        scanner.disconnect()
