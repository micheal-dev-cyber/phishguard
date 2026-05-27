"""
PhishGuard AI — Automated IMAP Mailbox Parser

Polls a corporate inbox (e.g. report@secopsnode.com) via IMAP SSL,
extracts forwarded phishing emails, runs them through the detection
engine, and auto-replies to the reporter with a structured verdict.

Usage:
    IMAP_HOST=imap.example.com IMAP_USER=report@secopsnode.com \
    IMAP_PASS=secret SMTP_HOST=smtp.example.com SMTP_USER=noreply@secopsnode.com \
    SMTP_PASS=secret python workers/imap_worker.py
"""

import os
import sys
import time
import email
import logging
import imaplib
import smtplib
import html
from datetime import datetime
from email.message import EmailMessage
from email.utils import parsedate_to_datetime, formataddr, parseaddr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from src.detector import analyze_email

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] imap_worker: %(message)s",
)
logger = logging.getLogger("imap-worker")

POLL_INTERVAL = int(os.getenv("IMAP_POLL_INTERVAL", "30"))
PROCESSED_DIR = "PROCESSED"


def _env_or_die(name: str) -> str:
    val = os.getenv(name)
    if not val:
        logger.error("Required env var %s is not set", name)
        sys.exit(1)
    return val


def _decode_mime(part: bytes, charset: str = "utf-8") -> str:
    try:
        return part.decode(charset or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError):
        return part.decode("utf-8", errors="replace")


def _extract_text_from_msg(msg: email.message.Message) -> str:
    """Extract plain text body from an email message."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get_content_disposition() or "")
            if "attachment" in cd.lower():
                continue
            if ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body = _decode_mime(payload, charset)
                break
            elif ct == "text/html" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    raw = _decode_mime(payload, charset)
                    body = raw
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            body = _decode_mime(payload, charset)
    return body.strip() or ""


def _extract_forwarded_body(msg: email.message.Message) -> str:
    """Try to extract the original forwarded email body from a report.

    Handles common forwarding patterns: Begin forwarded message, ---Original
    Message---, > quoted text, etc.
    """
    raw = _extract_text_from_msg(msg)
    if not raw:
        return ""

    # Strip the forwarding wrapper — keep content after the forwarded delimiter
    for delimiter in [
        "begin forwarded message",
        "---original message---",
        "---------- forwarded message ----------",
        "---original message---",
    ]:
        idx = raw.lower().find(delimiter)
        if idx != -1:
            raw = raw[idx + len(delimiter):]
            break

    # Strip leading > quoted lines (common in reply-forward chains)
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(">"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _compose_verdict_reply(
    original_msg: email.message.Message,
    results: dict,
    reporter_email: str,
) -> EmailMessage:
    """Build a structured security verdict reply."""
    score = results.get("risk_score", 0)
    severity = results.get("severity", "LOW")
    keyword_hits = results.get("total_keyword_hits", 0)
    url_count = results.get("url_count", 0)
    susp_urls = results.get("suspicious_url_count", 0)
    keyword_matches = results.get("keyword_matches", {})

    status_icon = "🔴" if score >= 50 else "🟡" if score >= 25 else "🟢"
    threat_label = {
        "CRITICAL": "CRITICAL THREAT",
        "HIGH": "HIGH RISK",
        "MEDIUM": "MEDIUM RISK",
        "LOW": "LOW RISK",
    }.get(severity, "UNKNOWN")

    # Build indicator details
    indicator_lines = []
    for category, keywords in keyword_matches.items():
        indicator_lines.append(
            f"  • {category.upper()}: {', '.join(keywords[:5])}"
        )

    indicators_text = "\n".join(indicator_lines) if indicator_lines else "  • None detected"

    reply = EmailMessage()
    reply["In-Reply-To"] = original_msg.get("Message-ID", "")
    reply["References"] = original_msg.get("Message-ID", "")
    reply["Subject"] = f"[PhishGuard] Security Analysis Result — {severity}"
    reply["From"] = formataddr(("PhishGuard AI Security", reporter_email))
    reply["To"] = original_msg.get("From", "")

    reply.set_content(f"""\
{status_icon} PhishGuard AI — Automated Threat Analysis
=========================================================

Thank you for forwarding this email for analysis.

📊 THREAT ASSESSMENT
--------------------
Status:          {status_icon} {threat_label}
Risk Score:      {score}/100
Keyword Matches: {keyword_hits}
URLs Found:      {url_count}
Suspicious URLs: {susp_urls}

🔍 DETECTED INDICATORS
-----------------------
{indicators_text}

{'⚠️ RECOMMENDED ACTION' if score >= 50 else '✅ RECOMMENDED ACTION'}
{'-' * 40 if score >= 50 else '-' * 35}
{'Do not click any links in this email.'
 if score >= 50 else 'No immediate action required — remain vigilant.'}
{'Report to your IT security team immediately.'
 if score >= 50 else 'If you have concerns, forward to IT for review.'}

--
PhishGuard AI | SecOpsNode AI
Enterprise Threat Intelligence Platform
""")

    return reply


def _mark_as_processed(imap: imaplib.IMAP4_SSL, uid: bytes):
    """Move the processed email to the PROCESSED folder."""
    try:
        imap.create(PROCESSED_DIR)
    except imaplib.IMAP4.error:
        pass
    try:
        imap.uid("COPY", uid, PROCESSED_DIR)
        imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        imap.expunge()
    except Exception as exc:
        logger.warning("Could not move UID %s to processed: %s", uid, exc)


def poll_cycle(imap: imaplib.IMAP4_SSL, smtp_host: str, smtp_port: int,
               smtp_user: str, smtp_pass: str):
    """Single poll cycle: fetch unseen, analyse, reply, move."""
    try:
        imap.select("INBOX")
        result, data = imap.uid("SEARCH", None, "UNSEEN")
        if result != "OK" or not data or not data[0]:
            return

        uids = data[0].split()
        logger.info("Found %d unseen message(s)", len(uids))

        for uid in uids[:20]:
            try:
                result, msg_data = imap.uid("FETCH", uid, "(RFC822)")
                if result != "OK" or not msg_data or not msg_data[0]:
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                reporter = msg.get("From", "unknown@example.com")
                reporter_name, reporter_addr = parseaddr(reporter)
                subject = msg.get("Subject", "(No Subject)")

                logger.info("Processing report from %s: %s", reporter_addr, subject[:60])

                body = _extract_forwarded_body(msg)
                if not body:
                    logger.warning("No body content in UID %s — skipping", uid)
                    continue

                # Run detection engine
                results = analyze_email(body)
                logger.info(
                    "Analysis complete — Score: %s, Severity: %s",
                    results.get("risk_score"),
                    results.get("severity"),
                )

                # Compose and send reply
                reply = _compose_verdict_reply(msg, results, smtp_user)
                try:
                    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                        server.starttls()
                        server.login(smtp_user, smtp_pass)
                        server.send_message(reply)
                    logger.info("Verdict sent to %s", reporter_addr)
                except Exception as exc:
                    logger.error("SMTP send failed for %s: %s", reporter_addr, exc)
                    continue

                _mark_as_processed(imap, uid)

            except Exception as exc:
                logger.error("Error processing UID %s: %s", uid, exc)
                continue

    except imaplib.IMAP4.error as exc:
        logger.error("IMAP command failed: %s", exc)
    except Exception as exc:
        logger.error("Poll cycle error: %s", exc)


def main():
    logger.info("Starting PhishGuard IMAP Worker")

    imap_host = _env_or_die("IMAP_HOST")
    imap_user = _env_or_die("IMAP_USER")
    imap_pass = _env_or_die("IMAP_PASS")
    smtp_host = _env_or_die("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = _env_or_die("SMTP_USER")
    smtp_pass = _env_or_die("SMTP_PASS")

    logger.info("IMAP server: %s | SMTP server: %s", imap_host, smtp_host)

    consecutive_errors = 0

    while True:
        imap = None
        try:
            imap = imaplib.IMAP4_SSL(imap_host, timeout=30)
            imap.login(imap_user, imap_pass)
            logger.info("Connected and authenticated to %s", imap_host)

            poll_cycle(imap, smtp_host, smtp_port, smtp_user, smtp_pass)

            consecutive_errors = 0

        except imaplib.IMAP4.abort as exc:
            consecutive_errors += 1
            logger.error("IMAP connection aborted (%d): %s", consecutive_errors, exc)
        except imaplib.IMAP4.error as exc:
            consecutive_errors += 1
            logger.error("IMAP login/connection error (%d): %s", consecutive_errors, exc)
        except Exception as exc:
            consecutive_errors += 1
            logger.error("Unexpected error (%d): %s", consecutive_errors, exc)
        finally:
            if imap:
                try:
                    imap.logout()
                except Exception:
                    pass

        # Exponential back-off on repeated failures
        if consecutive_errors >= 5:
            wait = min(consecutive_errors * 60, 1800)
            logger.warning("Back-off: waiting %d seconds after %d consecutive errors",
                          wait, consecutive_errors)
            time.sleep(wait)
        else:
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
