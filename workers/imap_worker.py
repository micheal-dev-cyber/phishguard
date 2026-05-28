"""
PhishGuard AI — IMAP Worker

Usage:
    set IMAP_HOST=imap.gmail.com
    set IMAP_USER=user@gmail.com
    set IMAP_PASS=app-password
    python workers/imap_worker.py

Scans unseen inbox messages and prints verdicts.
"""
import os
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.inbox_scanner import scan_unseen
from src.enterprise_api import handle_scan_request

HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
PORT = int(os.getenv("IMAP_PORT", "993"))
USER = os.getenv("IMAP_USER", "")
PASS = os.getenv("IMAP_PASS", "")


def main():
    if not USER or not PASS:
        print("Set IMAP_USER and IMAP_PASS environment variables")
        sys.exit(1)

    print(f"Connecting to {HOST} as {USER}...")
    emails = scan_unseen(HOST, PORT, USER, PASS, max_emails=20)
    print(f"Found {len(emails)} unseen messages")

    for e in emails:
        print(f"\n--- {e.get('subject', '(no subject)')} ---")
        print(f"From: {e.get('sender', '')}")
        body = e.get("body", "")
        result = handle_scan_request({"text": body[:10000], "sender": e.get("sender", "")})
        v = result.get("verdict", {})
        score = v.get("risk_score", 0)
        severity = v.get("severity", "UNKNOWN")
        print(f"Verdict: {severity} ({score}/100)")
        print(f"AI-written: {v.get('ai_written_probability', 0):.0%}")
        print(f"AitM: {v.get('aitm_confidence', 0):.0%}")

    print("\nDone.")


if __name__ == "__main__":
    main()
