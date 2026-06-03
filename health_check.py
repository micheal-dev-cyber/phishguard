"""
PhishGuard AI — Health Check / Monitoring Utility

Run on a schedule (cron, systemd timer, UptimeRobot) to verify the app is alive.

Usage:
    python health_check.py                    # check all local services
    python health_check.py --url https://huggingface.co/spaces/Sabersouihi/phishguard-ai
    python health_check.py --db-only
"""

import os
import sys
import json
import urllib.request
import urllib.error
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = os.getenv("DATABASE_URL", "data/phishguard.db")


def check_database() -> tuple[bool, str]:
    try:
        if not Path(DB_PATH).exists():
            return False, f"Database file not found: {DB_PATH}"
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM analyses")
        count = c.fetchone()[0]
        conn.close()
        return True, f"Database OK ({count} analysis records)"
    except Exception as e:
        return False, f"Database error: {e}"


def check_http(url: str, timeout: int = 10) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return True, f"HTTP 200 — {url}"
            return False, f"HTTP {resp.status} — {url}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code} — {url}"
    except Exception as e:
        return False, f"Connection failed — {url}: {e}"


def main():
    targets = []
    args = sys.argv[1:]

    if "--db-only" in args:
        ok, msg = check_database()
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
        sys.exit(0 if ok else 1)

    if "--url" in args:
        idx = args.index("--url")
        if idx + 1 < len(args):
            targets.append(args[idx + 1])
    else:
        targets = [
            os.getenv("APP_URL", "http://127.0.0.1:8501"),
            os.getenv("API_URL", "http://127.0.0.1:8080"),
        ]

    all_ok = True

    for url in targets:
        ok, msg = check_http(url)
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
        if not ok:
            all_ok = False

    ok, msg = check_database()
    print(f"[{'OK' if ok else 'FAIL'}] {msg}")
    if not ok:
        all_ok = False

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
