"""
Health / status page — system uptime, DB health, queue status, component checks.

Also includes DB backup CLI utility.
"""
import json
import logging
import os
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("health")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"
BACKUP_DIR = Path(__file__).parent.parent / "backups"
HEALTH_TABLE = "health_checks"


def init_health():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {HEALTH_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            message TEXT DEFAULT '',
            checked_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()
    BACKUP_DIR.mkdir(exist_ok=True)


def check_database() -> dict:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sqlite_master")
        table_count = c.fetchone()[0]
        c.execute("PRAGMA integrity_check")
        integrity = c.fetchone()[0]
        conn.close()
        return {
            "component": "database",
            "status": "healthy" if integrity == "ok" else "degraded",
            "message": f"{table_count} tables, integrity: {integrity}",
        }
    except Exception as e:
        return {"component": "database", "status": "down", "message": str(e)}


def check_disk() -> dict:
    try:
        db_path = Path(DB_PATH)
        if db_path.exists():
            size_mb = db_path.stat().st_size / (1024 * 1024)
            free = shutil.disk_usage(db_path.parent).free / (1024 * 1024 * 1024)
            return {
                "component": "disk",
                "status": "healthy" if free > 0.1 else "degraded",
                "message": f"DB: {size_mb:.1f}MB, Free: {free:.1f}GB",
            }
        return {"component": "disk", "status": "unknown", "message": "DB not found"}
    except Exception as e:
        return {"component": "disk", "status": "down", "message": str(e)}


def check_task_queue() -> dict:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        c = conn.cursor()
        c.execute("SELECT status, COUNT(*) FROM task_queue GROUP BY status")
        rows = c.fetchall()
        conn.close()
        counts = {r[0]: r[1] for r in rows}
        pending = counts.get("pending", 0)
        failed = counts.get("failed", 0)
        status = "healthy" if failed == 0 else "degraded"
        return {
            "component": "task_queue",
            "status": status,
            "message": f"{pending} pending, {failed} failed",
        }
    except Exception as e:
        return {"component": "task_queue", "status": "unknown", "message": str(e)}


def check_redis() -> dict:
    try:
        from src.redis_cache import ping
        ok = ping()
        return {
            "component": "redis",
            "status": "healthy" if ok else "down",
            "message": "Redis connected" if ok else "Redis unreachable",
        }
    except Exception:
        return {"component": "redis", "status": "disabled", "message": "Redis not configured"}


def run_all_checks() -> list[dict]:
    checks = [check_database(), check_disk(), check_task_queue(), check_redis()]
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    for chk in checks:
        c.execute(
            f"INSERT INTO {HEALTH_TABLE} (component, status, message) VALUES (?, ?, ?)",
            (chk["component"], chk["status"], chk["message"]),
        )
    conn.commit()
    conn.close()
    return checks


def get_health_summary() -> dict:
    checks = run_all_checks()
    all_healthy = all(c["status"] == "healthy" for c in checks)
    return {
        "status": "healthy" if all_healthy else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "uptime": _get_uptime(),
    }


def _get_uptime() -> str:
    try:
        import subprocess
        if os.name == "nt":
            result = subprocess.run(["net", "statistics", "workstation"], capture_output=True, text=True, timeout=5)
            return result.stdout[:100] if result.stdout else "unknown"
        result = subprocess.run(["uptime", "-p"], capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except Exception:
        return "unknown"


def run_backup() -> dict:
    init_health()
    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"phishguard_backup_{timestamp}.db"
    try:
        shutil.copy2(str(DB_PATH), str(backup_path))
        size_mb = backup_path.stat().st_size / (1024 * 1024)
        logger.info("Backup created: %s (%.1fMB)", backup_path, size_mb)
        return {"success": True, "path": str(backup_path), "size_mb": round(size_mb, 1)}
    except Exception as e:
        logger.error("Backup failed: %s", e)
        return {"success": False, "error": str(e)}


def list_backups() -> list[dict]:
    BACKUP_DIR.mkdir(exist_ok=True)
    backups = []
    for f in sorted(BACKUP_DIR.glob("phishguard_backup_*.db"), reverse=True):
        backups.append({
            "filename": f.name,
            "size_mb": round(f.stat().st_size / (1024 * 1024), 1),
            "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
        })
    return backups


def restore_backup(backup_path: str) -> dict:
    src = Path(backup_path)
    if not src.exists():
        return {"success": False, "error": "Backup file not found"}
    try:
        shutil.copy2(str(src), str(DB_PATH))
        logger.info("Restored backup: %s", backup_path)
        return {"success": True, "path": str(DB_PATH)}
    except Exception as e:
        logger.error("Restore failed: %s", e)
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "backup":
        result = run_backup()
        print(json.dumps(result, indent=2))
    elif len(sys.argv) > 2 and sys.argv[1] == "restore":
        result = restore_backup(sys.argv[2])
        print(json.dumps(result, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "list":
        backups = list_backups()
        print(json.dumps(backups, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "check":
        summary = get_health_summary()
        print(json.dumps(summary, indent=2))
    else:
        print("Usage: python -m src.health [backup|restore <path>|list|check]")
