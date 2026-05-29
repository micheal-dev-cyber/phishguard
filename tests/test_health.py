import pytest
import sqlite3
from pathlib import Path
from src.health import (
    init_health, check_database, check_disk, run_all_checks,
    get_health_summary, run_backup, list_backups,
)

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


@pytest.fixture(autouse=True)
def setup():
    init_health()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM health_checks")
    conn.commit()
    conn.close()
    yield


def test_check_database():
    result = check_database()
    assert result["component"] == "database"
    assert result["status"] in ("healthy", "degraded", "down")


def test_check_disk():
    result = check_disk()
    assert result["component"] == "disk"
    assert "DB:" in result["message"]


def test_run_all_checks():
    results = run_all_checks()
    assert len(results) >= 3
    components = [r["component"] for r in results]
    assert "database" in components
    assert "disk" in components


def test_health_summary():
    summary = get_health_summary()
    assert "status" in summary
    assert "checks" in summary
    assert len(summary["checks"]) >= 3


def test_backup():
    result = run_backup()
    assert result["success"] is True
    assert "size_mb" in result
    backups = list_backups()
    assert len(backups) >= 1
