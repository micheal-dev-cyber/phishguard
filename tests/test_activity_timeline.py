import pytest
from src.activity_timeline import (
    init_activity_timeline, record_activity, get_activity,
    get_all_activity, get_activity_summary,
)


@pytest.fixture(autouse=True)
def setup():
    init_activity_timeline()
    # Clean table between runs
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM activity_timeline")
    conn.commit()
    conn.close()
    yield


import sqlite3
from pathlib import Path
DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def test_record_and_get():
    record_activity("timeline_user", "login", detail="Logged in from Chrome",
                    ip_address="192.168.1.1", severity="info")
    activity = get_activity("timeline_user")
    assert len(activity) == 1
    assert activity[0]["action"] == "login"
    assert activity[0]["ip_address"] == "192.168.1.1"


def test_get_all():
    record_activity("user_a", "scan", detail="Scanned email")
    record_activity("user_b", "export", detail="Exported CSV")
    all_activity = get_all_activity()
    assert len(all_activity) >= 2


def test_filter_by_action():
    record_activity("filter_user", "login", detail="Login")
    record_activity("filter_user", "scan", detail="Scan")
    record_activity("filter_user", "login", detail="Login again")
    logins = get_activity("filter_user", action_filter="login")
    assert len(logins) == 2
    assert all(a["action"] == "login" for a in logins)


def test_summary():
    record_activity("summary_user", "login", detail="Login event")
    record_activity("summary_user", "scan", detail="Scan email")
    record_activity("summary_user", "scan", detail="Scan another")
    summary = get_activity_summary("summary_user", days=30)
    assert summary.get("login") == 1
    assert summary.get("scan") == 2
