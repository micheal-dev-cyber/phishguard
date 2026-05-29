import pytest
import sqlite3
from pathlib import Path
from src.scheduler import (
    init_scheduler, create_schedule, list_schedules,
    delete_schedule, toggle_schedule, get_due_schedules, mark_run,
)

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


@pytest.fixture(autouse=True)
def setup():
    init_scheduler()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM scan_schedules")
    conn.commit()
    conn.close()
    yield


def test_create_and_list():
    sid = create_schedule("sched_test_user", mailbox="inbox", interval_minutes=30)
    assert sid > 0
    schedules = list_schedules("sched_test_user")
    assert len(schedules) == 1
    assert schedules[0]["interval_minutes"] == 30


def test_list_all():
    create_schedule("user_a", mailbox="inbox", interval_minutes=60)
    create_schedule("user_b", mailbox="inbox", interval_minutes=120)
    all_s = list_schedules()
    assert len(all_s) == 2


def test_delete():
    sid = create_schedule("del_user", mailbox="inbox", interval_minutes=15)
    assert delete_schedule(sid) is True
    assert len(list_schedules("del_user")) == 0


def test_toggle():
    sid = create_schedule("toggle_user", mailbox="inbox", interval_minutes=30)
    assert toggle_schedule(sid, False) is True
    schedules = list_schedules("toggle_user")
    assert schedules[0]["enabled"] == 0
    assert toggle_schedule(sid, True) is True
    schedules = list_schedules("toggle_user")
    assert schedules[0]["enabled"] == 1


def test_due_schedules():
    sid = create_schedule("due_user", mailbox="inbox", interval_minutes=0)
    due = get_due_schedules()
    assert any(s["id"] == sid for s in due)


def test_mark_run():
    sid = create_schedule("mark_user", mailbox="inbox", interval_minutes=60)
    mark_run(sid, 60)
    due = get_due_schedules()
    assert not any(s["id"] == sid for s in due)
