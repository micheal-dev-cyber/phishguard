import pytest
import sqlite3
from pathlib import Path
from src.webhook_routing import (
    init_webhook_routes, set_webhook_route, delete_webhook_route,
    get_webhook_routes, get_webhook_url, enable_route, EVENT_TYPES,
)

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


@pytest.fixture(autouse=True)
def setup():
    init_webhook_routes()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM webhook_routes")
    conn.commit()
    conn.close()
    yield


def test_set_and_get():
    assert set_webhook_route("wh_user", "critical_alert", "https://hooks.example.com/critical")
    routes = get_webhook_routes("wh_user")
    assert len(routes) == 1
    assert routes[0]["event_type"] == "critical_alert"


def test_get_url():
    set_webhook_route("wh_user2", "high_alert", "https://hooks.example.com/high")
    url = get_webhook_url("wh_user2", "high_alert")
    assert url == "https://hooks.example.com/high"
    missing = get_webhook_url("wh_user2", "critical_alert")
    assert missing is None


def test_delete():
    set_webhook_route("del_user", "scan_complete", "https://hooks.example.com/scan")
    assert delete_webhook_route("del_user", "scan_complete") is True
    routes = get_webhook_routes("del_user")
    assert len(routes) == 0


def test_enable_disable():
    set_webhook_route("toggle_user", "daily_digest", "https://hooks.example.com/daily")
    all_routes = get_webhook_routes("toggle_user")
    route_id = all_routes[0]["id"]
    assert enable_route(route_id, False) is True
    url = get_webhook_url("toggle_user", "daily_digest")
    assert url is None
    assert enable_route(route_id, True) is True
    url = get_webhook_url("toggle_user", "daily_digest")
    assert url == "https://hooks.example.com/daily"


def test_event_types_defined():
    assert "critical_alert" in EVENT_TYPES
    assert "scan_complete" in EVENT_TYPES
    assert "daily_digest" in EVENT_TYPES
    assert len(EVENT_TYPES) >= 9
