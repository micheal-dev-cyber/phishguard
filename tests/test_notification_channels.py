import pytest
import sqlite3
from pathlib import Path
from src.notification_channels import (
    init_channels, set_channel, delete_channel, get_channels,
    enable_channel, SUPPORTED_CHANNELS,
)

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


@pytest.fixture(autouse=True)
def setup():
    init_channels()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM notification_channels")
    conn.commit()
    conn.close()
    yield


def test_set_and_get():
    assert set_channel("ch_user", "slack", "https://hooks.slack.com/test", notify_on="critical")
    channels = get_channels("ch_user")
    assert len(channels) == 1
    assert channels[0]["channel_type"] == "slack"


def test_delete():
    set_channel("del_user", "discord", "https://discord.com/api/webhooks/test")
    assert delete_channel("del_user", "discord") is True
    assert len(get_channels("del_user")) == 0


def test_enable_disable():
    set_channel("tog_user", "teams", "https://teams.webhook/test")
    assert enable_channel("tog_user", "teams", False) is True
    channels = get_channels("tog_user")
    assert channels[0]["enabled"] == 0
    assert enable_channel("tog_user", "teams", True) is True
    channels = get_channels("tog_user")
    assert channels[0]["enabled"] == 1


def test_unsupported_channel():
    assert set_channel("test_user", "telegram", "https://t.me/bot") is False


def test_supported_channels():
    assert "slack" in SUPPORTED_CHANNELS
    assert "teams" in SUPPORTED_CHANNELS
    assert "discord" in SUPPORTED_CHANNELS
    assert "pagerduty" in SUPPORTED_CHANNELS


def test_get_all():
    set_channel("user_a", "slack", "https://hooks.slack.com/a")
    set_channel("user_b", "discord", "https://discord.com/b")
    all_ch = get_channels()
    user_names = set(c["username"] for c in all_ch)
    assert "user_a" in user_names
    assert "user_b" in user_names
