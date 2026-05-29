import pytest
from src.redis_cache import get, set, delete, REDIS_ENABLED


def test_get_set():
    if not REDIS_ENABLED:
        pytest.skip("Redis not enabled")
    set("test_key", {"hello": "world"}, ttl=10)
    assert get("test_key") == {"hello": "world"}
    delete("test_key")
    assert get("test_key") is None


def test_missing_key():
    if not REDIS_ENABLED:
        pytest.skip("Redis not enabled")
    assert get("nonexistent_key_xyz") is None
