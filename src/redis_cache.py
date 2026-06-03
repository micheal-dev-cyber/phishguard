import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger("redis-cache")

_pool = None
_client = None

REDIS_ENABLED = os.getenv("REDIS_ENABLED", "").lower() in ("1", "true", "yes")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL = int(os.getenv("REDIS_CACHE_TTL", "300"))


def _get_client():
    global _client, _pool
    if _client is not None:
        return _client
    if not REDIS_ENABLED:
        return None
    try:
        import redis as _redis
        _pool = _redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
        _client = _redis.Redis(connection_pool=_pool)
        _client.ping()
        logger.info("Connected to Redis at %s", REDIS_URL)
        return _client
    except ImportError:
        logger.debug("redis-py not installed; caching disabled")
        return None
    except Exception as e:
        logger.warning("Redis connection failed: %s", e)
        return None


def get(key: str) -> Optional[Any]:
    client = _get_client()
    if client is None:
        return None
    try:
        val = client.get(key)
        return json.loads(val) if val else None
    except Exception as e:
        logger.debug("Redis get(%s) failed: %s", key, e)
        return None


def set(key: str, value: Any, ttl: int = CACHE_TTL) -> bool:
    client = _get_client()
    if client is None:
        return False
    try:
        client.setex(key, ttl, json.dumps(value))
        return True
    except Exception as e:
        logger.debug("Redis set(%s) failed: %s", key, e)
        return False


def delete(key: str) -> bool:
    client = _get_client()
    if client is None:
        return False
    try:
        client.delete(key)
        return True
    except Exception as e:
        logger.debug("Redis delete(%s) failed: %s", key, e)
        return False


def flush_pattern(pattern: str = "*") -> bool:
    client = _get_client()
    if client is None:
        return False
    try:
        for key in client.scan_iter(match=pattern):
            client.delete(key)
        return True
    except Exception as e:
        logger.debug("Redis flush_pattern(%s) failed: %s", pattern, e)
        return False


def memoize(ttl: int = CACHE_TTL):
    def decorator(func):
        def wrapper(*args, **kwargs):
            key_parts = [func.__name__] + [str(a) for a in args] + [f"{k}={v}" for k, v in sorted(kwargs.items())]
            cache_key = ":".join(key_parts)
            cached = get(cache_key)
            if cached is not None:
                return cached
            result = func(*args, **kwargs)
            set(cache_key, result, ttl)
            return result
        return wrapper
    return decorator
