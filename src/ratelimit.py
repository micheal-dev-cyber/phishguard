import time
from collections import defaultdict
from threading import Lock

_rate_store = defaultdict(list)
_lock = Lock()


def check_rate_limit(key: str, max_requests: int = 30, window: int = 60) -> bool:
    """
    Returns True if the request is allowed, False if rate limited.
    Allows up to `max_requests` in a rolling `window` (seconds).
    """
    now = time.time()
    cutoff = now - window

    with _lock:
        timestamps = _rate_store[key]
        timestamps[:] = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= max_requests:
            return False
        timestamps.append(now)
        return True


def get_rate_limit_remaining(key: str, max_requests: int = 30, window: int = 60) -> int:
    now = time.time()
    cutoff = now - window
    with _lock:
        timestamps = [t for t in _rate_store[key] if t > cutoff]
        return max(0, max_requests - len(timestamps))


def get_rate_limit_reset(key: str, window: int = 60) -> int:
    with _lock:
        timestamps = _rate_store.get(key, [])
        if not timestamps:
            return 0
        return int(window - (time.time() - timestamps[0]))
