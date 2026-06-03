"""
Server-Sent Events (SSE) notification system.

Replaces 30s polling with push-based notifications via a Streamlit component bridge.
Uses a simple in-memory event queue flushed periodically.
"""
import queue
import threading
import time
from datetime import datetime, timezone

_events: dict[str, queue.Queue] = {}
_lock = threading.Lock()
_cleanup_interval = 300


def _get_queue(username: str) -> queue.Queue:
    with _lock:
        if username not in _events:
            _events[username] = queue.Queue(maxsize=100)
        return _events[username]


def push_event(username: str, event_type: str, data: dict):
    q = _get_queue(username)
    payload = {
        "type": event_type,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        q.put_nowait(payload)
    except queue.Full:
        pass


def pop_events(username: str) -> list[dict]:
    q = _get_queue(username)
    events = []
    while not q.empty():
        try:
            events.append(q.get_nowait())
        except queue.Empty:
            break
    return events


def get_event_count(username: str) -> int:
    q = _get_queue(username)
    return q.qsize()


def cleanup_stale_queues(max_age: float = 3600):
    now = time.time()
    with _lock:
        stale = [k for k, v in _events.items()
                 if hasattr(v, "_last_access") and now - getattr(v, "_last_access", 0) > max_age]
        for k in stale:
            del _events[k]


def render_sse_script(username: str, check_interval: int = 5, origin: str = "") -> str:
    target_origin = origin if origin else "window.location.origin"
    return f"""
    <script>
    (function() {{
        let lastId = 0;
        const targetOrigin = {target_origin};
        function poll() {{
            fetch('/_sse_events?username={username}&after=' + lastId + '&t=' + Date.now())
                .then(r => r.json())
                .then(events => {{
                    if (events && events.length) {{
                        lastId = events[events.length - 1].timestamp;
                        window.parent.postMessage({{type: 'sse_events', events: events}}, targetOrigin);
                    }}
                }})
                .catch(() => {{}});
        }}
        setInterval(poll, {check_interval * 1000});
        poll();
    }})();
    </script>
    """
