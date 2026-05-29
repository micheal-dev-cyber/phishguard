import pytest
import time
import uuid
from src.task_queue import (init_task_queue, enqueue, register_task,
                             get_pending_count, get_failed_tasks,
                             start_worker, wait_for_completion)

_results = []


def _test_handler(payload):
    _results.append(payload.get("value", 0))


@pytest.fixture(autouse=True)
def reset():
    global _results
    _results = []
    init_task_queue()
    start_worker()
    yield


def test_enqueue_and_wait():
    uid = str(uuid.uuid4())[:8]
    name = f"test_wait_{uid}"
    register_task(name, _test_handler)
    tid = enqueue(name, {"value": 42}, delay_seconds=0, max_retries=0)
    assert tid > 0
    status = wait_for_completion(tid, timeout=8)
    assert status == "completed", f"Expected completed, got {status}"
    assert 42 in _results


def test_pending_count():
    count = get_pending_count()
    assert isinstance(count, int)


def test_failed_tasks():
    uid = str(uuid.uuid4())[:8]
    task_name = "nonexistent_" + uid
    tid = enqueue(task_name, {}, max_retries=0)
    status = wait_for_completion(tid, timeout=8)
    assert status == "failed"
    failed = get_failed_tasks()
    names = [f[1] for f in failed]
    assert task_name in names
