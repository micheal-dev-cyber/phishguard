import pytest
import time
import uuid
from src.task_queue import init_task_queue, enqueue, register_task, get_pending_count, get_failed_tasks, start_worker

_results = []


def _test_handler(payload):
    _results.append(payload.get("value", 0))


@pytest.fixture(autouse=True)
def reset():
    global _results
    _results = []
    register_task("test_job_" + str(uuid.uuid4())[:8], _test_handler)
    yield


def test_enqueue():
    init_task_queue()
    start_worker()
    tid = enqueue("test_job", {"value": 42}, delay_seconds=0, max_retries=0)
    assert tid > 0


def test_pending_count():
    init_task_queue()
    count = get_pending_count()
    assert isinstance(count, int)


def test_failed_tasks():
    init_task_queue()
    task_name = "nonexistent_" + str(uuid.uuid4())[:8]
    tid = enqueue(task_name, {}, max_retries=0)
    time.sleep(4)
    failed = get_failed_tasks()
    names = [f[1] for f in failed]
    assert task_name in names
