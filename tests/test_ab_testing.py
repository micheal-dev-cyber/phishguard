import pytest
import uuid
from src.ab_testing import ABTest, list_active_tests, stop_test


def test_create_and_record():
    uid = str(uuid.uuid4())[:8]
    test = ABTest(f"test_boost_{uid}", owner="pytest",
                  control_config={"rules": []}, variant_config={"rules": [{"name": "boost_test", "type": "keyword", "pattern": "urgent", "boost": 15}]})
    assert test.test_id > 0
    test.record_scan("control", risk_score=45, is_phishing=True, user_flagged=False)
    test.record_scan("variant", risk_score=72, is_phishing=True, user_flagged=True)
    results = test.get_results()
    assert results["total_scans"] == 2
    assert "control" in results["variants"]
    assert "variant" in results["variants"]
    assert results["variants"]["variant"]["avg_score"] == 72.0


def test_list_active():
    uid = str(uuid.uuid4())[:8]
    ABTest(f"list_test_{uid}", owner="pytest")
    active = list_active_tests()
    names = [t["test_name"] for t in active]
    assert f"list_test_{uid}" in names


def test_stop():
    uid = str(uuid.uuid4())[:8]
    ABTest(f"stop_test_{uid}", owner="pytest")
    stop_test(f"stop_test_{uid}")
    active = list_active_tests()
    names = [t["test_name"] for t in active]
    assert f"stop_test_{uid}" not in names
