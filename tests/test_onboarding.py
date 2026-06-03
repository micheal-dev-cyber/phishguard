"""Tests for onboarding wizard — checklist, plan activation."""

import pytest
import sys
import sqlite3
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestOnboarding:
    """Onboarding tests with isolated temp DB."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self._db_path = str(Path(self.tmpdir) / "onboarding_test.db")
        self._real_connect = sqlite3.connect

        def _fake_connect(db_path, *a, **kw):
            return self._real_connect(self._db_path, *a, **kw)
        monkeypatch.setattr(sqlite3, "connect", _fake_connect)
        from src import tenants
        import src.db; monkeypatch.setattr(src.db, "DB_PATH", self._db_path)
        # Note: sqlite3.connect is also monkeypatched globally, so
        # get_connection() from src.db will redirect to the temp DB.
        tenants.init_tenants()

    def test_get_onboarding_steps_all_incomplete(self):
        from src.onboarding import get_onboarding_steps
        steps = get_onboarding_steps("new_user")
        assert len(steps) == 5
        assert all(s["done"] is False for s in steps)

    def test_complete_onboarding_step(self):
        from src.onboarding import complete_onboarding_step, get_onboarding_steps
        complete_onboarding_step("new_user", "first_scan")
        steps = get_onboarding_steps("new_user")
        first_scan = [s for s in steps if s["step"] == "first_scan"][0]
        assert first_scan["done"] is True

    def test_complete_multiple_steps(self):
        from src.onboarding import complete_onboarding_step, get_onboarding_steps
        complete_onboarding_step("multi_user", "connect_email")
        complete_onboarding_step("multi_user", "first_scan")
        steps = get_onboarding_steps("multi_user")
        done_steps = [s for s in steps if s["done"]]
        assert len(done_steps) == 2

    def test_activate_plan(self):
        from src.onboarding import activate_plan
        from src.tenants import create_tenant, verify_tenant
        create_tenant("plan_user", "pass", plan="trial")
        result = activate_plan("plan_user", "business", order_id="ord_123")
        assert result is True
        t = verify_tenant("plan_user", "pass")
        assert t["plan"] == "business"

    def test_create_checkout_session_stripe_not_configured(self, monkeypatch):
        from src.onboarding import create_checkout_session
        from src.env import ENV
        monkeypatch.setattr(ENV, "STRIPE_SECRET_KEY", "")
        result = create_checkout_session("starter", "user_x", "x@y.com", provider="stripe")
        assert "error" in result
        assert "not configured" in result["error"]

    def test_activate_plan_creates_subscription(self):
        from src.onboarding import activate_plan
        from src.tenants import create_tenant
        create_tenant("sub_user", "pass")
        activate_plan("sub_user", "business", order_id="ord_456")
        conn = self._real_connect(self._db_path)
        c = conn.cursor()
        c.execute("SELECT username, plan, order_id, status FROM subscriptions")
        rows = c.fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][0] == "sub_user"
        assert rows[0][1] == "business"
        assert rows[0][2] == "ord_456"
        assert rows[0][3] == "active"
