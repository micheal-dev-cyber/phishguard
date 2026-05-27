"""Tests for tenant management — pure Python, no streamlit dependency."""

import os
import pytest
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Point to a temp DB for test isolation
import src.tenants as tenants_mod
import src.database as db_mod


class TestTenantManagement:
    """Test tenant CRUD operations with isolated temp database."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        monkeypatch.setattr(tenants_mod, "DB_PATH", str(self.db_path))
        monkeypatch.setattr(tenants_mod, "DB_PATH", str(self.db_path))
        # Re-init with new path
        tenants_mod.init_tenants()

    def test_create_tenant(self):
        ok = tenants_mod.create_tenant("testuser", "secret123")
        assert ok is True

    def test_create_duplicate_tenant(self):
        tenants_mod.create_tenant("dupuser", "password1")
        ok = tenants_mod.create_tenant("dupuser", "password2")
        assert ok is False

    def test_verify_tenant_success(self):
        tenants_mod.create_tenant("alice", "p@ssword")
        tenant = tenants_mod.verify_tenant("alice", "p@ssword")
        assert tenant is not None
        assert tenant["username"] == "alice"
        assert tenant["is_active"] == 1

    def test_verify_tenant_wrong_password(self):
        tenants_mod.create_tenant("bob", "correct")
        tenant = tenants_mod.verify_tenant("bob", "wrong")
        assert tenant is None

    def test_verify_tenant_nonexistent(self):
        tenant = tenants_mod.verify_tenant("nobody", "password")
        assert tenant is None

    def test_update_tenant_plan(self):
        tenants_mod.create_tenant("upgrade_user", "pass")
        tenants_mod.update_tenant("upgrade_user", plan="business")
        t = tenants_mod.verify_tenant("upgrade_user", "pass")
        assert t["plan"] == "business"

    def test_suspend_tenant(self):
        tenants_mod.create_tenant("suspend_me", "pass")
        tenants_mod.update_tenant("suspend_me", is_active=0)
        t = tenants_mod.verify_tenant("suspend_me", "pass")
        assert t is None  # verify_tenant returns None if not active

    def test_set_password(self):
        tenants_mod.create_tenant("pw_user", "oldpass")
        tenants_mod.set_password("pw_user", "newpass")
        t1 = tenants_mod.verify_tenant("pw_user", "oldpass")
        t2 = tenants_mod.verify_tenant("pw_user", "newpass")
        assert t1 is None
        assert t2 is not None

    def test_delete_tenant(self):
        tenants_mod.create_tenant("delete_me", "pass")
        tenants_mod.delete_tenant("delete_me")
        t = tenants_mod.verify_tenant("delete_me", "pass")
        assert t is None

    def test_get_all_tenants(self):
        tenants_mod.create_tenant("user_a", "pass1")
        tenants_mod.create_tenant("user_b", "pass2")
        all_t = tenants_mod.get_all_tenants()
        usernames = [r[1] for r in all_t]
        assert "user_a" in usernames
        assert "user_b" in usernames

    def test_log_and_check_usage(self):
        tenants_mod.create_tenant("heavy_user", "pass", plan="business")
        from datetime import datetime

        tenants_mod.log_usage("heavy_user", "analysis", 75)
        tenants_mod.log_usage("heavy_user", "analysis", 50)
        usage = tenants_mod.get_usage("heavy_user")
        assert usage["analyses"] >= 2

    def test_check_quota(self):
        tenants_mod.create_tenant("quota_user", "pass", plan="starter")
        q = tenants_mod.check_quota("quota_user", "starter")
        assert q["limit"] == 100  # starter plan
        assert q["usage"] >= 0
        assert q["remaining"] > 0
