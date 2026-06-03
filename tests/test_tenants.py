"""Tests for tenant management — bcrypt, lockout, CRUD."""

import os
import pytest
import sys
import time
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import src.tenants as tenants_mod


class TestTenantManagement:
    """Test tenant CRUD operations with isolated temp database."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        import src.db; monkeypatch.setattr(src.db, "DB_PATH", str(self.db_path))
        tenants_mod.init_tenants()

    def test_create_tenant(self):
        assert tenants_mod.create_tenant("testuser", "secret123") is True

    def test_create_duplicate_tenant(self):
        tenants_mod.create_tenant("dupuser", "password1")
        assert tenants_mod.create_tenant("dupuser", "password2") is False

    def test_verify_tenant_success(self):
        tenants_mod.create_tenant("alice", "p@ssword")
        tenant = tenants_mod.verify_tenant("alice", "p@ssword")
        assert tenant is not None
        assert tenant["username"] == "alice"
        assert tenant["is_active"] == 1

    def test_verify_tenant_wrong_password(self):
        tenants_mod.create_tenant("bob", "correct")
        assert tenants_mod.verify_tenant("bob", "wrong") is None

    def test_verify_tenant_nonexistent(self):
        assert tenants_mod.verify_tenant("nobody", "password") is None

    def test_verify_suspended_returns_dict(self):
        tenants_mod.create_tenant("suspend_me", "pass")
        tenants_mod.update_tenant("suspend_me", is_active=0)
        result = tenants_mod.verify_tenant("suspend_me", "pass")
        assert result == {"error": "suspended"}

    def test_update_tenant_plan(self):
        tenants_mod.create_tenant("upgrade_user", "pass")
        tenants_mod.update_tenant("upgrade_user", plan="business")
        t = tenants_mod.verify_tenant("upgrade_user", "pass")
        assert t["plan"] == "business"

    def test_set_password(self):
        tenants_mod.create_tenant("pw_user", "oldpass")
        tenants_mod.set_password("pw_user", "newpass")
        assert tenants_mod.verify_tenant("pw_user", "oldpass") is None
        assert tenants_mod.verify_tenant("pw_user", "newpass") is not None

    def test_delete_tenant(self):
        tenants_mod.create_tenant("delete_me", "pass")
        tenants_mod.delete_tenant("delete_me")
        assert tenants_mod.verify_tenant("delete_me", "pass") is None

    def test_get_all_tenants(self):
        tenants_mod.create_tenant("user_a", "pass1")
        tenants_mod.create_tenant("user_b", "pass2")
        usernames = [r[1] for r in tenants_mod.get_all_tenants()]
        assert "user_a" in usernames
        assert "user_b" in usernames

    def test_log_and_check_usage(self):
        tenants_mod.create_tenant("heavy_user", "pass", plan="business")
        tenants_mod.log_usage("heavy_user", "analysis", 75)
        tenants_mod.log_usage("heavy_user", "analysis", 50)
        usage = tenants_mod.get_usage("heavy_user")
        assert usage["analyses"] >= 2

    def test_check_quota(self):
        tenants_mod.create_tenant("quota_user", "pass", plan="starter")
        q = tenants_mod.check_quota("quota_user", "starter")
        assert q["limit"] == 100
        assert q["usage"] >= 0
        assert q["remaining"] > 0


class TestLoginLockout:
    """Test brute-force lockout behaviour."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "lockout_test.db"
        import src.db; monkeypatch.setattr(src.db, "DB_PATH", str(self.db_path))
        monkeypatch.setattr(tenants_mod, "MAX_LOGIN_ATTEMPTS", 3)
        monkeypatch.setattr(tenants_mod, "LOCKOUT_WINDOW", 30)
        tenants_mod.init_tenants()
        tenants_mod.create_tenant("lockme", "sekret")

    def test_lockout_after_n_failures(self):
        for _ in range(3):
            tenants_mod.verify_tenant("lockme", "wrong")
        assert tenants_mod.is_locked_out("lockme") is True

    def test_locked_out_returns_error_dict(self):
        for _ in range(3):
            tenants_mod.verify_tenant("lockme", "wrong")
        result = tenants_mod.verify_tenant("lockme", "sekret")
        assert isinstance(result, dict)
        assert result.get("error") == "locked_out"
        assert "remaining" in result

    def test_unlock_clears_lockout(self):
        for _ in range(3):
            tenants_mod.verify_tenant("lockme", "wrong")
        assert tenants_mod.is_locked_out("lockme") is True
        tenants_mod.unlock_user("lockme")
        assert tenants_mod.is_locked_out("lockme") is False

    def test_correct_password_resets_lockout(self):
        for _ in range(2):
            tenants_mod.verify_tenant("lockme", "wrong")
        tenants_mod.verify_tenant("lockme", "sekret")
        assert tenants_mod.is_locked_out("lockme") is False

    def test_lockout_window_expires(self, monkeypatch):
        for _ in range(3):
            tenants_mod.verify_tenant("lockme", "wrong")
        assert tenants_mod.is_locked_out("lockme") is True
        fake_future = time.time() + 31
        monkeypatch.setattr(time, "time", lambda: fake_future)
        assert tenants_mod.is_locked_out("lockme") is False
