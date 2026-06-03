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


class TestSessionSecurity:
    """Regression tests for session security fixes."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "security_test.db"
        import src.db; monkeypatch.setattr(src.db, "DB_PATH", str(self.db_path))
        tenants_mod.init_tenants()

    def test_session_id_unpredictable(self):
        """Session IDs should be long, random, and different each time."""
        from src.session_manager import create_session, revoke_all_sessions
        sid1 = create_session("alice")
        sid2 = create_session("alice")
        sid3 = create_session("bob")
        revoke_all_sessions("alice")
        revoke_all_sessions("bob")
        assert len(sid1) >= 32, f"Session ID too short: {len(sid1)}"
        assert len(sid2) >= 32
        assert sid1 != sid2, "Two consecutive sessions for same user are identical"
        assert sid1 != sid3, "Sessions for different users are identical"

    def test_session_id_no_predictable_pattern(self):
        """Session IDs should not contain username, ip, or timestamp."""
        from src.session_manager import create_session, revoke_all_sessions
        sid = create_session("charlie", ip_address="192.168.1.1")
        revoke_all_sessions("charlie")
        assert "charlie" not in sid
        assert "192.168" not in sid

    def test_touch_session_stores_ip(self):
        """touch_session with ip_address should persist it."""
        from src.session_manager import create_session, touch_session, list_sessions, revoke_all_sessions
        sid = create_session("dave", ip_address="10.0.0.1")
        touch_session(sid, ip_address="10.0.0.2")
        sessions = list_sessions("dave")
        revoke_all_sessions("dave")
        matching = [s for s in sessions if s["is_active"]]
        assert any("10.0.0.2" in s["ip"] for s in matching), "IP not updated"

    def test_revoke_all_sessions_clears_active(self):
        """revoke_all_sessions should mark all user sessions inactive."""
        from src.session_manager import create_session, revoke_all_sessions, list_sessions
        create_session("eve")
        create_session("eve")
        revoke_all_sessions("eve")
        sessions = list_sessions("eve")
        active = [s for s in sessions if s["is_active"]]
        assert len(active) == 0, f"Expected 0 active sessions, got {len(active)}"

    def test_revoke_all_sessions_invalid_table_does_not_crash(self):
        """revoke_all_sessions should handle missing sessions table."""
        from src.session_manager import revoke_all_sessions
        revoke_all_sessions("nonexistent_user")

    def test_set_password_revokes_sessions(self):
        """set_password should call revoke_all_sessions."""
        from src.session_manager import create_session, list_sessions
        tenants_mod.create_tenant("pwsec_user", "oldpass")
        sid = create_session("pwsec_user")
        tenants_mod.set_password("pwsec_user", "newpass")
        sessions = list_sessions("pwsec_user")
        active = [s for s in sessions if s["is_active"]]
        assert len(active) == 0, "Sessions still active after password change"

    def test_email_verification_default_unverified(self):
        """New tenants should not be email-verified by default."""
        from src.email_verify import is_email_verified
        tenants_mod.create_tenant("unverified_user", "pass", email="test@example.com")
        assert not is_email_verified("unverified_user")

    def test_email_verification_flow(self):
        """create_verification + verify_email_token should mark as verified."""
        from src.email_verify import create_verification, is_email_verified, verify_email_token
        tenants_mod.create_tenant("verify_user", "pass", email="v@example.com")
        assert not is_email_verified("verify_user")
        result = create_verification("verify_user", "v@example.com")
        assert verify_email_token(result["token"])
        assert is_email_verified("verify_user")
