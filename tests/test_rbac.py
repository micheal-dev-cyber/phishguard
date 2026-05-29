"""
Tests for the RBAC permissions module.
"""

import pytest
from src.rbac import (
    init_rbac, check_permission, get_user_role,
    get_base_permissions, get_effective_permissions,
    grant_permission, revoke_permission,
    list_all_permissions, ROLE_PERMISSIONS,
)


@pytest.fixture(autouse=True)
def setup():
    init_rbac()
    yield


def test_base_permissions_viewer():
    perms = get_base_permissions("nonexistent_user")
    assert perms == ROLE_PERMISSIONS["viewer"]


def test_base_permissions_roles():
    for role, expected in ROLE_PERMISSIONS.items():
        role_user = f"test_{role}"
        from src.database import init_db
        import sqlite3
        from pathlib import Path
        _db = Path(__file__).parent.parent / "data" / "phishguard.db"
        conn = sqlite3.connect(str(_db))
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, 'x', ?)",
            (role_user, role),
        )
        conn.commit()
        conn.close()
        perms = get_base_permissions(role_user)
        assert perms == expected, f"Mismatch for role {role}: {perms} != {expected}"


def test_grant_and_revoke():
    init_rbac()
    grant_permission("test_user", "export")
    eff = get_effective_permissions("test_user")
    assert "export" in eff
    revoke_permission("test_user", "view_history")
    eff2 = get_effective_permissions("test_user")
    assert "view_history" not in eff2


def test_check_permission():
    init_rbac()
    assert check_permission("test_user", "nonexistent_perm") is False
    grant_permission("test_user", "manage_billing")
    assert check_permission("test_user", "manage_billing") is True


def test_list_all_permissions():
    all_perms = list_all_permissions()
    assert "scan" in all_perms
    assert "export" in all_perms
    assert "manage_users" in all_perms
    assert "manage_campaigns" in all_perms


def test_admin_has_all():
    from src.database import init_db
    import sqlite3
    from pathlib import Path
    _db = Path(__file__).parent.parent / "data" / "phishguard.db"
    conn = sqlite3.connect(str(_db))
    c = conn.cursor()
    c.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES ('admin_test', 'x', 'admin')",
    )
    conn.commit()
    conn.close()
    eff = get_effective_permissions("admin_test")
    for perm in list_all_permissions():
        assert perm in eff, f"Admin should have {perm}"
