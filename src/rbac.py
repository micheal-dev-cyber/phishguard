"""
Granular RBAC permissions system.

Provides per-action permission checks beyond the existing role-based system.
Roles are: viewer, analyst, admin.
Permissions are: scan, view_history, export, manage_users, manage_settings, etc.

Usage:
    from src.rbac import check_permission, require_permission
    if not check_permission(username, "export"):
        st.error("Permission denied")
"""

from src.db import get_connection

ROLE_PERMISSIONS = {
    "viewer": {
        "scan", "view_history", "view_analytics",
    },
    "analyst": {
        "scan", "view_history", "view_analytics", "export",
        "manage_rules", "manage_ip_allowlist", "view_admin",
    },
    "admin": {
        "scan", "view_history", "view_analytics", "export",
        "manage_rules", "manage_ip_allowlist", "view_admin",
        "manage_users", "manage_settings", "manage_billing",
        "manage_workspaces", "delete_data", "manage_api_keys",
        "view_audit_log", "manage_integrations", "manage_campaigns",
    },
}

# Overridable per-user permissions stored in DB
PERMISSION_OVERRIDES_TABLE = "user_permissions"


def init_rbac():
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {PERMISSION_OVERRIDES_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            permission TEXT NOT NULL,
            granted INTEGER DEFAULT 1,
            UNIQUE(username, permission)
        )
    """)
    conn.commit()
    conn.close()


def get_user_role(username: str) -> str:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        c.execute("SELECT is_admin FROM tenants WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            return "admin" if row[0] else "viewer"
        return "viewer"
    conn.close()
    return row[0] if row else "viewer"


def get_base_permissions(username: str) -> set:
    role = get_user_role(username)
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["viewer"])


def get_overrides(username: str) -> dict:
    init_rbac()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"SELECT permission, granted FROM {PERMISSION_OVERRIDES_TABLE} WHERE username=?",
        (username,),
    )
    rows = c.fetchall()
    conn.close()
    return {r[0]: bool(r[1]) for r in rows}


def get_effective_permissions(username: str) -> set:
    base = get_base_permissions(username)
    overrides = get_overrides(username)
    for perm, granted in overrides.items():
        if granted:
            base.add(perm)
        else:
            base.discard(perm)
    return base


def check_permission(username: str, permission: str) -> bool:
    return permission in get_effective_permissions(username)


def grant_permission(username: str, permission: str):
    init_rbac()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"INSERT OR REPLACE INTO {PERMISSION_OVERRIDES_TABLE} (username, permission, granted) VALUES (?, ?, 1)",
        (username, permission),
    )
    conn.commit()
    conn.close()


def revoke_permission(username: str, permission: str):
    init_rbac()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"INSERT OR REPLACE INTO {PERMISSION_OVERRIDES_TABLE} (username, permission, granted) VALUES (?, ?, 0)",
        (username, permission),
    )
    conn.commit()
    conn.close()


def list_all_permissions() -> list:
    all_perms = set()
    for perms in ROLE_PERMISSIONS.values():
        all_perms.update(perms)
    return sorted(all_perms)


def require_permission(username: str, permission: str):
    if not check_permission(username, permission):
        raise PermissionError(f"User '{username}' lacks '{permission}' permission")
