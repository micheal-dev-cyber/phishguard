"""Workspaces & RBAC — orgs, teams, roles, and membership management."""

import logging
import secrets
import sqlite3
from pathlib import Path

logger = logging.getLogger("workspace")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"
ROLES = ["viewer", "analyst", "admin"]


def init_workspace_tables():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS workspaces (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE NOT NULL,
            owner       TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now')),
            is_active   INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS workspace_members (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            username    TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('viewer','analyst','admin')),
            invited_by  TEXT DEFAULT '',
            joined_at   TEXT DEFAULT (datetime('now')),
            UNIQUE(workspace_id, username)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_ws_member_user ON workspace_members (username)")
    conn.commit()

    # Migration: add columns to tenants if needed
    for col in ("workspace_id", "role"):
        try:
            c.execute(f"ALTER TABLE tenants ADD COLUMN {col} TEXT DEFAULT ''")
        except Exception:
            pass
    conn.commit()
    conn.close()


def create_workspace(name: str, owner: str) -> dict:
    init_workspace_tables()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    try:
        c.execute("INSERT INTO workspaces (name, owner) VALUES (?, ?)", (name, owner))
        ws_id = c.lastrowid
        c.execute(
            "INSERT OR REPLACE INTO workspace_members (workspace_id, username, role) VALUES (?, ?, 'admin')",
            (ws_id, owner),
        )
        c.execute("UPDATE tenants SET workspace_id = ?, role = 'admin' WHERE username = ?",
                  (str(ws_id), owner))
        conn.commit()
        return {"success": True, "workspace_id": ws_id, "name": name}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Workspace name already exists"}
    finally:
        conn.close()


def invite_member(workspace_id: int, username: str, role: str = "viewer", invited_by: str = "") -> dict:
    init_workspace_tables()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    try:
        c.execute("SELECT username FROM tenants WHERE username = ?", (username,))
        if not c.fetchone():
            return {"success": False, "error": "User not found"}
        c.execute(
            "INSERT OR REPLACE INTO workspace_members (workspace_id, username, role, invited_by) VALUES (?, ?, ?, ?)",
            (workspace_id, username, role, invited_by),
        )
        c.execute("UPDATE tenants SET workspace_id = ?, role = ? WHERE username = ?",
                  (str(workspace_id), role, username))
        conn.commit()
        return {"success": True, "username": username, "role": role}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


def remove_member(workspace_id: int, username: str):
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("DELETE FROM workspace_members WHERE workspace_id = ? AND username = ?",
              (workspace_id, username))
    c.execute("UPDATE tenants SET workspace_id = '', role = '' WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def get_workspace(workspace_id: int) -> dict:
    init_workspace_tables()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT id, name, owner, created_at, is_active FROM workspaces WHERE id = ?", (workspace_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {}
    return {"id": row[0], "name": row[1], "owner": row[2], "created_at": row[3], "is_active": bool(row[4])}


def list_workspaces(username: str) -> list:
    init_workspace_tables()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        SELECT w.id, w.name, w.owner, wm.role
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE wm.username = ?
    """, (username,))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "owner": r[2], "role": r[3]} for r in rows]


def get_members(workspace_id: int) -> list:
    init_workspace_tables()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "SELECT username, role, invited_by, joined_at FROM workspace_members WHERE workspace_id = ? ORDER BY joined_at",
        (workspace_id,),
    )
    rows = c.fetchall()
    conn.close()
    return [{"username": r[0], "role": r[1], "invited_by": r[2], "joined_at": r[3]} for r in rows]


def user_role(username: str) -> str:
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT role FROM tenants WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row and row[0] else ""


def user_workspace_id(username: str) -> str:
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("SELECT workspace_id FROM tenants WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return str(row[0]) if row and row[0] else ""
