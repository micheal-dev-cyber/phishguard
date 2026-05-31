"""
SCIM 2.0 provisioning endpoint for automatic user management
from identity providers (Azure AD, Okta, OneLogin).

Endpoints:
  POST /api/v1/scim/Users       — Create user
  GET  /api/v1/scim/Users       — List users
  GET  /api/v1/scim/Users/:id   — Get user
  PUT  /api/v1/scim/Users/:id   — Update user
  PATCH /api/v1/scim/Users/:id  — Partial update
  DELETE /api/v1/scim/Users/:id — Deactivate user

Usage from webhook.py or any Flask/FastAPI handler:
    from src.scim import handle_scim_request
    response = handle_scim_request(method, path, body)
"""

import json
import sqlite3
import hashlib
import secrets
from typing import Optional

from src.db import DB_PATH, get_connection

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"

BASE_LOCATION = "/api/v1/scim/Users"


def _db():
    return get_connection()


def _scim_user(row) -> dict:
    return {
        "schemas": [SCHEMA_USER],
        "id": str(row["rowid"]),
        "userName": row["username"],
        "name": {"givenName": "", "familyName": ""},
        "emails": [{"value": row["email"] if row["email"] else "", "primary": True}],
        "active": row["status"] == "active",
        "meta": {
            "resourceType": "User",
            "location": f"{BASE_LOCATION}/{row['rowid']}",
        },
    }


def _error(status: int, detail: str) -> dict:
    return {
        "schemas": [SCHEMA_ERROR],
        "status": str(status),
        "detail": detail,
    }


def handle_scim_request(method: str, path: str, body: Optional[dict] = None) -> dict:
    parts = [p for p in path.split("/") if p]
    user_id = parts[-1] if parts and parts[-1].isdigit() else None

    if method == "GET" and not user_id:
        return _list_users(body)
    elif method == "GET" and user_id:
        return _get_user(int(user_id))
    elif method == "POST" and not user_id:
        return _create_user(body or {})
    elif method in ("PUT", "PATCH") and user_id:
        return _update_user(int(user_id), body or {}, partial=(method == "PATCH"))
    elif method == "DELETE" and user_id:
        return _deactivate_user(int(user_id))
    else:
        return _error(400, f"Unsupported SCIM operation: {method} {path}")


def _list_users(filter_params: Optional[dict] = None) -> dict:
    conn = _db()
    c = conn.cursor()
    c.execute("SELECT rowid, username, email, role, status FROM users ORDER BY rowid ASC")
    rows = c.fetchall()
    conn.close()
    resources = [_scim_user(r) for r in rows]
    return {
        "schemas": [SCHEMA_LIST],
        "totalResults": len(resources),
        "itemsPerPage": len(resources),
        "startIndex": 1,
        "Resources": resources,
    }


def _get_user(user_id: int) -> dict:
    conn = _db()
    c = conn.cursor()
    c.execute("SELECT rowid, username, email, role, status FROM users WHERE rowid=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return _error(404, f"User {user_id} not found")
    return _scim_user(row)


def _create_user(body: dict) -> dict:
    username = body.get("userName", "")
    email = ""
    emails = body.get("emails", [])
    if emails:
        email = emails[0].get("value", "")
    if not username:
        return _error(400, "userName is required")

    password = secrets.token_urlsafe(16)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = _db()
    c = conn.cursor()
    try:
        from datetime import datetime, timezone
        c.execute(
            "INSERT INTO users (username, password_hash, email, status, role, created_at) VALUES (?, ?, ?, 'active', 'user', ?)",
            (username, password_hash, email, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        new_id = c.lastrowid
        c.execute("SELECT rowid, username, email, role, status FROM users WHERE rowid=?", (new_id,))
        row = c.fetchone()
        conn.close()
        return _scim_user(row)
    except sqlite3.IntegrityError as e:
        conn.close()
        return _error(409, f"User '{username}' already exists")


def _update_user(user_id: int, body: dict, partial: bool = False) -> dict:
    conn = _db()
    c = conn.cursor()
    c.execute("SELECT rowid, username, email, role, status FROM users WHERE rowid=?", (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return _error(404, f"User {user_id} not found")

    update_fields = {}
    if "userName" in body and not partial:
        update_fields["username"] = body["userName"]
    emails = body.get("emails", [])
    if emails and emails[0].get("value"):
        update_fields["email"] = emails[0]["value"]
    if "active" in body:
        update_fields["status"] = "active" if body["active"] else "suspended"

    if update_fields:
        set_clause = ", ".join(f"{k}=?" for k in update_fields)
        values = list(update_fields.values()) + [user_id]
        c.execute(f"UPDATE users SET {set_clause} WHERE rowid=?", values)
        conn.commit()

    c.execute("SELECT rowid, username, email, role, status FROM users WHERE rowid=?", (user_id,))
    updated = c.fetchone()
    conn.close()
    return _scim_user(updated)


def _deactivate_user(user_id: int) -> dict:
    conn = _db()
    c = conn.cursor()
    c.execute("UPDATE users SET status='suspended' WHERE rowid=?", (user_id,))
    conn.commit()
    conn.close()
    return {"schemas": [SCHEMA_USER], "id": str(user_id), "active": False}
