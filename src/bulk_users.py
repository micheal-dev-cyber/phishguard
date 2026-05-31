"""
Bulk user CSV import/export for admin user management.
"""
import csv
import io
import logging
from typing import Optional

from src.db import DB_PATH, get_connection

logger = logging.getLogger("bulk_users")


def export_users_csv() -> str:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT username, email, role, status, plan, is_active, created_at FROM users ORDER BY username")
    rows = c.fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "email", "role", "status", "plan", "is_active", "created_at"])
    for r in rows:
        writer.writerow(r)
    return output.getvalue()


def import_users_csv(csv_content: str, default_plan: str = "free") -> dict:
    results = {"imported": 0, "skipped": 0, "errors": []}
    conn = get_connection()
    c = conn.cursor()
    reader = csv.DictReader(io.StringIO(csv_content))
    for row in reader:
        username = row.get("username", "").strip()
        email = row.get("email", "").strip()
        role = row.get("role", "viewer").strip()
        if not username:
            results["errors"].append("Row missing username")
            continue
        try:
            c.execute(
                "INSERT OR IGNORE INTO users (username, email, role, plan, status, is_active, password_hash) VALUES (?, ?, ?, ?, 'active', 1, 'imported')",
                (username, email or f"{username}@imported.local", role, default_plan),
            )
            if c.rowcount:
                results["imported"] += 1
            else:
                try:
                    c.execute("INSERT OR IGNORE INTO tenants (username, email, plan, is_active) VALUES (?, ?, ?, 1)",
                              (username, email or f"{username}@imported.local", default_plan))
                    if c.rowcount:
                        results["imported"] += 1
                    else:
                        results["skipped"] += 1
                except Exception:
                    results["skipped"] += 1
        except Exception as e:
            results["errors"].append(f"{username}: {e}")
    conn.commit()
    conn.close()
    return results


def export_template_csv() -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "email", "role", "plan"])
    writer.writerow(["john.doe", "john@example.com", "viewer", "free"])
    writer.writerow(["jane.smith", "jane@company.com", "analyst", "pro"])
    return output.getvalue()
