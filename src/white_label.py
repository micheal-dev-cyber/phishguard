"""
White-label branding — custom logo, colors, company name.

Stores branding preferences per user/tenant for multi-tenant white-labeling.
"""
import json
import logging
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger("white_label")

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"
BRANDING_TABLE = "white_label_branding"


def init_white_label():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {BRANDING_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            company_name TEXT DEFAULT '',
            logo_url TEXT DEFAULT '',
            primary_color TEXT DEFAULT '#2563eb',
            secondary_color TEXT DEFAULT '#1e3a5f',
            accent_color TEXT DEFAULT '#60a5fa',
            custom_css TEXT DEFAULT '',
            enabled INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def set_branding(username: str, company_name: str = "", logo_url: str = "",
                 primary_color: str = "#2563eb", secondary_color: str = "#1e3a5f",
                 accent_color: str = "#60a5fa", custom_css: str = "") -> bool:
    init_white_label()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    try:
        c.execute(
            f"INSERT OR REPLACE INTO {BRANDING_TABLE} "
            "(username, company_name, logo_url, primary_color, secondary_color, accent_color, custom_css, enabled) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (username, company_name, logo_url, primary_color, secondary_color, accent_color, custom_css),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error("Failed to set branding: %s", e)
        return False
    finally:
        conn.close()


def get_branding(username: str) -> dict:
    init_white_label()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(f"SELECT * FROM {BRANDING_TABLE} WHERE username=?", (username,))
    cols = [d[0] for d in c.description]
    row = c.fetchone()
    conn.close()
    if row:
        return dict(zip(cols, row))
    return {"enabled": False, "company_name": "", "logo_url": "", "primary_color": "#2563eb", "secondary_color": "#1e3a5f", "accent_color": "#60a5fa"}


def enable_branding(username: str, enabled: bool) -> bool:
    init_white_label()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(f"UPDATE {BRANDING_TABLE} SET enabled=? WHERE username=?", (1 if enabled else 0, username))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def inject_branding_css(username: str) -> str:
    brand = get_branding(username)
    if not brand.get("enabled"):
        return ""
    css = f"""
    <style>
    :root {{
        --primary: {brand['primary_color']};
        --secondary: {brand['secondary_color']};
        --accent: {brand['accent_color']};
    }}
    .stApp header {{ background: var(--secondary) !important; }}
    .stButton button {{ background: var(--primary) !important; }}
    a {{ color: var(--accent) !important; }}
    {brand.get('custom_css', '')}
    </style>
    """
    if brand.get("logo_url"):
        css += f'<img src="{brand["logo_url"]}" style="height:32px;margin-right:8px;vertical-align:middle" alt="Logo">'
    if brand.get("company_name"):
        css += f'<span style="color:var(--accent);font-weight:600">{brand["company_name"]}</span>'
    return css
