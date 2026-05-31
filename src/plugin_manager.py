"""
Plugin system for custom analyzers.

Users can write Python plugins that implement detect(text) -> dict
and register them at runtime without modifying core code.
"""
import importlib
import inspect
import logging
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

from src.db import DB_PATH, get_connection

logger = logging.getLogger("plugin_manager")

PLUGIN_DIR = Path(__file__).parent.parent / "plugins"
PLUGIN_TABLE = "analysis_plugins"

_loaded_plugins: dict[str, Callable] = {}


def init_plugins():
    PLUGIN_DIR.mkdir(exist_ok=True)
    init_file = PLUGIN_DIR / "__init__.py"
    if not init_file.exists():
        init_file.write_text("# PhishGuard plugins\n")
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        CREATE TABLE IF NOT EXISTS {PLUGIN_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            module_path TEXT NOT NULL,
            handler_function TEXT NOT NULL DEFAULT 'detect',
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            author TEXT DEFAULT '',
            version TEXT DEFAULT '1.0.0',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def register_plugin(
    name: str,
    module_path: str,
    handler: str = "detect",
    description: str = "",
    author: str = "",
    version: str = "1.0.0",
) -> bool:
    init_plugins()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            f"INSERT OR REPLACE INTO {PLUGIN_TABLE} (name, module_path, handler_function, enabled, description, author, version) VALUES (?, ?, ?, 1, ?, ?, ?)",
            (name, module_path, handler, description, author, version),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error("Failed to register plugin '%s': %s", name, e)
        return False
    finally:
        conn.close()


def unregister_plugin(name: str) -> bool:
    init_plugins()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"DELETE FROM {PLUGIN_TABLE} WHERE name=?", (name,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    _loaded_plugins.pop(name, None)
    return affected > 0


def list_plugins(enabled_only: bool = False) -> list[dict]:
    init_plugins()
    conn = get_connection()
    c = conn.cursor()
    if enabled_only:
        c.execute(f"SELECT * FROM {PLUGIN_TABLE} WHERE enabled=1 ORDER BY name")
    else:
        c.execute(f"SELECT * FROM {PLUGIN_TABLE} ORDER BY name")
    cols = [d[0] for d in c.description]
    rows = [dict(zip(cols, r)) for r in c.fetchall()]
    conn.close()
    return rows


def enable_plugin(name: str) -> bool:
    init_plugins()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"UPDATE {PLUGIN_TABLE} SET enabled=1 WHERE name=?", (name,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def disable_plugin(name: str) -> bool:
    init_plugins()
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"UPDATE {PLUGIN_TABLE} SET enabled=0 WHERE name=?", (name,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    _loaded_plugins.pop(name, None)
    return affected > 0


def load_plugin(name: str) -> Optional[Callable]:
    plugins = list_plugins(enabled_only=True)
    plugin = next((p for p in plugins if p["name"] == name), None)
    if not plugin:
        logger.warning("Plugin '%s' not found or disabled", name)
        return None
    if name in _loaded_plugins:
        return _loaded_plugins[name]
    module_path = plugin["module_path"]
    handler_name = plugin["handler_function"]
    try:
        if module_path not in sys.path:
            sys.path.insert(0, str(PLUGIN_DIR))
        mod = importlib.import_module(module_path.replace(".py", "").replace("/", "."))
        handler = getattr(mod, handler_name, None)
        if handler is None:
            logger.error("Plugin '%s': function '%s' not found in %s", name, handler_name, module_path)
            return None
        _loaded_plugins[name] = handler
        return handler
    except Exception as e:
        logger.error("Failed to load plugin '%s': %s", name, e)
        return None


def load_all_plugins() -> list[tuple[str, Callable]]:
    plugins = list_plugins(enabled_only=True)
    loaded = []
    for p in plugins:
        handler = load_plugin(p["name"])
        if handler:
            loaded.append((p["name"], handler))
    return loaded


def run_plugins(text: str) -> dict[str, Any]:
    results = {}
    for name, handler in load_all_plugins():
        try:
            result = handler(text)
            results[name] = result
        except Exception as e:
            results[name] = {"error": str(e)}
            logger.error("Plugin '%s' error: %s", name, e)
    return results
