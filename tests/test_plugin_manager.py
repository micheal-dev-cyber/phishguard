"""
Tests for the plugin system.

Creates a real .py file in the plugins/ directory for testing.
"""
import os
import pytest
from pathlib import Path
from src.plugin_manager import (
    init_plugins, register_plugin, unregister_plugin,
    list_plugins, enable_plugin, disable_plugin,
    run_plugins,
)

PLUGIN_DIR = Path(__file__).parent.parent / "plugins"


@pytest.fixture(autouse=True)
def setup():
    init_plugins()
    # Clean up test plugins from previous runs
    for p in list_plugins():
        if "test_" in p["name"]:
            unregister_plugin(p["name"])
    # Remove test plugin files
    for f in PLUGIN_DIR.glob("test_*.py"):
        f.unlink(missing_ok=True)
    yield
    for f in PLUGIN_DIR.glob("test_*.py"):
        f.unlink(missing_ok=True)
    for p in list_plugins():
        if "test_" in p["name"]:
            unregister_plugin(p["name"])


def test_register_and_list():
    _write_plugin("test_checker", "def detect(text): return {'found': 'bad' in text.lower()}")
    assert register_plugin("test_checker", "test_checker", handler="detect",
                           description="Test plugin", author="tester", version="0.1.0")
    plugins = list_plugins()
    names = [p["name"] for p in plugins]
    assert "test_checker" in names


def test_enable_disable():
    _write_plugin("test_toggle", "def detect(text): return {'ok': True}")
    register_plugin("test_toggle", "test_toggle", handler="detect")
    assert disable_plugin("test_toggle") is True
    enabled = list_plugins(enabled_only=True)
    assert "test_toggle" not in [p["name"] for p in enabled]
    assert enable_plugin("test_toggle") is True
    enabled = list_plugins(enabled_only=True)
    assert "test_toggle" in [p["name"] for p in enabled]


def test_unregister():
    _write_plugin("test_delete", "def detect(text): return {}")
    register_plugin("test_delete", "test_delete", handler="detect")
    assert unregister_plugin("test_delete") is True
    plugins = list_plugins()
    assert "test_delete" not in [p["name"] for p in plugins]


def test_run_plugins():
    _write_plugin("test_run_checker", "def detect(text): return {'detected_phishing': 'test' in text.lower()}")
    register_plugin("test_run_checker", "test_run_checker", handler="detect",
                   description="A test checker", author="tester")
    results = run_plugins("this is a test email")
    assert "test_run_checker" in results
    assert results["test_run_checker"]["detected_phishing"] is True
    results2 = run_plugins("clean email")
    assert results2["test_run_checker"]["detected_phishing"] is False


def test_plugin_error_handling():
    _write_plugin("test_broken", "def detect(text): raise ValueError('broken')")
    register_plugin("test_broken", "test_broken", handler="detect")
    results = run_plugins("anything")
    assert "test_broken" in results
    assert "error" in results["test_broken"]


def _write_plugin(name: str, code: str):
    path = PLUGIN_DIR / f"{name}.py"
    path.write_text(code, encoding="utf-8")
