import os
import sys
import shutil
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Use a test database to avoid clobbering production data
TEST_DATA_DIR = PROJECT_ROOT / "data" / "test"
TEST_DB = TEST_DATA_DIR / "phishguard.db"


def pytest_configure(config):
    TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)


def pytest_unconfigure(config):
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR)
