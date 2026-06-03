import os
import sys
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def pytest_configure(config):
    from src.database import init_db
    from src.tenants import init_tenants
    init_db()
    init_tenants()
