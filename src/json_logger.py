"""Structured JSON logging for SIEM ingestion and debugging.

Usage:
    from src.json_logger import setup_json_logging
    setup_json_logging()

Then all standard logging.getLogger(...) calls automatically emit JSON lines.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Outputs every log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }
        if hasattr(record, "extra_fields"):
            entry.update(record.extra_fields)
        return json.dumps(entry, default=str)


def setup_json_logging(level: str = None):
    """Replace root logger handlers with JSON formatter.

    Only activates when JSON_LOG=true env var is set, so plain-text
    logging remains the default for local development.
    """
    if os.getenv("JSON_LOG", "").lower() not in ("1", "true", "yes"):
        return

    level = level or os.getenv("LOG_LEVEL", "INFO")
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
