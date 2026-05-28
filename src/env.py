"""
PhishGuard AI — Centralised Environment & Secrets Loader

All API keys and sensitive configuration are loaded from environment
variables via os.getenv(). This is compatible with:

  • Hugging Face Spaces → "Variables and secrets" panel (sets env vars)
  • Local development  → .env file via python-dotenv, or manual export

IMPORTANT: This module does NOT import streamlit, so it can be imported
before st.set_page_config() without triggering Streamlit internals.

Usage:
    from src.env import ENV
    client = OpenAI(api_key=ENV.OPENAI_API_KEY)

Naming convention:  All caps, underscores.  Every key defaults to "".
"""

import os
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("phishguard-env")


@dataclass
class EnvConfig:
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    PADDLE_API_KEY: str = ""
    PADDLE_CLIENT_TOKEN: str = ""
    PADDLE_WEBHOOK_SECRET: str = ""
    PADDLE_PRICE_ID_STARTER: str = ""
    PADDLE_PRICE_ID_BUSINESS: str = ""
    PADDLE_ENVIRONMENT: str = "sandbox"
    LOG_LEVEL: str = "INFO"
    ADMIN_PASSWORD: str = "phishguard2026"
    APP_URL: str = ""
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    SMTP_FROM: str = ""
    paddle_configured: bool = False
    # Enterprise SSO
    OAUTH_CLIENT_ID: str = ""
    OAUTH_CLIENT_SECRET: str = ""
    OAUTH_AUTHORITY: str = ""
    OAUTH_REDIRECT_URI: str = ""
    # Microsoft Graph API
    GRAPH_TENANT_ID: str = ""
    GRAPH_CLIENT_ID: str = ""
    GRAPH_CLIENT_SECRET: str = ""
    # SIEM Webhooks
    SIEM_SPLUNK_HEC_URL: str = ""
    SIEM_SPLUNK_HEC_TOKEN: str = ""
    SIEM_ELASTIC_CLOUD_ID: str = ""
    SIEM_ELASTIC_API_KEY: str = ""
    SIEM_QRAZAR_URL: str = ""
    SIEM_QRAZAR_API_KEY: str = ""
    # PostgreSQL (optional — HF Spaces default is SQLite)
    PGHOST: str = ""
    PGPORT: str = "5432"
    PGUSER: str = ""
    PGPASSWORD: str = ""
    PGDATABASE: str = ""

    def __post_init__(self):
        self.paddle_configured = bool(
            self.PADDLE_API_KEY and self.PADDLE_CLIENT_TOKEN
        )


def _read_env(key: str, default: str = "") -> str:
    """Read an env var. Pure os.getenv — no streamlit import."""
    return os.getenv(key, default)


def load_env() -> EnvConfig:
    return EnvConfig(
        OPENAI_API_KEY=_read_env("OPENAI_API_KEY"),
        ANTHROPIC_API_KEY=_read_env("ANTHROPIC_API_KEY"),
        GROQ_API_KEY=_read_env("GROQ_API_KEY"),
        OPENROUTER_API_KEY=_read_env("OPENROUTER_API_KEY"),
        VIRUSTOTAL_API_KEY=_read_env("VIRUSTOTAL_API_KEY"),
        PADDLE_API_KEY=_read_env("PADDLE_API_KEY"),
        PADDLE_CLIENT_TOKEN=_read_env("PADDLE_CLIENT_TOKEN"),
        PADDLE_WEBHOOK_SECRET=_read_env("PADDLE_WEBHOOK_SECRET"),
        PADDLE_PRICE_ID_STARTER=_read_env("PADDLE_PRICE_ID_STARTER"),
        PADDLE_PRICE_ID_BUSINESS=_read_env("PADDLE_PRICE_ID_BUSINESS"),
        PADDLE_ENVIRONMENT=_read_env("PADDLE_ENVIRONMENT", "sandbox"),
        LOG_LEVEL=_read_env("LOG_LEVEL", "INFO"),
        ADMIN_PASSWORD=_read_env("ADMIN_PASSWORD", "phishguard2026"),
        APP_URL=_read_env("APP_URL", ""),
        SMTP_HOST=_read_env("SMTP_HOST", "smtp.gmail.com"),
        SMTP_PORT=int(_read_env("SMTP_PORT", "587")),
        SMTP_USER=_read_env("SMTP_USER"),
        SMTP_PASS=_read_env("SMTP_PASS"),
        SMTP_FROM=_read_env("SMTP_FROM"),
        # Enterprise SSO
        OAUTH_CLIENT_ID=_read_env("OAUTH_CLIENT_ID"),
        OAUTH_CLIENT_SECRET=_read_env("OAUTH_CLIENT_SECRET"),
        OAUTH_AUTHORITY=_read_env("OAUTH_AUTHORITY"),
        OAUTH_REDIRECT_URI=_read_env("OAUTH_REDIRECT_URI"),
        # Microsoft Graph API
        GRAPH_TENANT_ID=_read_env("GRAPH_TENANT_ID"),
        GRAPH_CLIENT_ID=_read_env("GRAPH_CLIENT_ID"),
        GRAPH_CLIENT_SECRET=_read_env("GRAPH_CLIENT_SECRET"),
        # SIEM Webhooks
        SIEM_SPLUNK_HEC_URL=_read_env("SIEM_SPLUNK_HEC_URL"),
        SIEM_SPLUNK_HEC_TOKEN=_read_env("SIEM_SPLUNK_HEC_TOKEN"),
        SIEM_ELASTIC_CLOUD_ID=_read_env("SIEM_ELASTIC_CLOUD_ID"),
        SIEM_ELASTIC_API_KEY=_read_env("SIEM_ELASTIC_API_KEY"),
        SIEM_QRAZAR_URL=_read_env("SIEM_QRAZAR_URL"),
        SIEM_QRAZAR_API_KEY=_read_env("SIEM_QRAZAR_API_KEY"),
        # PostgreSQL (optional)
        PGHOST=_read_env("PGHOST"),
        PGPORT=_read_env("PGPORT", "5432"),
        PGUSER=_read_env("PGUSER"),
        PGPASSWORD=_read_env("PGPASSWORD"),
        PGDATABASE=_read_env("PGDATABASE"),
    )


# Singleton — import once, use everywhere.
# Pure os.getenv — safe to import before set_page_config().
ENV: EnvConfig = load_env()


def get_config_status() -> dict:
    status = {}
    for key in [
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "VIRUSTOTAL_API_KEY",
        "PADDLE_API_KEY", "PADDLE_CLIENT_TOKEN", "PADDLE_WEBHOOK_SECRET",
        "SMTP_HOST", "SMTP_USER", "SMTP_FROM",
    ]:
        val = getattr(ENV, key, "")
        status[key] = {
            "configured": bool(val),
            "value": (val[:8] + "..." + val[-4:]) if len(val) > 14 else ("***" if val else ""),
        }
    status["paddle_configured"] = ENV.paddle_configured
    return status


def log_config_status():
    status = get_config_status()
    configured = [k for k, v in status.items() if isinstance(v, dict) and v["configured"]]
    missing = [k for k, v in status.items() if isinstance(v, dict) and not v["configured"]]
    logger.info("Configured services: %s", ", ".join(configured) or "none")
    if missing:
        logger.warning("Missing API keys: %s", ", ".join(missing))
