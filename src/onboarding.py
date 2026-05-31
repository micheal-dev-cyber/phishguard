"""Tenant Onboarding Wizard — self-service signup with Stripe/Paddle."""

import json
import logging
import secrets
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("onboarding")
from src.tenants import PLANS


def create_checkout_session(plan: str, username: str, email: str, provider: str = "stripe") -> dict:
    """Create a Stripe or Paddle checkout session for the given plan."""
    if provider == "stripe":
        return _stripe_checkout(plan, username, email)
    else:
        return _paddle_checkout(plan, username, email)


def _stripe_checkout(plan: str, username: str, email: str) -> dict:
    from src.env import ENV
    secret_key = getattr(ENV, "STRIPE_SECRET_KEY", "") or ""
    if not secret_key:
        return {"error": "Stripe not configured"}

    pricing = PLANS.get(plan, PLANS["trial"])
    if pricing.get("custom"):
        return {"error": "Enterprise plan requires contact sales"}

    data = urlencode({
        "mode": "subscription",
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][product_data][name]": f"PhishGuard {pricing['label']}",
        "line_items[0][price_data][unit_amount]": str(pricing["price_monthly"] * 100),
        "line_items[0][price_data][recurring][interval]": "month",
        "line_items[0][quantity]": "1",
        "customer_email": email,
        "client_reference_id": username,
        "success_url": f"{ENV.APP_URL or 'https://phishguard.ai'}/billing?success=true",
        "cancel_url": f"{ENV.APP_URL or 'https://phishguard.ai'}/billing?canceled=true",
    }).encode()

    req = Request(
        "https://api.stripe.com/v1/checkout/sessions",
        data=data,
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        resp = urlopen(req, timeout=15)
        body = json.loads(resp.read())
        return {"url": body["url"], "session_id": body["id"]}
    except Exception as e:
        logger.error("Stripe checkout failed: %s", e)
        return {"error": str(e)}


def _paddle_checkout(plan: str, username: str, email: str) -> dict:
    pricing = PLANS.get(plan, PLANS["trial"])
    if pricing.get("custom"):
        return {"error": "Enterprise plan requires contact sales"}
    try:
        from src.paddle_billing import generate_checkout_url
        from src.env import ENV
        url = generate_checkout_url(username, plan, success_url=f"{ENV.APP_URL or 'https://phishguard.ai'}/?checkout=completed")
        if url:
            return {"url": url, "session_id": plan}
        return {"error": "Failed to create Paddle checkout"}
    except Exception as e:
        logger.error("Paddle checkout failed: %s", e)
        return {"error": str(e)}


def activate_plan(username: str, plan: str, order_id: str = ""):
    """Activate a plan after successful payment."""
    try:
        import sqlite3
        from pathlib import Path
        db = Path(__file__).parent.parent / "data" / "phishguard.db"
        conn = sqlite3.connect(str(db))
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                plan        TEXT NOT NULL,
                order_id    TEXT,
                status      TEXT DEFAULT 'active',
                started_at  TEXT DEFAULT (datetime('now')),
                renews_at   TEXT,
                cancelled_at TEXT
            )
        """)

        from src.tenants import update_tenant
        update_tenant(username, plan=plan)

        c.execute(
            "INSERT OR REPLACE INTO subscriptions (username, plan, order_id, status, started_at) "
            "VALUES (?, ?, ?, 'active', datetime('now'))",
            (username, plan, order_id or ""),
        )
        conn.commit()
        conn.close()
        logger.info("Plan %s activated for %s", plan, username)
        return True
    except Exception as e:
        logger.error("Plan activation failed: %s", e)
        return False


def get_onboarding_steps(username: str) -> list:
    """Return onboarding checklist for a new user."""
    steps = [
        {"step": "connect_email",      "label": "Connect your email inbox",        "done": False},
        {"step": "first_scan",         "label": "Run your first phishing scan",    "done": False},
        {"step": "configure_alerts",   "label": "Set up Slack/Teams alerts",      "done": False},
        {"step": "invite_team",        "label": "Invite your team members",       "done": False},
        {"step": "weekly_report",      "label": "Enable weekly security reports",  "done": False},
    ]
    try:
        import sqlite3
        from pathlib import Path
        db = Path(__file__).parent.parent / "data" / "phishguard.db"
        conn = sqlite3.connect(str(db))
        c = conn.cursor()
        c.execute("SELECT step FROM onboarding_progress WHERE username = ?", (username,))
        done_steps = {r[0] for r in c.fetchall()}
        conn.close()
        for step in steps:
            if step["step"] in done_steps:
                step["done"] = True
    except Exception as e:
        logger.warning("onboarding: Failed to load progress for %s: %s", username, e)
    return steps


def complete_onboarding_step(username: str, step: str):
    try:
        import sqlite3
        from pathlib import Path
        db = Path(__file__).parent.parent / "data" / "phishguard.db"
        conn = sqlite3.connect(str(db))
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS onboarding_progress (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT NOT NULL,
                step        TEXT NOT NULL,
                completed_at TEXT DEFAULT (datetime('now')),
                UNIQUE(username, step)
            )
        """)
        c.execute(
            "INSERT OR IGNORE INTO onboarding_progress (username, step) VALUES (?, ?)",
            (username, step),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Onboarding step failed: %s", e)
