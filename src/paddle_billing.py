import logging
import hmac
import hashlib
import requests
from typing import Optional
from src.env import ENV

logger = logging.getLogger(__name__)

PADDLE_API_URL = "https://api.paddle.com"
PADDLE_SANDBOX_API_URL = "https://sandbox-api.paddle.com"


def _get_config():
    return {
        "api_key": ENV.PADDLE_API_KEY,
        "client_token": ENV.PADDLE_CLIENT_TOKEN,
        "webhook_secret": ENV.PADDLE_WEBHOOK_SECRET,
        "price_ids": {
            "starter": ENV.PADDLE_PRICE_ID_STARTER,
            "business": ENV.PADDLE_PRICE_ID_BUSINESS,
            "consultant": ENV.PADDLE_PRICE_ID_CONSULTANT,
            "enterprise": ENV.PADDLE_PRICE_ID_ENTERPRISE,
        },
        "environment": ENV.PADDLE_ENVIRONMENT,
    }


def _api_base() -> str:
    cfg = _get_config()
    return PADDLE_API_URL if cfg["environment"] == "production" else PADDLE_SANDBOX_API_URL


def _headers() -> dict:
    cfg = _get_config()
    return {"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"}


def is_configured() -> bool:
    cfg = _get_config()
    return bool(cfg["api_key"] and cfg["client_token"])


def get_price_id(plan: str) -> Optional[str]:
    return _get_config()["price_ids"].get(plan)


def generate_checkout_url(username: str, plan: str, success_url: str = "") -> Optional[str]:
    """Create a Paddle transaction and return its checkout URL."""
    cfg = _get_config()
    price_id = get_price_id(plan)
    if not cfg["api_key"] or not price_id:
        return None

    body = {
        "items": [{"price_id": price_id, "quantity": 1}],
        "custom_data": {"username": username, "plan": plan},
    }
    if success_url:
        body["urls"] = {"success": success_url}

    try:
        resp = requests.post(
            f"{_api_base()}/transactions",
            headers=_headers(),
            json=body,
            timeout=15,
        )
        if resp.status_code in (200, 201):
            data = resp.json().get("data", {})
            return data.get("urls", {}).get("checkout", data.get("checkout", {}).get("url"))
    except Exception as e:
        logger.warning("paddle_billing: Failed to create checkout URL: %s", e)
    return None


def verify_webhook_signature(request_body: bytes, signature_header: str) -> bool:
    """Verify Paddle Billing webhook signature (Paddle-Signature header)."""
    cfg = _get_config()
    secret = cfg["webhook_secret"]
    if not secret or not signature_header:
        return False
    try:
        parts = {p.split("=")[0].strip(): p.split("=")[1].strip() for p in signature_header.split(";")}
        ts = parts.get("ts", "")
        sig = parts.get("h1", "")
        expected = hmac.new(secret.encode(), f"{ts}{request_body.decode()}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception as e:
        logger.warning("paddle_billing: Webhook signature verification failed: %s", e)
        return False


def verify_transaction(transaction_id: str) -> Optional[dict]:
    """Verify a transaction status with Paddle API."""
    cfg = _get_config()
    if not cfg["api_key"]:
        return None
    try:
        resp = requests.get(
            f"{_api_base()}/transactions/{transaction_id}",
            headers=_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "id": data.get("id"),
                "status": data.get("status"),
                "custom_data": data.get("custom_data", {}),
            }
    except Exception as e:
        logger.warning("paddle_billing: Transaction verification failed: %s", e)
    return None


# ── Subscription Management ──────────────────────────────────────────────


def get_subscription(subscription_id: str) -> Optional[dict]:
    """Get subscription details from Paddle API."""
    cfg = _get_config()
    if not cfg["api_key"]:
        return None
    try:
        resp = requests.get(
            f"{_api_base()}/subscriptions/{subscription_id}",
            headers=_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            items = data.get("items", [])
            price_id = items[0]["price"]["id"] if items else ""
            plan = _plan_from_price_id(price_id)
            next_billed_at = data.get("next_billed_at", "")
            return {
                "id": data.get("id"),
                "status": data.get("status"),
                "plan": plan,
                "price_id": price_id,
                "currency": data.get("currency_code", "USD"),
                "unit_price": items[0]["price"]["unit_price"]["amount"] if items else "0",
                "next_billed_at": next_billed_at,
                "paused_at": data.get("paused_at"),
                "canceled_at": data.get("canceled_at"),
                "created_at": data.get("created_at"),
                "current_billing_period": data.get("billing_cycle", {}),
                "scheduled_change": data.get("scheduled_change"),
            }
    except Exception as e:
        logger.warning("paddle_billing: Failed to get subscription: %s", e)
    return None


def _plan_from_price_id(price_id: str) -> str:
    cfg = _get_config()
    for plan, pid in cfg["price_ids"].items():
        if pid == price_id:
            return plan
    return "unknown"


def get_customer_portal_url(customer_id: str) -> Optional[str]:
    """Generate a Paddle customer portal session URL for self-service billing."""
    cfg = _get_config()
    if not cfg["api_key"] or not customer_id:
        return None
    try:
        resp = requests.post(
            f"{_api_base()}/customers/{customer_id}/portal-sessions",
            headers=_headers(),
            json={},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("urls", {}).get("general", {}).get("overview")
    except Exception as e:
        logger.warning("paddle_billing: Failed to create customer portal URL: %s", e)
    return None


def get_invoices(customer_id: str, limit: int = 10) -> list:
    """Get recent invoices for a customer."""
    cfg = _get_config()
    if not cfg["api_key"]:
        return []
    try:
        resp = requests.get(
            f"{_api_base()}/invoices",
            params={"customer_id": customer_id, "status": "paid", "per_page": limit},
            headers=_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            return [
                {
                    "id": inv.get("id"),
                    "status": inv.get("status"),
                    "total": inv.get("total", {}).get("amount", "0"),
                    "currency": inv.get("total", {}).get("currency_code", "USD"),
                    "paid_at": inv.get("paid_at", ""),
                    "invoice_url": inv.get("urls", {}).get("invoice", {}).get("pdf", ""),
                    "number": inv.get("invoice_number", ""),
                }
                for inv in data
            ]
    except Exception as e:
        logger.warning("paddle_billing: Failed to get invoices: %s", e)
    return []


def pause_subscription(subscription_id: str) -> bool:
    """Pause a subscription."""
    cfg = _get_config()
    if not cfg["api_key"]:
        return False
    try:
        resp = requests.post(
            f"{_api_base()}/subscriptions/{subscription_id}/pause",
            headers=_headers(),
            json={},
            timeout=10,
        )
        return resp.status_code in (200, 201)
    except Exception as e:
        logger.warning("paddle_billing: Failed to pause subscription: %s", e)
        return False


def cancel_subscription(subscription_id: str, reason: str = "") -> bool:
    """Cancel a subscription."""
    cfg = _get_config()
    if not cfg["api_key"]:
        return False
    try:
        body = {"effective_from": "next_billing_period"}
        if reason:
            body["reason"] = reason
        resp = requests.post(
            f"{_api_base()}/subscriptions/{subscription_id}/cancel",
            headers=_headers(),
            json=body,
            timeout=10,
        )
        return resp.status_code in (200, 201)
    except Exception as e:
        logger.warning("paddle_billing: Failed to cancel subscription: %s", e)
        return False


def resume_subscription(subscription_id: str) -> bool:
    """Resume a paused subscription."""
    cfg = _get_config()
    if not cfg["api_key"]:
        return False
    try:
        resp = requests.post(
            f"{_api_base()}/subscriptions/{subscription_id}/resume",
            headers=_headers(),
            json={},
            timeout=10,
        )
        return resp.status_code in (200, 201)
    except Exception as e:
        logger.warning("paddle_billing: Failed to resume subscription: %s", e)
        return False


def update_subscription_plan(subscription_id: str, new_plan: str) -> bool:
    """Change the plan (price) on an existing subscription."""
    cfg = _get_config()
    price_id = get_price_id(new_plan)
    if not cfg["api_key"] or not price_id:
        return False
    try:
        resp = requests.patch(
            f"{_api_base()}/subscriptions/{subscription_id}",
            headers=_headers(),
            json={
                "items": [{"price_id": price_id, "quantity": 1}],
                "proration_billing_mode": "prorated_immediately",
                "custom_data": {"plan": new_plan},
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        logger.warning("paddle_billing: Failed to update subscription plan: %s", e)
        return False


# ── Webhook Event Handling ──────────────────────────────────────────────


def _save_subscription(username: str, plan: str, sub_id: str, status: str):
    """Persist subscription record in the local DB."""
    import sqlite3
    from pathlib import Path
    db = Path(__file__).parent.parent / "data" / "phishguard.db"
    try:
        conn = sqlite3.connect(str(db))
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS paddle_subscriptions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                username         TEXT UNIQUE NOT NULL,
                plan             TEXT NOT NULL,
                subscription_id  TEXT DEFAULT '',
                status           TEXT DEFAULT 'active',
                customer_id      TEXT DEFAULT '',
                next_billed_at   TEXT DEFAULT '',
                ended_at         TEXT,
                created_at       TEXT DEFAULT (datetime('now')),
                updated_at       TEXT DEFAULT (datetime('now'))
            )
        """)
        c.execute(
            "INSERT OR REPLACE INTO paddle_subscriptions "
            "(username, plan, subscription_id, status, updated_at) "
            "VALUES (?, ?, ?, ?, datetime('now'))",
            (username, plan, sub_id, status),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("paddle_billing: Failed to save subscription for %s: %s", username, e)


def handle_webhook_event(payload: dict) -> dict:
    event_type = payload.get("event_type", "")
    data = payload.get("data", {})

    handlers = {
        "transaction.completed": _handle_transaction_completed,
        "transaction.paid": _handle_transaction_completed,
        "subscription.created": _handle_subscription_created,
        "subscription.updated": _handle_subscription_updated,
        "subscription.cancelled": _handle_subscription_cancelled,
        "subscription.paused": _handle_subscription_paused,
        "subscription.resumed": _handle_subscription_resumed,
    }
    handler = handlers.get(event_type)
    if handler:
        return handler(data)
    return {"status": "ignored", "event_type": event_type}


def _handle_transaction_completed(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    plan = custom.get("plan", "")
    txn_id = data.get("id", "")
    if username and plan:
        from src.tenants import update_tenant
        update_tenant(username, plan=plan)
        _save_subscription(username, plan, f"txn_{txn_id}", "active")
        return {"status": "upgraded", "username": username, "plan": plan}
    return {"status": "no_action", "reason": "Missing username/plan in custom_data"}


def _handle_subscription_created(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    plan = custom.get("plan", "")
    sub_id = data.get("id", "")
    items = data.get("items", [])
    price_id = items[0]["price"]["id"] if items else ""
    plan = plan or _plan_from_price_id(price_id)
    if username and plan:
        from src.tenants import update_tenant
        update_tenant(username, plan=plan)
        _save_subscription(username, plan, sub_id, "active")
        return {"status": "subscribed", "username": username, "plan": plan, "subscription_id": sub_id}
    return {"status": "no_action", "reason": "Missing data"}


def _handle_subscription_updated(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    plan = custom.get("plan", "")
    sub_id = data.get("id", "")
    status = data.get("status", "")
    items = data.get("items", [])
    price_id = items[0]["price"]["id"] if items else ""
    plan = plan or _plan_from_price_id(price_id)
    if username and plan and status == "active":
        from src.tenants import update_tenant
        update_tenant(username, plan=plan)
        _save_subscription(username, plan, sub_id, status)
        return {"status": "updated", "username": username, "plan": plan}
    if username:
        _save_subscription(username, plan or "trial", sub_id, status)
    return {"status": "no_action", "reason": "No update needed"}


def _handle_subscription_cancelled(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    sub_id = data.get("id", "")
    if username:
        from src.tenants import update_tenant
        update_tenant(username, plan="trial")
        _save_subscription(username, "trial", sub_id, "cancelled")
        return {"status": "downgraded", "username": username, "plan": "trial"}
    return {"status": "no_action", "reason": "Missing username"}


def _handle_subscription_paused(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    sub_id = data.get("id", "")
    if username:
        _save_subscription(username, "", sub_id, "paused")
        return {"status": "paused", "username": username}
    return {"status": "no_action", "reason": "Missing username"}


def _handle_subscription_resumed(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    sub_id = data.get("id", "")
    items = data.get("items", [])
    price_id = items[0]["price"]["id"] if items else ""
    plan = _plan_from_price_id(price_id)
    if username:
        _save_subscription(username, plan, sub_id, "active")
        return {"status": "resumed", "username": username, "plan": plan}
    return {"status": "no_action", "reason": "Missing username"}


# ── Local Subscription Queries ──────────────────────────────────────────


def get_local_subscription(username: str) -> Optional[dict]:
    """Get subscription record from local DB."""
    import sqlite3
    from pathlib import Path
    db = Path(__file__).parent.parent / "data" / "phishguard.db"
    try:
        conn = sqlite3.connect(str(db))
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS paddle_subscriptions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                username         TEXT UNIQUE NOT NULL,
                plan             TEXT NOT NULL,
                subscription_id  TEXT DEFAULT '',
                status           TEXT DEFAULT 'active',
                customer_id      TEXT DEFAULT '',
                next_billed_at   TEXT DEFAULT '',
                ended_at         TEXT,
                created_at       TEXT DEFAULT (datetime('now')),
                updated_at       TEXT DEFAULT (datetime('now'))
            )
        """)
        c.execute(
            "SELECT subscription_id, plan, status, customer_id, next_billed_at, created_at, updated_at "
            "FROM paddle_subscriptions WHERE username = ?",
            (username,),
        )
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "subscription_id": row[0],
                "plan": row[1],
                "status": row[2],
                "customer_id": row[3],
                "next_billed_at": row[4],
                "created_at": row[5],
                "updated_at": row[6],
            }
    except Exception as e:
        logger.warning("paddle_billing: Failed to get subscription by username: %s", e)
    return None
