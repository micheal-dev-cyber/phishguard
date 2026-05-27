# src/paddle_billing.py
import os
import json
import hmac
import hashlib
import requests
from datetime import datetime
from typing import Optional

PADDLE_API_URL = "https://api.paddle.com"
PADDLE_SANDBOX_API_URL = "https://sandbox-api.paddle.com"


def _get_config():
    try:
        import streamlit as st
        p = st.secrets.get("paddle", {})
        return {
            "api_key": p.get("api_key", os.getenv("PADDLE_API_KEY", "")),
            "client_token": p.get("client_token", os.getenv("PADDLE_CLIENT_TOKEN", "")),
            "webhook_secret": p.get("webhook_secret", os.getenv("PADDLE_WEBHOOK_SECRET", "")),
            "price_ids": {
                "starter": p.get("price_id_starter", os.getenv("PADDLE_PRICE_ID_STARTER", "")),
                "business": p.get("price_id_business", os.getenv("PADDLE_PRICE_ID_BUSINESS", "")),
            },
            "environment": p.get("environment", os.getenv("PADDLE_ENVIRONMENT", "sandbox")),
        }
    except Exception:
        return {
            "api_key": os.getenv("PADDLE_API_KEY", ""),
            "client_token": os.getenv("PADDLE_CLIENT_TOKEN", ""),
            "webhook_secret": os.getenv("PADDLE_WEBHOOK_SECRET", ""),
            "price_ids": {
                "starter": os.getenv("PADDLE_PRICE_ID_STARTER", ""),
                "business": os.getenv("PADDLE_PRICE_ID_BUSINESS", ""),
            },
            "environment": os.getenv("PADDLE_ENVIRONMENT", "sandbox"),
        }


def _api_base() -> str:
    cfg = _get_config()
    return PADDLE_API_URL if cfg.get("environment") == "production" else PADDLE_SANDBOX_API_URL


def is_configured() -> bool:
    cfg = _get_config()
    return bool(cfg["api_key"] and cfg["client_token"])


def get_price_id(plan: str) -> Optional[str]:
    cfg = _get_config()
    return cfg["price_ids"].get(plan)


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
            headers={"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"},
            json=body,
            timeout=15,
        )
        if resp.status_code in (200, 201):
            data = resp.json().get("data", {})
            return data.get("urls", {}).get("checkout", data.get("checkout", {}).get("url"))
    except Exception:
        pass
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
    except Exception:
        return False


def verify_transaction(transaction_id: str) -> Optional[dict]:
    """Verify a transaction status with Paddle API."""
    cfg = _get_config()
    if not cfg["api_key"]:
        return None
    try:
        resp = requests.get(
            f"{_api_base()}/transactions/{transaction_id}",
            headers={"Authorization": f"Bearer {cfg['api_key']}"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "id": data.get("id"),
                "status": data.get("status"),
                "custom_data": data.get("custom_data", {}),
            }
    except Exception:
        pass
    return None


def handle_webhook_event(payload: dict) -> dict:
    """Route a Paddle webhook event to the right handler."""
    event_type = payload.get("event_type", "")
    data = payload.get("data", {})

    handlers = {
        "transaction.completed": _handle_transaction_completed,
        "transaction.paid": _handle_transaction_completed,
        "subscription.created": _handle_subscription_created,
        "subscription.updated": _handle_subscription_updated,
        "subscription.cancelled": _handle_subscription_cancelled,
    }
    handler = handlers.get(event_type)
    if handler:
        return handler(data)
    return {"status": "ignored", "event_type": event_type}


def _handle_transaction_completed(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    plan = custom.get("plan", "")
    if username and plan:
        from src.tenants import update_tenant
        update_tenant(username, plan=plan)
        return {"status": "upgraded", "username": username, "plan": plan}
    return {"status": "no_action", "reason": "Missing username/plan in custom_data"}


def _handle_subscription_created(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    plan = custom.get("plan", "")
    sub_id = data.get("id", "")
    if username and plan:
        from src.tenants import update_tenant
        update_tenant(username, plan=plan)
        return {"status": "subscribed", "username": username, "plan": plan, "subscription_id": sub_id}
    return {"status": "no_action", "reason": "Missing data"}


def _handle_subscription_updated(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    plan = custom.get("plan", "")
    status = data.get("status", "")
    if status == "active" and username and plan:
        from src.tenants import update_tenant
        update_tenant(username, plan=plan)
        return {"status": "updated", "username": username, "plan": plan}
    return {"status": "no_action", "reason": "No update needed"}


def _handle_subscription_cancelled(data: dict) -> dict:
    custom = data.get("custom_data", {}) or {}
    username = custom.get("username", "")
    if username:
        from src.tenants import update_tenant
        update_tenant(username, plan="trial")
        return {"status": "downgraded", "username": username, "plan": "trial"}
    return {"status": "no_action", "reason": "Missing username"}
