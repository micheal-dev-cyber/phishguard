# src/billing/paddle_compat.py
"""
Compatibility layer — routes old Paddle calls through the new BillingService.
Allows gradual migration: old Paddle imports continue to work while new
code uses BillingService directly.
"""

from typing import Optional
from src.billing.gumroad import GumroadProvider, is_gumroad_configured
from src.billing.service import BillingService


def _get_service():
    return BillingService(GumroadProvider())


# ── Stub: re-export for backward compatibility ─────────────────────────

def paddle_configured() -> bool:
    """Check if ANY billing provider is configured (Paddle or Gumroad)."""
    from src.env import ENV
    if ENV.paddle_configured:
        return True
    return is_gumroad_configured()


def get_local_subscription(username: str) -> Optional[dict]:
    svc = _get_service()
    sub = svc.get_user_subscription(username)
    if sub:
        return {
            "subscription_id": sub.provider_subscription_id,
            "plan": sub.plan_name,
            "status": sub.status,
            "billing_cycle": sub.billing_cycle,
            "next_billed_at": sub.next_billing_date or "",
        }
    return None


def cancel_user_subscription(username: str) -> bool:
    svc = _get_service()
    return svc.cancel_subscription(username)
