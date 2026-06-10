"""
PhishGuard AI — Billing Data Models

Shared value objects used across all billing providers and the service layer.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class Subscription:
    username: str
    plan_name: str
    status: str  # active, cancelled, expired, paused
    billing_cycle: str  # monthly, yearly
    billing_provider: str  # gumroad, paddle, stripe
    provider_subscription_id: str = ""
    provider_sale_id: str = ""
    last_payment_date: Optional[str] = None
    next_billing_date: Optional[str] = None
    trial_end: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""

    def is_active(self) -> bool:
        return self.status in ("active", "trialing")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PurchaseResult:
    success: bool
    plan_name: str = ""
    billing_cycle: str = ""
    subscription_id: str = ""
    sale_id: str = ""
    license_key: str = ""
    message: str = ""


@dataclass
class CheckoutRequest:
    username: str
    plan_name: str
    billing_cycle: str  # monthly, yearly
    success_url: str = ""
    cancel_url: str = ""


@dataclass
class CheckoutResponse:
    url: str
    plan_name: str
    billing_cycle: str


@dataclass
class WebhookEvent:
    event_type: str
    payload: dict
    raw_body: bytes
    provider: str = "gumroad"
    processed: bool = False
    error: Optional[str] = None
