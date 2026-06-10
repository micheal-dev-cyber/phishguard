"""
PhishGuard AI — Billing Provider Interface

All billing providers must implement this abstract base class.
New providers (Stripe, LemonSqueezy, Paddle) implement this interface.
"""
from abc import ABC, abstractmethod
from typing import Optional


class BillingProvider(ABC):
    """Abstract interface for payment providers."""

    @abstractmethod
    def create_checkout_url(
        self,
        username: str,
        plan_name: str,
        billing_cycle: str,
        success_url: str = "",
        cancel_url: str = "",
    ) -> Optional[str]:
        ...

    @abstractmethod
    def verify_purchase(self, sale_id: str) -> Optional[dict]:
        ...

    @abstractmethod
    def get_subscription(self, subscription_id: str) -> Optional[dict]:
        ...

    @abstractmethod
    def cancel_subscription(self, subscription_id: str) -> bool:
        ...

    @abstractmethod
    def update_subscription_plan(
        self, subscription_id: str, new_plan: str, new_billing_cycle: str = ""
    ) -> bool:
        ...

    @abstractmethod
    def verify_webhook_signature(
        self, raw_body: bytes, signature_header: str
    ) -> bool:
        ...

    @abstractmethod
    def name(self) -> str:
        ...
