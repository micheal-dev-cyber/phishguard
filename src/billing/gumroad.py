"""
PhishGuard AI — Gumroad Billing Provider

Implements the BillingProvider interface for Gumroad.
https://gumroad.com/api

Gumroad model:
- Products created in Gumroad dashboard (not via API)
- Checkout links generated as product URLs with query params
- License key API for purchase verification
- Webhooks for event processing (sale.created, etc.)
- No official subscription management API — uses sale-based tracking
"""

import json
import logging
from typing import Optional

from src.env import ENV
from src.http_client import post

from src.billing.provider import BillingProvider

logger = logging.getLogger(__name__)

GUMROAD_API_BASE = "https://api.gumroad.com/v2"
GUMROAD_CHECKOUT_BASE = "https://gumroad.com/l"


class GumroadProvider(BillingProvider):
    def name(self) -> str:
        return "gumroad"

    def _license_key_verify(self, license_key: str, product_permalink: str) -> Optional[dict]:
        try:
            resp = post(
                f"{GUMROAD_API_BASE}/licenses/verify",
                json={
                    "product_permalink": product_permalink,
                    "license_key": license_key,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    return data.get("purchase", {})
            return None
        except Exception as e:
            logger.warning("gumroad: License verification failed: %s", e)
            return None

    def create_checkout_url(
        self,
        username: str,
        plan_name: str,
        billing_cycle: str,
        success_url: str = "",
        cancel_url: str = "",
    ) -> Optional[str]:
        """Generate a Gumroad checkout URL for the given plan.

        Gumroad uses product permalinks. We pass custom params via query string.
        """
        products = _get_products()
        product_key = f"{plan_name}_{billing_cycle}"
        product_info = products.get(product_key)
        if not product_info:
            logger.warning("gumroad: No product configured for %s", product_key)
            return None

        permalink = product_info.get("permalink")
        if not permalink:
            return None

        params = f"custom={username}"
        base = f"{GUMROAD_CHECKOUT_BASE}/{permalink}?{params}"

        if success_url:
            base += f"&success_url={_urlencode(success_url)}"
        return base

    def verify_purchase(self, sale_id: str) -> Optional[dict]:
        """Verify a sale using Gumroad's API."""
        access_token = ENV.GUMROAD_ACCESS_TOKEN
        if not access_token:
            return None
        try:
            resp = post(
                f"{GUMROAD_API_BASE}/sales/{sale_id}",
                data={"access_token": access_token},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    sale = data.get("sale", {})
                    return {
                        "id": sale.get("id"),
                        "email": sale.get("email", ""),
                        "product_name": sale.get("product_name", ""),
                        "recurrence": sale.get("recurrence", ""),
                        "subscription_id": sale.get("subscription_id", ""),
                        "license_key": sale.get("license_key", ""),
                        "price": sale.get("price", 0),
                        "currency": sale.get("currency", "usd"),
                        "status": "paid" if sale.get("charged") else "pending",
                        "variants": sale.get("variants", ""),
                        "custom_fields": json.loads(sale.get("custom_fields", "{}")),
                    }
            return None
        except Exception as e:
            logger.warning("gumroad: Sale verification failed: %s", e)
            return None

    def get_subscription(self, subscription_id: str) -> Optional[dict]:
        """Get subscription details. Gumroad exposes limited subscription data via sales API.

        For full data, we rely on locally-stored subscription records updated by webhooks.
        """
        access_token = ENV.GUMROAD_ACCESS_TOKEN
        if not access_token or not subscription_id:
            return None
        try:
            resp = post(
                f"{GUMROAD_API_BASE}/subscriptions/{subscription_id}",
                data={"access_token": access_token},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    sub = data.get("subscription", {})
                    return {
                        "id": sub.get("id"),
                        "product_name": sub.get("product_name", ""),
                        "recurrence": sub.get("recurrence", ""),
                        "status": sub.get("status", "unknown"),
                        "user_email": sub.get("user_email", ""),
                        "cancelled_at": sub.get("cancelled_at", ""),
                        "ended_at": sub.get("ended_at", ""),
                        "charged_at": sub.get("charged_at", ""),
                    }
            return None
        except Exception as e:
            logger.warning("gumroad: Get subscription failed: %s", e)
            return None

    def cancel_subscription(self, subscription_id: str) -> bool:
        """Cancel a G- subscription via Gumroad API."""
        access_token = ENV.GUMROAD_ACCESS_TOKEN
        if not access_token or not subscription_id:
            return False
        try:
            resp = post(
                f"{GUMROAD_API_BASE}/subscriptions/{subscription_id}/cancel",
                data={"access_token": access_token},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("success", False)
            return False
        except Exception as e:
            logger.warning("gumroad: Cancel subscription failed: %s", e)
            return False

    def update_subscription_plan(
        self, subscription_id: str, new_plan: str, new_billing_cycle: str = ""
    ) -> bool:
        """Gumroad doesn't support plan changes via API.

        For upgrades/downgrades, user must cancel and re-subscribe.
        We store the desired plan and handle it on next webhook.
        """
        logger.info(
            "gumroad: Plan change requested for %s -> %s. "
            "User should cancel and re-subscribe.",
            subscription_id, new_plan,
        )
        return False

    def verify_webhook_signature(self, raw_body: bytes, signature_header: str) -> bool:
        secret = ENV.GUMROAD_WEBHOOK_SECRET or ""
        if not secret:
            logger.warning("GUMROAD_WEBHOOK_SECRET not set — webhook auth disabled")
            return True
        import hmac
        return hmac.compare_digest(signature_header.strip(), secret.strip())


# ── Helper ──────────────────────────────────────────────────────────────


def _get_products() -> dict:
    """Get product permalink mapping from env configuration.

    Returns:
        dict: { "{plan}_{cycle}": {"permalink": "...", "price": ...} }
    """
    return {
        "starter_monthly":  {"permalink": ENV.GUMROAD_STARTER_MONTHLY_PERMALINK},
        "starter_yearly":   {"permalink": ENV.GUMROAD_STARTER_YEARLY_PERMALINK},
        "business_monthly": {"permalink": ENV.GUMROAD_BUSINESS_MONTHLY_PERMALINK},
        "business_yearly":  {"permalink": ENV.GUMROAD_BUSINESS_YEARLY_PERMALINK},
    }


def _urlencode(s: str) -> str:
    """Minimal URL encoding for query params."""
    import urllib.parse
    return urllib.parse.quote(s, safe="")


def is_gumroad_configured() -> bool:
    """Check if Gumroad credentials are configured."""
    return bool(ENV.GUMROAD_ACCESS_TOKEN)
