"""
PhishGuard AI — Billing Service

Orchestration layer that ties together billing providers, local state,
plan management, analytics, and events.  Provider-agnostic — swap the
provider to change payment backend.
"""
import json
import logging
from datetime import datetime
from typing import Optional

from src.billing.models import (
    CheckoutRequest,
    CheckoutResponse,
    PurchaseResult,
    Subscription,
    WebhookEvent,
)
from src.billing.provider import BillingProvider

logger = logging.getLogger(__name__)


class BillingService:
    """High-level billing operations.  Single entry point for the rest of the app."""

    def __init__(self, provider: BillingProvider):
        self.provider = provider

    # ── Checkout ────────────────────────────────────────────────────────

    def create_checkout(self, req: CheckoutRequest) -> Optional[CheckoutResponse]:
        """Create a checkout URL for the given plan and billing cycle."""
        url = self.provider.create_checkout_url(
            username=req.username,
            plan_name=req.plan_name,
            billing_cycle=req.billing_cycle,
            success_url=req.success_url,
            cancel_url=req.cancel_url,
        )
        if not url:
            return None
        self._emit("billing:checkout_started", req.username, {
            "plan": req.plan_name,
            "cycle": req.billing_cycle,
        })
        self._track("checkout_started", req.username, {
            "plan": req.plan_name,
            "cycle": req.billing_cycle,
        })
        return CheckoutResponse(
            url=url,
            plan_name=req.plan_name,
            billing_cycle=req.billing_cycle,
        )

    # ── Purchase verification ───────────────────────────────────────────

    def verify_and_activate(
        self, sale_id: str, username_hint: str = ""
    ) -> PurchaseResult:
        """Verify a purchase with the provider, then activate the plan locally."""
        sale = self.provider.verify_purchase(sale_id)
        if not sale:
            return PurchaseResult(success=False, message="Purchase verification failed")

        plan_name = self._plan_from_product(sale.get("product_name", ""))
        billing_cycle = sale.get("recurrence", "monthly")
        sub_id = sale.get("subscription_id", "")
        license_key = sale.get("license_key", "")
        email = sale.get("email", "")

        username = self._resolve_username(sale, username_hint)

        if not username and email:
            username = email.split("@")[0]

        if not username:
            return PurchaseResult(success=False, message="Could not identify user")

        _save_subscription(
            username=username,
            plan_name=plan_name,
            status="active",
            billing_cycle=billing_cycle,
            provider_sub_id=sub_id,
            provider_sale_id=sale_id,
        )

        self._update_tenant_plan(username, plan_name)

        self._emit("billing:checkout_completed", username, {
            "plan": plan_name, "cycle": billing_cycle,
        })
        self._emit("billing:subscription_created", username, {
            "plan": plan_name, "cycle": billing_cycle, "sub_id": sub_id,
        })
        self._track("checkout_completed", username, {
            "plan": plan_name, "cycle": billing_cycle,
        })
        self._track("subscription_created", username, {
            "plan": plan_name, "cycle": billing_cycle,
        })

        return PurchaseResult(
            success=True,
            plan_name=plan_name,
            billing_cycle=billing_cycle,
            subscription_id=sub_id,
            sale_id=sale_id,
            license_key=license_key,
        )

    # ── Webhook processing ──────────────────────────────────────────────

    def process_webhook(self, raw_body: bytes, headers: dict) -> dict:
        """Verify signature, parse event, and dispatch to handler."""
        sig_header = headers.get("X-Gumroad-Signature", "")
        if not self.provider.verify_webhook_signature(raw_body, sig_header):
            logger.warning("billing: Invalid webhook signature")
            return {"status": "rejected", "reason": "invalid_signature"}

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            logger.warning("billing: Failed to parse webhook body: %s", e)
            return {"status": "rejected", "reason": "invalid_json"}

        # Gumroad uses "resource_name" field; standard format uses "type"
        event_type = payload.get("type", "")
        resource_name = payload.get("resource_name", "")

        if resource_name:
            event_type = _GUROAD_TO_EVENT.get(resource_name, "")
            data = {k: v for k, v in payload.items() if k != "resource_name"}
        else:
            data = payload.get("data", {})

        evt = WebhookEvent(
            event_type=event_type or resource_name,
            payload=payload,
            raw_body=raw_body,
            provider=self.provider.name(),
        )

        if not event_type:
            logger.info("billing: Ignored webhook with unknown event: %s", event_type or resource_name)
            self._persist_webhook_event(evt)
            return {"status": "ignored", "event_type": event_type or resource_name}

        handler = _WEBHOOK_HANDLERS.get(event_type)
        if not handler:
            logger.info("billing: Ignored webhook event: %s", event_type)
            self._persist_webhook_event(evt)
            return {"status": "ignored", "event_type": event_type}

        try:
            result = handler(self, data)
            evt.processed = True
            self._persist_webhook_event(evt)
            return result
        except Exception as e:
            evt.error = str(e)
            self._persist_webhook_event(evt)
            logger.error("billing: Webhook handler failed: %s", e)
            return {"status": "error", "reason": str(e)}

    # ── Subscription queries ────────────────────────────────────────────

    def get_user_subscription(self, username: str) -> Optional[Subscription]:
        """Get the active subscription for a user from local DB."""
        return _load_subscription(username)

    def cancel_subscription(self, username: str) -> bool:
        """Cancel a user's subscription via the provider."""
        sub = _load_subscription(username)
        if not sub or not sub.provider_subscription_id:
            return False
        ok = self.provider.cancel_subscription(sub.provider_subscription_id)
        if ok:
            _save_subscription(
                username=username,
                plan_name=sub.plan_name,
                status="cancelled",
                billing_cycle=sub.billing_cycle,
                provider_sub_id=sub.provider_subscription_id,
            )
            self._emit("billing:subscription_cancelled", username, {
                "plan": sub.plan_name,
            })
            self._track("subscription_cancelled", username, {
                "plan": sub.plan_name,
            })
        return ok

    # ── Webhook event handlers ──────────────────────────────────────────

    def _handle_sale_created(self, data: dict) -> dict:
        """Handle sale.created webhook."""
        return self._process_sale(data, event_subtype="created")

    def _handle_sale_updated(self, data: dict) -> dict:
        """Handle sale.updated webhook."""
        return self._process_sale(data, event_subtype="updated")

    def _handle_subscription_cancelled(self, data: dict) -> dict:
        """Handle subscription.cancelled webhook."""
        sub_id = data.get("subscription_id", "")
        username = self._username_from_subscription(sub_id)
        if not username:
            return {"status": "no_action", "reason": "unknown_user"}

        _save_subscription(
            username=username,
            plan_name=_load_subscription(username).plan_name if _load_subscription(username) else "free",
            status="cancelled",
            billing_cycle="",
            provider_sub_id=sub_id,
        )
        self._emit("billing:subscription_cancelled", username, {})
        self._track("subscription_cancelled", username, {})
        return {"status": "cancelled", "username": username}

    def _handle_subscription_ended(self, data: dict) -> dict:
        """Handle subscription.ended webhook — downgrade to free."""
        sub_id = data.get("subscription_id", "")
        username = self._username_from_subscription(sub_id)
        if not username:
            return {"status": "no_action", "reason": "unknown_user"}

        _save_subscription(
            username=username,
            plan_name="free",
            status="expired",
            billing_cycle="",
            provider_sub_id=sub_id,
        )
        self._update_tenant_plan(username, "free")
        return {"status": "expired", "username": username, "plan": "free"}

    def _handle_subscription_updated(self, data: dict) -> dict:
        """Handle subscription.updated — upgrade/downgrade."""
        sub_id = data.get("subscription_id", "")
        new_product = data.get("product_name", "")
        new_plan = self._plan_from_product(new_product)
        username = self._username_from_subscription(sub_id)
        if not username or not new_plan:
            return {"status": "no_action", "reason": "missing_data"}

        old_plan = _load_subscription(username).plan_name if _load_subscription(username) else ""
        status = "upgraded" if self._is_upgrade(new_plan, old_plan) else "downgraded"

        _save_subscription(
            username=username,
            plan_name=new_plan,
            status="active",
            billing_cycle=data.get("recurrence", "monthly"),
            provider_sub_id=sub_id,
        )
        self._update_tenant_plan(username, new_plan)

        self._emit(f"billing:subscription_{status}", username, {
            "from": old_plan, "to": new_plan,
        })
        self._track(f"subscription_{status}", username, {
            "from": old_plan, "to": new_plan,
        })
        return {"status": status, "username": username, "plan": new_plan}

    def _handle_refund_created(self, data: dict) -> dict:
        """Handle refund.created webhook."""
        sale_id = data.get("sale_id", "")
        username = self._username_from_sale(sale_id)
        if not username:
            return {"status": "no_action", "reason": "unknown_user"}

        _save_subscription(
            username=username,
            plan_name="free",
            status="refunded",
            billing_cycle="",
            provider_sub_id="",
        )
        self._update_tenant_plan(username, "free")
        self._track("subscription_cancelled", username, {"reason": "refund"})
        return {"status": "refunded", "username": username}

    # ── Internal helpers ────────────────────────────────────────────────

    def _process_sale(self, data: dict, event_subtype: str = "created") -> dict:
        sale_id = str(data.get("id", ""))
        email = data.get("email", "")
        product_name = data.get("product_name", "")
        recurrence = data.get("recurrence", "monthly")
        sub_id = data.get("subscription_id", "")
        # Gumroad Ping URL: "custom" flat field. Resource Subs: "custom_fields.username"
        custom_fields = data.get("custom_fields", {})
        custom_username = ""
        if isinstance(custom_fields, dict):
            custom_username = custom_fields.get("username", "")
        if not custom_username:
            custom_username = data.get("custom", "")
        username = custom_username or email.split("@")[0]

        plan = self._plan_from_product(product_name)
        if not plan:
            return {"status": "ignored", "reason": f"Unknown product: {product_name}"}

        # Upsert local subscription record
        _save_subscription(
            username=username,
            plan_name=plan,
            status="active",
            billing_cycle=recurrence,
            provider_sub_id=sub_id,
            provider_sale_id=sale_id,
        )
        self._update_tenant_plan(username, plan)

        self._track(f"checkout_{event_subtype}", username, {
            "plan": plan, "cycle": recurrence,
        })
        if event_subtype == "created":
            self._track("subscription_created", username, {
                "plan": plan, "cycle": recurrence,
            })

        return {"status": event_subtype, "username": username, "plan": plan}

    def _plan_from_product(self, product_name: str) -> str:
        name_lower = product_name.lower().strip()
        if "starter" in name_lower:
            return "starter"
        if "business" in name_lower:
            return "business"
        if "free" in name_lower or "trial" in name_lower:
            return "free"
        return ""

    def _resolve_username(self, sale: dict, hint: str) -> str:
        if hint:
            return hint
        custom = sale.get("custom_fields", {})
        if isinstance(custom, dict) and custom.get("username"):
            return custom["username"]
        custom_flat = sale.get("custom", "")
        if custom_flat:
            return custom_flat
        email = sale.get("email", "")
        if email:
            return email.split("@")[0].replace(".", "_")
        return ""

    def _username_from_subscription(self, sub_id: str) -> str:
        from src.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "SELECT username FROM billing_subscriptions WHERE provider_subscription_id = ?",
            (sub_id,),
        )
        row = c.fetchone()
        conn.close()
        return row[0] if row else ""

    def _username_from_sale(self, sale_id: str) -> str:
        from src.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "SELECT username FROM billing_subscriptions WHERE provider_sale_id = ?",
            (sale_id,),
        )
        row = c.fetchone()
        conn.close()
        return row[0] if row else ""

    def _is_upgrade(self, new_plan: str, old_plan: str) -> bool:
        tiers = ["free", "trial", "starter", "business", "enterprise"]
        try:
            return tiers.index(new_plan) > tiers.index(old_plan)
        except ValueError:
            return False

    def _update_tenant_plan(self, username: str, plan: str):
        from src.tenants import update_tenant
        update_tenant(username, plan=plan)

    def _persist_webhook_event(self, evt: WebhookEvent):
        from src.db import get_connection
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO webhook_events (event_type, provider, payload, processed, error, created_at) "
                "VALUES (?, ?, ?, ?, ?, datetime('now'))",
                (evt.event_type, evt.provider, json.dumps(evt.payload),
                 1 if evt.processed else 0, evt.error),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning("billing: Failed to persist webhook event: %s", e)

    def _track(self, event: str, username: str = "", metadata: dict = None):
        try:
            from src.analytics import track_event
            track_event(event, username, metadata=metadata or {})
        except Exception as e:
            logger.debug("billing: Analytics track failed: %s", e)

    def _emit(self, event: str, username: str = "", metadata: dict = None):
        """Emit an event for AICOS compatibility."""
        try:
            from src.events import emit
            emit(event, username=username, metadata=metadata or {})
        except ImportError:
            pass  # AICOS not installed
        except Exception as e:
            logger.debug("billing: Event emit failed: %s", e)


# ── Webhook handler registry ────────────────────────────────────────────

_WEBHOOK_HANDLERS = {
    "sale.created": lambda svc, d: svc._handle_sale_created(d),
    "sale.updated": lambda svc, d: svc._handle_sale_updated(d),
    "subscription.created": lambda svc, d: svc._handle_sale_created(d),
    "subscription.cancelled": lambda svc, d: svc._handle_subscription_cancelled(d),
    "subscription.ended": lambda svc, d: svc._handle_subscription_ended(d),
    "subscription.updated": lambda svc, d: svc._handle_subscription_updated(d),
    "refund.created": lambda svc, d: svc._handle_refund_created(d),
}

# Gumroad resource_name → event type mapping
_GUROAD_TO_EVENT = {
    "sale": "sale.created",
    "refund": "refund.created",
    "cancellation": "subscription.cancelled",
    "subscription_updated": "subscription.updated",
    "subscription_ended": "subscription.ended",
    "subscription_restarted": "subscription.updated",
}


# ── Local DB helpers ────────────────────────────────────────────────────


def _save_subscription(
    username: str,
    plan_name: str,
    status: str,
    billing_cycle: str,
    provider_sub_id: str = "",
    provider_sale_id: str = "",
):
    from src.db import get_connection
    try:
        conn = get_connection()
        c = conn.cursor()
        _ensure_table(c)

        # Check if row exists
        c.execute("SELECT id FROM billing_subscriptions WHERE username = ?", (username,))
        row = c.fetchone()

        if row:
            c.execute(
                """UPDATE billing_subscriptions SET
                   plan_name = ?, status = ?, billing_cycle = ?,
                   provider_subscription_id = ?, provider_sale_id = ?,
                   updated_at = datetime('now')
                   WHERE username = ?""",
                (plan_name, status, billing_cycle,
                 provider_sub_id, provider_sale_id, username),
            )
        else:
            c.execute(
                """INSERT INTO billing_subscriptions
                   (username, plan_name, status, billing_cycle,
                    provider_subscription_id, provider_sale_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                (username, plan_name, status, billing_cycle,
                 provider_sub_id, provider_sale_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("billing: Failed to save subscription for %s: %s", username, e)


def _load_subscription(username: str) -> Optional[Subscription]:
    from src.db import get_connection
    try:
        conn = get_connection()
        c = conn.cursor()
        _ensure_table(c)
        c.execute(
            """SELECT plan_name, status, billing_cycle, billing_provider,
                      provider_subscription_id, provider_sale_id,
                      last_payment_date, next_billing_date, created_at, updated_at
               FROM billing_subscriptions WHERE username = ?""",
            (username,),
        )
        row = c.fetchone()
        conn.close()
        if row:
            return Subscription(
                username=username,
                plan_name=row[0] or "free",
                status=row[1] or "unknown",
                billing_cycle=row[2] or "",
                billing_provider=row[3] or "",
                provider_subscription_id=row[4] or "",
                provider_sale_id=row[5] or "",
                last_payment_date=row[6],
                next_billing_date=row[7],
                created_at=row[8] or "",
                updated_at=row[9] or "",
            )
    except Exception as e:
        logger.warning("billing: Failed to load subscription for %s: %s", username, e)
    return None


def _ensure_table(c):
    c.execute("""
        CREATE TABLE IF NOT EXISTS billing_subscriptions (
            id                        INTEGER PRIMARY KEY AUTOINCREMENT,
            username                  TEXT UNIQUE NOT NULL,
            plan_name                 TEXT NOT NULL DEFAULT 'free',
            status                    TEXT NOT NULL DEFAULT 'unknown',
            billing_cycle             TEXT DEFAULT '',
            billing_provider          TEXT DEFAULT 'gumroad',
            provider_subscription_id  TEXT DEFAULT '',
            provider_sale_id          TEXT DEFAULT '',
            last_payment_date         TEXT DEFAULT '',
            next_billing_date         TEXT DEFAULT '',
            created_at                TEXT DEFAULT (datetime('now')),
            updated_at                TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS webhook_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT NOT NULL,
            provider    TEXT DEFAULT '',
            payload     TEXT DEFAULT '{}',
            processed   INTEGER DEFAULT 0,
            error       TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
