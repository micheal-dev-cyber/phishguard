"""Tests for billing provider interface and config."""

import pytest
from unittest.mock import patch

from src.env import EnvConfig
from src.billing.provider import BillingProvider
from src.billing.config import get_plan, get_all_plans, get_yearly_savings_pct


def _make_env(**kwargs) -> EnvConfig:
    defaults = {
        "PADDLE_API_KEY": "",
        "PADDLE_CLIENT_TOKEN": "",
        "PADDLE_WEBHOOK_SECRET": "",
        "GUMROAD_ACCESS_TOKEN": "test_token",
        "GUMROAD_WEBHOOK_SECRET": "test_secret",
        "GUMROAD_STARTER_MONTHLY_PERMALINK": "starter-monthly",
        "GUMROAD_STARTER_YEARLY_PERMALINK": "starter-yearly",
        "GUMROAD_BUSINESS_MONTHLY_PERMALINK": "business-monthly",
        "GUMROAD_BUSINESS_YEARLY_PERMALINK": "business-yearly",
    }
    defaults.update(kwargs)
    env = EnvConfig(**defaults)
    env.__post_init__()
    return env


class TestPlanConfig:
    def test_get_plan_exists(self):
        plan = get_plan("starter")
        assert plan.key == "starter"
        assert plan.label == "Starter"
        assert plan.price_monthly == 29
        assert plan.price_yearly == 290

    def test_get_plan_business(self):
        plan = get_plan("business")
        assert plan.key == "business"
        assert plan.price_monthly == 99

    def test_get_plan_unknown_falls_back_to_free(self):
        plan = get_plan("nonexistent")
        assert plan.key == "free"

    def test_get_all_plans_includes_all_keys(self):
        plans = get_all_plans()
        keys = {p.key for p in plans}
        assert "free" in keys
        assert "starter" in keys
        assert "business" in keys
        assert "enterprise" in keys

    def test_yearly_savings_starter(self):
        pct = get_yearly_savings_pct("starter")
        expected = int((1 - 290 / (29 * 12)) * 100)
        assert pct == expected

    def test_yearly_savings_free(self):
        assert get_yearly_savings_pct("free") == 0

    def test_yearly_savings_unknown(self):
        assert get_yearly_savings_pct("nonexistent") == 0


class TestBillingProviderInterface:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BillingProvider()

    def test_subclass_must_implement_all_methods(self):
        class Incomplete(BillingProvider):
            def name(self):
                return "test"
        with pytest.raises(TypeError):
            Incomplete()

    def test_concrete_subclass_works(self):
        class Concrete(BillingProvider):
            def name(self):
                return "concrete"
            def create_checkout_url(self, username, plan_name, billing_cycle, success_url="", cancel_url=""):
                return "https://checkout.test"
            def verify_purchase(self, sale_id):
                return {}
            def get_subscription(self, subscription_id):
                return {}
            def cancel_subscription(self, subscription_id):
                return True
            def update_subscription_plan(self, subscription_id, new_plan, new_billing_cycle=""):
                return True
            def verify_webhook_signature(self, raw_body, signature_header):
                return True
        c = Concrete()
        assert c.name() == "concrete"
        assert c.create_checkout_url("u", "p", "m") == "https://checkout.test"
        assert c.verify_purchase("s") == {}
        assert c.get_subscription("s") == {}
        assert c.cancel_subscription("s") is True
        assert c.update_subscription_plan("s", "p") is True
        assert c.verify_webhook_signature(b"", "sig") is True
