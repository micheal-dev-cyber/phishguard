"""Integration-style tests for subscription lifecycle via BillingService."""

from unittest.mock import patch, MagicMock

import pytest

from src.env import EnvConfig
from src.billing.gumroad import GumroadProvider
from src.billing.service import BillingService
from src.billing.models import CheckoutRequest, Subscription


def _make_env(**kwargs) -> EnvConfig:
    defaults = {
        "GUMROAD_ACCESS_TOKEN": "test_at",
        "GUMROAD_WEBHOOK_SECRET": "test_ws",
        "GUMROAD_STARTER_MONTHLY_PERMALINK": "starter-monthly",
        "GUMROAD_STARTER_YEARLY_PERMALINK": "starter-yearly",
        "GUMROAD_BUSINESS_MONTHLY_PERMALINK": "business-monthly",
        "GUMROAD_BUSINESS_YEARLY_PERMALINK": "business-yearly",
    }
    defaults.update(kwargs)
    env = EnvConfig(**defaults)
    env.__post_init__()
    return env


@pytest.fixture
def provider():
    with patch("src.billing.gumroad.ENV", _make_env()):
        yield GumroadProvider()


@pytest.fixture
def service(provider):
    return BillingService(provider)


class TestCheckoutFlow:
    def test_create_checkout_returns_url(self, service):
        req = CheckoutRequest(username="alice", plan_name="starter", billing_cycle="monthly")
        resp = service.create_checkout(req)
        assert resp is not None
        assert resp.url is not None
        assert "starter-monthly" in resp.url
        assert resp.plan_name == "starter"
        assert resp.billing_cycle == "monthly"

    def test_create_checkout_yearly(self, service):
        req = CheckoutRequest(username="bob", plan_name="business", billing_cycle="yearly")
        resp = service.create_checkout(req)
        assert resp is not None
        assert "business-yearly" in resp.url

    def test_create_checkout_unknown_plan(self, service):
        req = CheckoutRequest(username="charlie", plan_name="nonexistent", billing_cycle="monthly")
        resp = service.create_checkout(req)
        assert resp is None


class TestPurchaseActivation:
    def test_verify_and_activate_success(self, service):
        mock_sale = {
            "id": "sale_1",
            "email": "alice@test.com",
            "product_name": "Starter Monthly",
            "recurrence": "monthly",
            "subscription_id": "sub_abc",
            "license_key": "lic_abc",
            "price": 2900,
            "currency": "usd",
            "custom_fields": {"username": "alice"},
        }
        with patch.object(service.provider, "verify_purchase", return_value=mock_sale):
            with patch("src.billing.service._save_subscription"):
                with patch.object(service, "_update_tenant_plan"):
                    result = service.verify_and_activate("sale_1")
                    assert result.success is True
                    assert result.plan_name == "starter"
                    assert result.subscription_id == "sub_abc"
                    assert result.license_key == "lic_abc"

    def test_verify_and_activate_verification_fails(self, service):
        with patch.object(service.provider, "verify_purchase", return_value=None):
            result = service.verify_and_activate("bad_sale")
            assert result.success is False
            assert "verification failed" in result.message.lower()

    def test_verify_and_activate_username_from_hint(self, service):
        mock_sale = {
            "id": "sale_2",
            "email": "nobody@test.com",
            "product_name": "Business Yearly",
            "recurrence": "yearly",
            "subscription_id": "sub_xyz",
            "custom_fields": {},
        }
        with patch.object(service.provider, "verify_purchase", return_value=mock_sale):
            with patch("src.billing.service._save_subscription"):
                with patch.object(service, "_update_tenant_plan"):
                    result = service.verify_and_activate("sale_2", username_hint="bob")
                    assert result.success is True
                    assert result.plan_name == "business"

    def test_verify_and_activate_without_username(self, service):
        mock_sale = {
            "id": "sale_3",
            "email": "",
            "product_name": "Starter Monthly",
            "recurrence": "monthly",
            "custom_fields": {},
        }
        with patch.object(service.provider, "verify_purchase", return_value=mock_sale):
            result = service.verify_and_activate("sale_3")
            assert result.success is False


class TestSubscriptionManagement:
    def test_get_user_subscription(self, service):
        with patch("src.billing.service._load_subscription") as mock_load:
            mock_load.return_value = Subscription(
                username="alice", plan_name="starter", status="active",
                billing_cycle="monthly", billing_provider="gumroad",
                provider_subscription_id="sub_abc",
            )
            sub = service.get_user_subscription("alice")
            assert sub is not None
            assert sub.plan_name == "starter"
            assert sub.is_active() is True

    def test_get_user_subscription_not_found(self, service):
        with patch("src.billing.service._load_subscription", return_value=None):
            assert service.get_user_subscription("nobody") is None

    def test_cancel_subscription_success(self, service):
        with patch("src.billing.service._load_subscription") as mock_load:
            mock_load.return_value = Subscription(
                username="alice", plan_name="starter", status="active",
                billing_cycle="monthly", billing_provider="gumroad",
                provider_subscription_id="sub_abc",
            )
            with patch.object(service.provider, "cancel_subscription", return_value=True):
                with patch("src.billing.service._save_subscription") as mock_save:
                    result = service.cancel_subscription("alice")
                    assert result is True
                    mock_save.assert_called_once()

    def test_cancel_subscription_no_local_record(self, service):
        with patch("src.billing.service._load_subscription", return_value=None):
            assert service.cancel_subscription("nobody") is False

    def test_cancel_subscription_provider_fails(self, service):
        with patch("src.billing.service._load_subscription") as mock_load:
            mock_load.return_value = Subscription(
                username="alice", plan_name="starter", status="active",
                billing_cycle="monthly", billing_provider="gumroad",
                provider_subscription_id="sub_abc",
            )
            with patch.object(service.provider, "cancel_subscription", return_value=False):
                assert service.cancel_subscription("alice") is False


class TestIsUpgrade:
    def test_is_upgrade_true(self, service):
        assert service._is_upgrade("starter", "free") is True
        assert service._is_upgrade("business", "starter") is True
        assert service._is_upgrade("enterprise", "business") is True

    def test_is_upgrade_false(self, service):
        assert service._is_upgrade("free", "starter") is False
        assert service._is_upgrade("starter", "business") is False

    def test_is_upgrade_unknown_plan(self, service):
        assert service._is_upgrade("nonexistent", "starter") is False


class TestPlanFromProduct:
    def test_starter(self, service):
        assert service._plan_from_product("Starter Monthly") == "starter"

    def test_business(self, service):
        assert service._plan_from_product("Business Yearly") == "business"

    def test_free(self, service):
        assert service._plan_from_product("Free Trial") == "free"

    def test_unknown(self, service):
        assert service._plan_from_product("Unknown Product") == ""
