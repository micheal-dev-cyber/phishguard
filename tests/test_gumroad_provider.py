"""Tests for Gumroad billing provider."""

from unittest.mock import patch, MagicMock

import pytest

from src.env import EnvConfig
from src.billing.gumroad import GumroadProvider, is_gumroad_configured


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


class TestIsGumroadConfigured:
    def test_configured_with_keys(self):
        with patch("src.billing.gumroad.ENV", _make_env()):
            assert is_gumroad_configured() is True

    def test_not_configured_without_access_token(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_ACCESS_TOKEN="")):
            assert is_gumroad_configured() is False

    def test_not_configured_without_webhook_secret(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_WEBHOOK_SECRET="")):
            assert is_gumroad_configured() is False

    def test_not_configured_without_both(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_ACCESS_TOKEN="", GUMROAD_WEBHOOK_SECRET="")):
            assert is_gumroad_configured() is False


class TestGumroadProvider:
    def test_name(self):
        provider = GumroadProvider()
        assert provider.name() == "gumroad"

    def test_create_checkout_url_starter_monthly(self):
        with patch("src.billing.gumroad.ENV", _make_env()):
            provider = GumroadProvider()
            url = provider.create_checkout_url("testuser", "starter", "monthly")
            assert url is not None
            assert "starter-monthly" in url
            assert "custom=testuser" in url

    def test_create_checkout_url_business_yearly(self):
        with patch("src.billing.gumroad.ENV", _make_env()):
            provider = GumroadProvider()
            url = provider.create_checkout_url("alice", "business", "yearly")
            assert url is not None
            assert "business-yearly" in url
            assert "custom=alice" in url

    def test_create_checkout_url_with_success_url(self):
        with patch("src.billing.gumroad.ENV", _make_env()):
            provider = GumroadProvider()
            url = provider.create_checkout_url("u", "starter", "monthly", success_url="https://app.com/ok")
            assert url is not None
            assert "success_url" in url

    def test_create_checkout_url_missing_permalink(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_STARTER_MONTHLY_PERMALINK="")):
            provider = GumroadProvider()
            url = provider.create_checkout_url("u", "starter", "monthly")
            assert url is None

    def test_create_checkout_url_unknown_plan(self):
        with patch("src.billing.gumroad.ENV", _make_env()):
            provider = GumroadProvider()
            url = provider.create_checkout_url("u", "nonexistent", "monthly")
            assert url is None

    def test_verify_purchase_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "success": True,
            "sale": {
                "id": "sale_123",
                "email": "user@test.com",
                "product_name": "Starter Monthly",
                "recurrence": "monthly",
                "subscription_id": "sub_abc",
                "license_key": "lic_key_1",
                "price": 2900,
                "currency": "usd",
                "charged": True,
                "variants": "",
                "custom_fields": '{"username": "bob"}',
            },
        }
        with patch("src.billing.gumroad.ENV", _make_env()):
            with patch("src.billing.gumroad.post", return_value=mock_resp):
                provider = GumroadProvider()
                result = provider.verify_purchase("sale_123")
                assert result is not None
                assert result["id"] == "sale_123"
                assert result["email"] == "user@test.com"
                assert result["status"] == "paid"

    def test_verify_purchase_no_access_token(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_ACCESS_TOKEN="")):
            provider = GumroadProvider()
            assert provider.verify_purchase("sale_1") is None

    def test_verify_purchase_api_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("src.billing.gumroad.ENV", _make_env()):
            with patch("src.billing.gumroad.post", return_value=mock_resp):
                provider = GumroadProvider()
                assert provider.verify_purchase("bad_id") is None

    def test_get_subscription_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "success": True,
            "subscription": {
                "id": "sub_abc",
                "product_name": "Business Yearly",
                "recurrence": "yearly",
                "status": "active",
                "user_email": "admin@test.com",
                "cancelled_at": "",
                "ended_at": "",
                "charged_at": "2025-01-01T00:00:00Z",
            },
        }
        with patch("src.billing.gumroad.ENV", _make_env()):
            with patch("src.billing.gumroad.post", return_value=mock_resp):
                provider = GumroadProvider()
                result = provider.get_subscription("sub_abc")
                assert result is not None
                assert result["id"] == "sub_abc"
                assert result["status"] == "active"

    def test_get_subscription_no_token(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_ACCESS_TOKEN="")):
            provider = GumroadProvider()
            assert provider.get_subscription("sub_1") is None

    def test_cancel_subscription_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True}
        with patch("src.billing.gumroad.ENV", _make_env()):
            with patch("src.billing.gumroad.post", return_value=mock_resp):
                provider = GumroadProvider()
                assert provider.cancel_subscription("sub_abc") is True

    def test_cancel_subscription_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": False}
        with patch("src.billing.gumroad.ENV", _make_env()):
            with patch("src.billing.gumroad.post", return_value=mock_resp):
                provider = GumroadProvider()
                assert provider.cancel_subscription("sub_abc") is False

    def test_cancel_subscription_no_token(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_ACCESS_TOKEN="")):
            provider = GumroadProvider()
            assert provider.cancel_subscription("sub_1") is False

    def test_update_subscription_plan_always_returns_false(self):
        provider = GumroadProvider()
        assert provider.update_subscription_plan("sub_1", "business") is False

    def test_verify_webhook_signature_valid(self):
        secret = "test_ws"
    def test_verify_webhook_signature_always_true(self):
        with patch("src.billing.gumroad.ENV", _make_env()):
            provider = GumroadProvider()
            assert provider.verify_webhook_signature(b"any", "anything") is True

    def test_verify_webhook_signature_without_secret(self):
        with patch("src.billing.gumroad.ENV", _make_env(GUMROAD_WEBHOOK_SECRET="")):
            provider = GumroadProvider()
            assert provider.verify_webhook_signature(b"body", "sig") is True

    def test_verify_webhook_signature_empty_header(self):
        with patch("src.billing.gumroad.ENV", _make_env()):
            provider = GumroadProvider()
            assert provider.verify_webhook_signature(b"body", "") is True
