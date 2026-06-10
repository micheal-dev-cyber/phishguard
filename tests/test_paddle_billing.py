import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from src.env import EnvConfig


def _make_env(**kwargs) -> EnvConfig:
    defaults = {
        "PADDLE_API_KEY": "test_api_key",
        "PADDLE_CLIENT_TOKEN": "test_client_token",
        "PADDLE_WEBHOOK_SECRET": "test_webhook_secret",
        "PADDLE_PRICE_ID_STARTER": "pri_starter",
        "PADDLE_PRICE_ID_BUSINESS": "pri_business",
        "PADDLE_PRICE_ID_CONSULTANT": "",
        "PADDLE_PRICE_ID_ENTERPRISE": "",
        "PADDLE_ENVIRONMENT": "sandbox",
    }
    defaults.update(kwargs)
    env = EnvConfig(**defaults)
    env.__post_init__()
    return env


@pytest.fixture(autouse=True)
def _reset_env():
    pass


class TestIsConfigured:
    def test_configured_with_keys(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import is_configured
            assert is_configured() is True

    def test_not_configured_without_api_key(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_API_KEY="")):
            from src.paddle_billing import is_configured
            assert is_configured() is False

    def test_not_configured_without_client_token(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_CLIENT_TOKEN="")):
            from src.paddle_billing import is_configured
            assert is_configured() is False

    def test_not_configured_without_both(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_API_KEY="", PADDLE_CLIENT_TOKEN="")):
            from src.paddle_billing import is_configured
            assert is_configured() is False


class TestGetPriceId:
    def test_returns_starter_price_id(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import get_price_id
            assert get_price_id("starter") == "pri_starter"

    def test_returns_business_price_id(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import get_price_id
            assert get_price_id("business") == "pri_business"

    def test_returns_none_for_unknown_plan(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import get_price_id
            assert get_price_id("nonexistent") is None

    def test_returns_empty_string_for_unset_price_id(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import get_price_id
            assert get_price_id("enterprise") == ""


class TestGenerateCheckoutUrl:
    def test_returns_url_on_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"data": {"urls": {"checkout": "https://checkout.paddle.com/123"}}}
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", return_value=mock_resp):
                from src.paddle_billing import generate_checkout_url
                result = generate_checkout_url("testuser", "starter")
                assert result == "https://checkout.paddle.com/123"

    def test_returns_url_with_success_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"data": {"urls": {"checkout": "https://checkout.paddle.com/123"}}}
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", return_value=mock_resp):
                from src.paddle_billing import generate_checkout_url
                result = generate_checkout_url("testuser", "starter", success_url="http://localhost:8501/?checkout=completed")
                assert result == "https://checkout.paddle.com/123"

    def test_returns_none_without_api_key(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_API_KEY="")):
            from src.paddle_billing import generate_checkout_url
            result = generate_checkout_url("testuser", "starter")
            assert result is None

    def test_returns_none_without_price_id(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import generate_checkout_url
            result = generate_checkout_url("testuser", "nonexistent")
            assert result is None

    def test_returns_none_on_api_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", return_value=mock_resp):
                from src.paddle_billing import generate_checkout_url
                result = generate_checkout_url("testuser", "starter")
                assert result is None

    def test_returns_none_on_exception(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", side_effect=Exception("Network error")):
                from src.paddle_billing import generate_checkout_url
                result = generate_checkout_url("testuser", "starter")
                assert result is None


class TestVerifyWebhookSignature:
    def test_valid_signature_passes(self):
        secret = "test_webhook_secret"
        body = json.dumps({"event_type": "transaction.completed"}).encode()
        ts = "1740000000"
        sig = hmac.new(secret.encode(), f"{ts}{body.decode()}".encode(), hashlib.sha256).hexdigest()
        header = f"ts={ts};h1={sig}"
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import verify_webhook_signature
            assert verify_webhook_signature(body, header) is True

    def test_invalid_signature_fails(self):
        body = json.dumps({"event_type": "transaction.completed"}).encode()
        header = "ts=1740000000;h1=invalid_signature"
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import verify_webhook_signature
            assert verify_webhook_signature(body, header) is False

    def test_missing_header_fails(self):
        body = json.dumps({"event_type": "transaction.completed"}).encode()
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import verify_webhook_signature
            assert verify_webhook_signature(body, "") is False

    def test_missing_secret_fails(self):
        body = json.dumps({"event_type": "transaction.completed"}).encode()
        header = "ts=1740000000;h1=somesig"
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_WEBHOOK_SECRET="")):
            from src.paddle_billing import verify_webhook_signature
            assert verify_webhook_signature(body, header) is False

    def test_malformed_header_fails(self):
        body = json.dumps({"event_type": "transaction.completed"}).encode()
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import verify_webhook_signature
            assert verify_webhook_signature(body, "not-a-valid-header") is False


class TestVerifyTransaction:
    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": "txn_123", "status": "completed", "custom_data": {"username": "testuser", "plan": "starter"}}}
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.get", return_value=mock_resp):
                from src.paddle_billing import verify_transaction
                result = verify_transaction("txn_123")
                assert result is not None
                assert result["id"] == "txn_123"
                assert result["status"] == "completed"

    def test_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.get", return_value=mock_resp):
                from src.paddle_billing import verify_transaction
                assert verify_transaction("txn_123") is None

    def test_no_api_key(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_API_KEY="")):
            from src.paddle_billing import verify_transaction
            assert verify_transaction("txn_123") is None


class TestPlanFromPriceId:
    def test_returns_plan_for_starter(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import _plan_from_price_id
            assert _plan_from_price_id("pri_starter") == "starter"

    def test_returns_plan_for_business(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import _plan_from_price_id
            assert _plan_from_price_id("pri_business") == "business"

    def test_returns_unknown_for_unmatched(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import _plan_from_price_id
            assert _plan_from_price_id("pri_unknown") == "unknown"


class TestHandleWebhookEvent:
    def test_transaction_completed_upgrades_user(self, tmp_path):
        payload = {
            "event_type": "transaction.completed",
            "data": {
                "id": "txn_123",
                "custom_data": {"username": "testuser", "plan": "starter"},
            },
        }
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.tenants.update_tenant") as mock_update:
                with patch("src.paddle_billing._save_subscription"):
                    from src.paddle_billing import handle_webhook_event
                    result = handle_webhook_event(payload)
                    assert result["status"] == "upgraded"
                    assert result["username"] == "testuser"
                    assert result["plan"] == "starter"
                    mock_update.assert_called_once_with("testuser", plan="starter")

    def test_subscription_created_with_custom_data(self):
        payload = {
            "event_type": "subscription.created",
            "data": {
                "id": "sub_123",
                "custom_data": {"username": "testuser", "plan": "business"},
                "items": [{"price": {"id": "pri_business"}}],
            },
        }
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.tenants.update_tenant") as mock_update:
                with patch("src.paddle_billing._save_subscription"):
                    from src.paddle_billing import handle_webhook_event
                    result = handle_webhook_event(payload)
                    assert result["status"] == "subscribed"
                    mock_update.assert_called_once_with("testuser", plan="business")

    def test_subscription_cancelled_downgrades_to_trial(self):
        payload = {
            "event_type": "subscription.cancelled",
            "data": {
                "id": "sub_123",
                "custom_data": {"username": "testuser"},
            },
        }
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.tenants.update_tenant") as mock_update:
                with patch("src.paddle_billing._save_subscription"):
                    from src.paddle_billing import handle_webhook_event
                    result = handle_webhook_event(payload)
                    assert result["status"] == "downgraded"
                    assert result["plan"] == "trial"
                    mock_update.assert_called_once_with("testuser", plan="trial")

    def test_unknown_event_type_is_ignored(self):
        payload = {"event_type": "unknown.event", "data": {}}
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import handle_webhook_event
            result = handle_webhook_event(payload)
            assert result["status"] == "ignored"


class TestSubscriptionManagement:
    def test_get_subscription_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "id": "sub_123",
                "status": "active",
                "items": [{"price": {"id": "pri_starter", "unit_price": {"amount": "2900"}}}],
                "currency_code": "USD",
                "created_at": "2025-01-01T00:00:00Z",
                "next_billed_at": "2025-02-01T00:00:00Z",
            }
        }
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.get", return_value=mock_resp):
                from src.paddle_billing import get_subscription
                result = get_subscription("sub_123")
                assert result is not None
                assert result["id"] == "sub_123"
                assert result["plan"] == "starter"

    def test_cancel_subscription_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", return_value=mock_resp):
                from src.paddle_billing import cancel_subscription
                assert cancel_subscription("sub_123") is True

    def test_cancel_subscription_no_api_key(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_API_KEY="")):
            from src.paddle_billing import cancel_subscription
            assert cancel_subscription("sub_123") is False

    def test_update_subscription_plan_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.patch", return_value=mock_resp):
                from src.paddle_billing import update_subscription_plan
                assert update_subscription_plan("sub_123", "business") is True

    def test_update_subscription_plan_no_price_id(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import update_subscription_plan
            assert update_subscription_plan("sub_123", "nonexistent") is False

    def test_resume_subscription_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", return_value=mock_resp):
                from src.paddle_billing import resume_subscription
                assert resume_subscription("sub_123") is True

    def test_pause_subscription_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", return_value=mock_resp):
                from src.paddle_billing import pause_subscription
                assert pause_subscription("sub_123") is True


class TestCustomerPortal:
    def test_portal_url_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"urls": {"general": {"overview": "https://portal.paddle.com/123"}}}}
        with patch("src.paddle_billing.ENV", _make_env()):
            with patch("src.paddle_billing.post", return_value=mock_resp):
                from src.paddle_billing import get_customer_portal_url
                result = get_customer_portal_url("cus_123")
                assert result == "https://portal.paddle.com/123"

    def test_portal_url_no_api_key(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_API_KEY="")):
            from src.paddle_billing import get_customer_portal_url
            assert get_customer_portal_url("cus_123") is None

    def test_portal_url_no_customer_id(self):
        with patch("src.paddle_billing.ENV", _make_env()):
            from src.paddle_billing import get_customer_portal_url
            assert get_customer_portal_url("") is None


class TestApiBase:
    def test_sandbox_url(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_ENVIRONMENT="sandbox")):
            from src.paddle_billing import _api_base
            assert "sandbox" in _api_base()

    def test_production_url(self):
        with patch("src.paddle_billing.ENV", _make_env(PADDLE_ENVIRONMENT="production")):
            from src.paddle_billing import _api_base
            assert "sandbox" not in _api_base()
            assert "api.paddle.com" in _api_base()
