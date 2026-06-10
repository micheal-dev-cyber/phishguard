"""Tests for Gumroad webhook processing and ASGI endpoint."""

import hmac
import hashlib
import json
from unittest.mock import patch, MagicMock

import pytest

from src.env import EnvConfig
from src.billing.gumroad import GumroadProvider
from src.billing.service import BillingService
from src.billing.webhook_handler import handle_gumroad_webhook, gumroad_webhook_app


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


def _sign_body(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def provider():
    with patch("src.billing.gumroad.ENV", _make_env()):
        yield GumroadProvider()


@pytest.fixture
def service(provider):
    return BillingService(provider)


class TestWebhookHandlers:
    def test_sale_created_activates_user(self, service):
        with patch("src.billing.service._save_subscription") as mock_save:
            with patch.object(service, "_update_tenant_plan") as mock_update:
                data = {
                    "id": "sale_1",
                    "email": "user@test.com",
                    "product_name": "Starter Monthly",
                    "recurrence": "monthly",
                    "subscription_id": "sub_abc",
                    "custom_fields": {"username": "alice"},
                }
                result = service._handle_sale_created(data)
                assert result["status"] == "created"
                assert result["username"] == "alice"
                assert result["plan"] == "starter"
                mock_save.assert_called_once()
                mock_update.assert_called_once_with("alice", "starter")

    def test_sale_created_unknown_product(self, service):
        data = {
            "id": "sale_2",
            "email": "u@t.com",
            "product_name": "Unknown Product",
            "recurrence": "monthly",
        }
        result = service._handle_sale_created(data)
        assert result["status"] == "ignored"

    def test_sale_created_username_from_email(self, service):
        with patch("src.billing.service._save_subscription"):
            with patch.object(service, "_update_tenant_plan"):
                data = {
                    "id": "sale_3",
                    "email": "john.doe@test.com",
                    "product_name": "Business Yearly",
                    "recurrence": "yearly",
                    "subscription_id": "sub_xyz",
                }
                result = service._handle_sale_created(data)
                assert result["username"] == "john.doe"

    def test_subscription_cancelled(self, service):
        with patch.object(service, "_username_from_subscription", return_value="alice"):
            with patch("src.billing.service._load_subscription") as mock_load:
                mock_load.return_value = None
                with patch("src.billing.service._save_subscription") as mock_save:
                    data = {"subscription_id": "sub_abc"}
                    result = service._handle_subscription_cancelled(data)
                    assert result["status"] == "cancelled"
                    assert result["username"] == "alice"
                    mock_save.assert_called_once()

    def test_subscription_ended_downgrades_to_free(self, service):
        with patch.object(service, "_username_from_subscription", return_value="bob"):
            with patch("src.billing.service._save_subscription") as mock_save:
                with patch.object(service, "_update_tenant_plan") as mock_update:
                    data = {"subscription_id": "sub_xyz"}
                    result = service._handle_subscription_ended(data)
                    assert result["status"] == "expired"
                    assert result["username"] == "bob"
                    assert result["plan"] == "free"
                    mock_update.assert_called_once_with("bob", "free")

    def test_subscription_updated_upgrade(self, service):
        with patch.object(service, "_username_from_subscription", return_value="charlie"):
            with patch("src.billing.service._load_subscription") as mock_load:
                from src.billing.models import Subscription
                mock_load.return_value = Subscription(
                    username="charlie", plan_name="starter", status="active",
                    billing_cycle="monthly", billing_provider="gumroad",
                    provider_subscription_id="sub_old",
                )
                with patch("src.billing.service._save_subscription"):
                    with patch.object(service, "_update_tenant_plan"):
                        data = {
                            "subscription_id": "sub_new",
                            "product_name": "Business Monthly",
                            "recurrence": "monthly",
                        }
                        result = service._handle_subscription_updated(data)
                        assert result["status"] == "upgraded"
                        assert result["plan"] == "business"

    def test_subscription_updated_unknown_user(self, service):
        with patch.object(service, "_username_from_subscription", return_value=""):
            data = {"subscription_id": "sub_unknown", "product_name": "Starter Monthly"}
            result = service._handle_subscription_updated(data)
            assert result["status"] == "no_action"

    def test_refund_created(self, service):
        with patch.object(service, "_username_from_sale", return_value="dave"):
            with patch("src.billing.service._save_subscription"):
                with patch.object(service, "_update_tenant_plan"):
                    data = {"sale_id": "sale_refund"}
                    result = service._handle_refund_created(data)
                    assert result["status"] == "refunded"
                    assert result["username"] == "dave"

    def test_sale_created_missing_data_uses_defaults(self, service):
        data = {}
        result = service._handle_sale_created(data)
        assert result["status"] == "ignored"


class TestProcessWebhook:
    def test_valid_webhook_processes_sale_created(self, service):
        payload = {
            "type": "sale.created",
            "data": {
                "id": "sale_wh",
                "email": "wh@test.com",
                "product_name": "Starter Monthly",
                "recurrence": "monthly",
                "subscription_id": "sub_wh",
            },
        }
        body = json.dumps(payload).encode()
        sig = _sign_body("test_ws", body)
        with patch("src.billing.service._save_subscription"):
            with patch.object(service, "_update_tenant_plan"):
                result = service.process_webhook(body, {"X-Gumroad-Signature": sig})
                assert result["status"] in ("created",)

    def test_invalid_body_ignored(self, service):
        body = json.dumps({"type": "sale.created", "data": {}}).encode()
        result = service.process_webhook(body, {})
        assert result["status"] == "ignored"

    def test_invalid_json_rejected(self, service):
        body = b"not json"
        sig = _sign_body("test_ws", body)
        result = service.process_webhook(body, {"X-Gumroad-Signature": sig})
        assert result["status"] == "rejected"

    def test_unknown_event_type_ignored(self, service):
        payload = {"type": "ping", "data": {}}
        body = json.dumps(payload).encode()
        sig = _sign_body("test_ws", body)
        result = service.process_webhook(body, {"X-Gumroad-Signature": sig})
        assert result["status"] == "ignored"

    def test_webhook_handler_error_on_empty_data(self, service):
        payload = {"type": "sale.created", "data": {}}
        body = json.dumps(payload).encode()
        sig = _sign_body("test_ws", body)
        result = service.process_webhook(body, {"X-Gumroad-Signature": sig})
        assert result["status"] == "ignored"


class TestWebhookASGIApp:
    @pytest.mark.asyncio
    async def test_get_method_returns_405(self):
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                assert message["status"] == 405

        scope = {"method": "GET", "headers": []}
        await gumroad_webhook_app(scope, receive, send)

    @pytest.mark.asyncio
    async def test_post_without_config_returns_503(self):
        scope = {"method": "POST", "headers": []}
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message):
            sent.append(message)

        with patch("src.billing.gumroad.is_gumroad_configured", return_value=False):
            await gumroad_webhook_app(scope, receive, send)

        assert sent[0]["status"] == 503

    @pytest.mark.asyncio
    async def test_post_valid_webhook(self):
        payload = {
            "type": "sale.created",
            "data": {"id": "s_1", "email": "a@b.com", "product_name": "Starter Monthly", "recurrence": "m"},
        }
        body = json.dumps(payload).encode()
        sig = _sign_body("test_ws", body)
        scope = {
            "method": "POST",
            "headers": [
                (b"x-gumroad-signature", sig.encode()),
            ],
        }
        sent = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        with patch("src.billing.gumroad.is_gumroad_configured", return_value=True):
            with patch("src.billing.service._save_subscription"):
                with patch("src.billing.service.BillingService._update_tenant_plan"):
                    await gumroad_webhook_app(scope, receive, send)

        assert sent[0]["status"] == 200
