"""Tests for SSO/OIDC — SSOManager provider detection, URL building."""

import pytest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.sso import SSOConfig


class TestSSOConfig:
    def test_disabled_when_no_creds(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_ID", "")
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_SECRET", "")
        monkeypatch.setattr("src.env.ENV.OAUTH_REDIRECT_URI", "")
        cfg = SSOConfig()
        assert cfg.enabled is False

    def test_enabled_when_creds_set(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_ID", "my-client")
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_SECRET", "my-secret")
        monkeypatch.setattr("src.env.ENV.OAUTH_REDIRECT_URI", "https://example.com/cb")
        cfg = SSOConfig()
        assert cfg.enabled is True

    def test_provider_azure(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_AUTHORITY", "https://login.microsoftonline.com/tenant-id")
        assert SSOConfig().provider == "azure"

    def test_provider_google(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_AUTHORITY", "https://accounts.google.com")
        assert SSOConfig().provider == "google"

    def test_provider_okta(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_AUTHORITY", "https://my-org.okta.com")
        assert SSOConfig().provider == "okta"

    def test_provider_fallback_oidc(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_AUTHORITY", "https://auth.example.com")
        assert SSOConfig().provider == "oidc"

    def test_authorize_url_contains_client_id(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_ID", "test-client")
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_SECRET", "secret")
        monkeypatch.setattr("src.env.ENV.OAUTH_REDIRECT_URI", "https://example.com/cb")
        url = SSOConfig().authorize_url
        assert "test-client" in url
        assert "response_type=code" in url

    def test_authorize_url_azure(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_AUTHORITY", "https://login.microsoftonline.com/abc")
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_ID", "cid")
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_SECRET", "sec")
        monkeypatch.setattr("src.env.ENV.OAUTH_REDIRECT_URI", "https://x.com/cb")
        url = SSOConfig().authorize_url
        assert "/oauth2/v2.0/authorize" in url

    def test_authorize_url_google(self, monkeypatch):
        monkeypatch.setattr("src.env.ENV.OAUTH_AUTHORITY", "https://accounts.google.com")
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_ID", "cid")
        monkeypatch.setattr("src.env.ENV.OAUTH_CLIENT_SECRET", "sec")
        monkeypatch.setattr("src.env.ENV.OAUTH_REDIRECT_URI", "https://x.com/cb")
        url = SSOConfig().authorize_url
        assert "accounts.google.com/o/oauth2/v2/auth" in url
