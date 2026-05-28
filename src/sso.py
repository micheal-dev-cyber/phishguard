"""SSO / OIDC — Okta, Azure AD, Google Workspace login."""

import json
import base64
import time
import logging
from urllib.parse import urlencode, parse_qs
from urllib.request import Request, urlopen
from typing import Optional

logger = logging.getLogger("sso")


class SSOConfig:
    def __init__(self):
        from src.env import ENV
        self.client_id = ENV.OAUTH_CLIENT_ID or ""
        self.client_secret = ENV.OAUTH_CLIENT_SECRET or ""
        self.authority = ENV.OAUTH_AUTHORITY or "https://login.microsoftonline.com/common"
        self.redirect_uri = ENV.OAUTH_REDIRECT_URI or ""
        self._provider = None

    @property
    def provider(self) -> str:
        if self._provider:
            return self._provider
        if "microsoft" in self.authority or "login.live" in self.authority:
            self._provider = "azure"
        elif "okta" in self.authority:
            self._provider = "okta"
        elif "google" in self.authority or "accounts.google" in self.authority:
            self._provider = "google"
        else:
            self._provider = "oidc"
        return self._provider

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret and self.redirect_uri)

    @property
    def authorize_url(self) -> str:
        base = {
            "azure": f"{self.authority}/oauth2/v2.0/authorize",
            "okta": f"{self.authority}/v1/authorize",
            "google": "https://accounts.google.com/o/oauth2/v2/auth",
        }.get(self.provider, f"{self.authority}/authorize")
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid email profile",
            "state": str(int(time.time())),
        }
        return f"{base}?{urlencode(params)}"

    def exchange_code(self, code: str) -> Optional[dict]:
        token_url = {
            "azure": f"{self.authority}/oauth2/v2.0/token",
            "okta": f"{self.authority}/v1/token",
            "google": "https://oauth2.googleapis.com/token",
        }.get(self.provider, f"{self.authority}/token")
        data = urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }).encode()
        req = Request(token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            resp = urlopen(req, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            logger.error("SSO token exchange failed: %s", e)
            return None

    def get_user_info(self, access_token: str) -> Optional[dict]:
        userinfo_url = {
            "azure": "https://graph.microsoft.com/v1.0/me",
            "okta": f"{self.authority}/v1/userinfo",
            "google": "https://www.googleapis.com/oauth2/v3/userinfo",
        }.get(self.provider, f"{self.authority}/userinfo")
        req = Request(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
        try:
            resp = urlopen(req, timeout=10)
            data = json.loads(resp.read())
            email = data.get("mail") or data.get("email") or data.get("userPrincipalName") or ""
            name = data.get("displayName") or data.get("name") or email.split("@")[0]
            return {"email": email, "name": name, "provider": self.provider, "raw": data}
        except Exception as e:
            logger.error("SSO userinfo failed: %s", e)
            return None


class SSOManager:
    def __init__(self):
        self.config = SSOConfig()

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def get_login_button_html(self) -> str:
        if not self.enabled:
            return ""
        provider_labels = {"azure": "Microsoft", "okta": "Okta", "google": "Google", "oidc": "SSO"}
        label = provider_labels.get(self.config.provider, "Enterprise SSO")
        return (
            f'<a href="{self.config.authorize_url}" '
            f'style="display:block;text-align:center;padding:12px;margin-top:12px;'
            f'background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);'
            f'border-radius:10px;color:#e2e8f0;text-decoration:none;font-weight:600;'
            f'font-size:14px">🔐 Sign in with {label}</a>'
        )

    def handle_callback(self, code: str) -> Optional[dict]:
        tokens = self.config.exchange_code(code)
        if not tokens:
            return None
        access_token = tokens.get("access_token")
        if not access_token:
            return None
        return self.config.get_user_info(access_token)
