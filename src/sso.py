"""SSO / OIDC — Okta, Azure AD, Google Workspace, GitHub login."""

import json
import logging
import os
import secrets
import time
from typing import Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("sso")


class SSOConfig:
    def __init__(self):
        from src.env import ENV
        self.client_id = ENV.OAUTH_CLIENT_ID or os.getenv("OAUTH_CLIENT_ID", "")
        self.client_secret = ENV.OAUTH_CLIENT_SECRET or os.getenv("OAUTH_CLIENT_SECRET", "")
        self.authority = ENV.OAUTH_AUTHORITY or os.getenv("OAUTH_AUTHORITY", "https://login.microsoftonline.com/common")
        self.redirect_uri = ENV.OAUTH_REDIRECT_URI or os.getenv("OAUTH_REDIRECT_URI", "")
        self.github_client_id = os.getenv("GITHUB_CLIENT_ID", "")
        self.github_client_secret = os.getenv("GITHUB_CLIENT_SECRET", "")
        self._provider = None

    @property
    def provider(self) -> str:
        if self._provider:
            return self._provider
        auth = self.authority.lower()
        if "microsoft" in auth or "login.live" in auth:
            self._provider = "azure"
        elif "okta" in auth:
            self._provider = "okta"
        elif "google" in auth or "accounts.google" in auth:
            self._provider = "google"
        else:
            self._provider = "oidc"
        return self._provider

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret and self.redirect_uri) or self.github_enabled

    @property
    def github_enabled(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

    def _generate_state(self) -> str:
        state = secrets.token_urlsafe(32)
        _state_store[state] = time.time()
        return state

    def _verify_state(self, state: str) -> bool:
        ts = _state_store.pop(state, None)
        if ts is None:
            return False
        return (time.time() - ts) < 600

    @property
    def authorize_url(self) -> str:
        state = self._generate_state()
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
            "state": state,
        }
        return f"{base}?{urlencode(params)}"

    @property
    def github_authorize_url(self) -> str:
        state = self._generate_state()
        params = {
            "client_id": self.github_client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"

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

    def exchange_github_code(self, code: str) -> Optional[dict]:
        data = urlencode({
            "client_id": self.github_client_id,
            "client_secret": self.github_client_secret,
            "code": code,
        }).encode()
        req = Request("https://github.com/login/oauth/access_token", data=data,
                      headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"})
        try:
            resp = urlopen(req, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            logger.error("GitHub token exchange failed: %s", e)
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

    def get_github_user_info(self, access_token: str) -> Optional[dict]:
        req = Request("https://api.github.com/user", headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "PhishGuard",
        })
        try:
            resp = urlopen(req, timeout=10)
            data = json.loads(resp.read())
            email = data.get("email", "")
            if not email:
                email_req = Request("https://api.github.com/user/emails", headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "User-Agent": "PhishGuard",
                })
                email_resp = urlopen(email_req, timeout=10)
                emails = json.loads(email_resp.read())
                for e in emails:
                    if e.get("primary") and e.get("verified"):
                        email = e["email"]
                        break
                if not email and emails:
                    email = emails[0].get("email", "")
            name = data.get("name") or data.get("login") or email.split("@")[0]
            return {"email": email, "name": name, "provider": "github", "raw": data}
        except Exception as e:
            logger.error("GitHub userinfo failed: %s", e)
            return None


class SSOManager:
    def __init__(self):
        self.config = SSOConfig()

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def get_login_buttons_html(self) -> str:
        buttons = ""
        if self.config.enabled:
            provider_labels = {"azure": "Microsoft", "okta": "Okta", "google": "Google", "oidc": "SSO"}
            label = provider_labels.get(self.config.provider, "Enterprise SSO")
            buttons += (
                f'<a href="{self.config.authorize_url}" '
                f'style="display:block;text-align:center;padding:10px;margin:6px 0;'
                f'background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);'
                f'border-radius:8px;color:#e2e8f0;text-decoration:none;font-weight:600;'
                f'font-size:13px">🔐 Sign in with {label}</a>'
            )
        if self.config.github_enabled:
            buttons += (
                f'<a href="{self.config.github_authorize_url}" '
                f'style="display:block;text-align:center;padding:10px;margin:6px 0;'
                f'background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);'
                f'border-radius:8px;color:#e2e8f0;text-decoration:none;font-weight:600;'
                f'font-size:13px">🐙 Sign in with GitHub</a>'
            )
        return buttons

    def handle_callback(self, code: str, state: str = "") -> Optional[dict]:
        if state and not self.config._verify_state(state):
            logger.warning("SSO state mismatch — possible CSRF")
            return None
        if self.config.github_enabled:
            tokens = self.config.exchange_github_code(code)
            if tokens and tokens.get("access_token"):
                return self.config.get_github_user_info(tokens["access_token"])
        tokens = self.config.exchange_code(code)
        if not tokens:
            return None
        access_token = tokens.get("access_token")
        if not access_token:
            return None
        return self.config.get_user_info(access_token)


_state_store: dict = {}
