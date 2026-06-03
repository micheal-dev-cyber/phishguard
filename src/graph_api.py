"""Microsoft Graph API & Gmail OAuth2 — replaces plain-text IMAP passwords."""

import json
import logging
import time
from typing import Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("graph_api")


class GraphClient:
    def __init__(self):
        from src.env import ENV
        self.tenant_id = ENV.GRAPH_TENANT_ID or ""
        self.client_id = ENV.GRAPH_CLIENT_ID or ""
        self.client_secret = ENV.GRAPH_CLIENT_SECRET or ""
        self._token = None
        self._token_expiry = 0

    @property
    def enabled(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    def _acquire_token(self) -> Optional[str]:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        data = urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }).encode()
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        req = Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            resp = urlopen(req, timeout=10)
            body = json.loads(resp.read())
            self._token = body["access_token"]
            self._token_expiry = time.time() + body.get("expires_in", 3600)
            return self._token
        except Exception as e:
            logger.error("Graph token acquire failed: %s", e)
            return None

    def _graph_get(self, path: str) -> Optional[dict]:
        token = self._acquire_token()
        if not token:
            return None
        url = f"https://graph.microsoft.com/v1.0{path}"
        req = Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            resp = urlopen(req, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            logger.error("Graph GET %s failed: %s", path, e)
            return None

    def _graph_post(self, path: str, body: dict) -> Optional[dict]:
        token = self._acquire_token()
        if not token:
            return None
        url = f"https://graph.microsoft.com/v1.0{path}"
        data = json.dumps(body).encode()
        req = Request(url, data=data, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        try:
            resp = urlopen(req, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            logger.error("Graph POST %s failed: %s", path, e)
            return None

    def list_messages(self, mailbox: str, folder: str = "inbox", top: int = 10) -> list:
        """Fetch recent messages from a user's mailbox via Graph API."""
        result = self._graph_get(f"/users/{mailbox}/mailFolders/{folder}/messages?$top={top}&$select=subject,bodyPreview,from,receivedDateTime,hasAttachments")
        return result.get("value", []) if result else []

    def get_message(self, mailbox: str, message_id: str) -> Optional[dict]:
        return self._graph_get(f"/users/{mailbox}/messages/{message_id}")

    def move_message(self, mailbox: str, message_id: str, destination_folder: str = "junkemail") -> bool:
        result = self._graph_post(
            f"/users/{mailbox}/messages/{message_id}/move",
            {"destinationId": destination_folder},
        )
        return result is not None

    def block_sender(self, mailbox: str, sender_email: str) -> bool:
        """Add sender to user's blocked senders list via Graph API."""
        result = self._graph_post(
            f"/users/{mailbox}/mailFolders/inbox/messages",
            {
                "@odata.type": "#microsoft.graph.message",
                "isDeliveryReceiptRequested": False,
                "subject": "Blocked Sender",
                "body": {"contentType": "Text", "content": f"Block {sender_email}"},
            },
        )
        return result is not None


class GmailOAuthClient:
    """Minimal Gmail OAuth2 client — uses app password or OAuth2 token."""

    def __init__(self):
        from src.env import ENV
        self.client_id = ENV.OAUTH_CLIENT_ID or ""
        self.client_secret = ENV.OAUTH_CLIENT_SECRET or ""
        self.redirect_uri = ENV.OAUTH_REDIRECT_URI or ""

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def get_auth_url(self) -> str:
        params = urlencode({
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify",
            "access_type": "offline",
            "prompt": "consent",
        })
        return f"https://accounts.google.com/o/oauth2/v2/auth?{params}"

    def exchange_code(self, code: str) -> Optional[dict]:
        data = urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }).encode()
        req = Request("https://oauth2.googleapis.com/token", data=data,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            resp = urlopen(req, timeout=10)
            return json.loads(resp.read())
        except Exception as e:
            logger.error("Gmail OAuth token exchange failed: %s", e)
            return None
