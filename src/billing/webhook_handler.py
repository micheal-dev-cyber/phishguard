# src/billing/webhook_handler.py
"""
FastAPI/Starlette-compatible webhook endpoint for Gumroad.
Mounted at /webhooks/gumroad in production.
"""
import json
import logging

from src.billing.service import BillingService

logger = logging.getLogger(__name__)


def handle_gumroad_webhook(service: BillingService, body: bytes, headers: dict) -> dict:
    """Entry point for Gumroad webhook HTTP requests.

    Args:
        service: Initialized BillingService with GumroadProvider.
        body: Raw request body bytes.
        headers: Request headers dict (case-sensitive keys).

    Returns:
        dict: Processing result with status and details.
    """
    return service.process_webhook(body, headers)


# ASGI / Starlette application factory
async def gumroad_webhook_app(scope, receive, send):
    """Minimal ASGI app for Gumroad webhooks. Mount at /webhooks/gumroad."""
    if scope["method"] != "POST":
        await send({"type": "http.response.start", "status": 405})
        await send({"type": "http.response.body", "body": b"Method not allowed"})
        return

    from src.billing.gumroad import GumroadProvider, is_gumroad_configured

    if not is_gumroad_configured():
        await send({"type": "http.response.start", "status": 503})
        await send({"type": "http.response.body", "body": b"Billing not configured"})
        return

    body = b""
    more_body = True
    while more_body:
        message = await receive()
        body += message.get("body", b"")
        more_body = message.get("more_body", False)

    headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}

    provider = GumroadProvider()
    service = BillingService(provider)
    result = handle_gumroad_webhook(service, body, headers)

    resp_body = json.dumps(result).encode()
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": resp_body})
