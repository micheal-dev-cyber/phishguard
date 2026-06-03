import hashlib
import hmac
import ipaddress
import json
import time
from urllib.parse import urlparse

import streamlit as st

from src.env import ENV


def _is_safe_url(url: str) -> bool:
    """Block requests to internal/private IPs to prevent SSRF."""
    if not url:
        return True
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
    except ValueError:
        pass
    return True


def render_webhook_tester_tab():
    st.markdown("#### 🔌 Webhook Tester & Event Replay")
    st.caption("Send sample webhook events to test integrations without external services.")

    event_type = st.selectbox("Event type", [
        "Paddle — subscription_created",
        "Paddle — subscription_updated",
        "Paddle — subscription_cancelled",
        "Paddle — transaction_completed",
        "Generic — scan_complete",
        "Generic — alert_triggered",
        "Custom JSON",
    ], key="wht_event")

    st.divider()

    payloads = {
        "Paddle — subscription_created": {
            "event_id": "evt_sample_sub_created",
            "event_type": "subscription.created",
            "data": {
                "id": "sub_01h2x3example",
                "status": "active",
                "customer_id": "cus_01h2x3example",
                "items": [{"price": {"product_id": "pro_01h2x3example"}}],
            },
        },
        "Paddle — subscription_updated": {
            "event_id": "evt_sample_sub_updated",
            "event_type": "subscription.updated",
            "data": {
                "id": "sub_01h2x3example",
                "status": "paused",
                "scheduled_change": {"effective_at": "2026-06-15T00:00:00Z"},
            },
        },
        "Paddle — subscription_cancelled": {
            "event_id": "evt_sample_sub_cancelled",
            "event_type": "subscription.cancelled",
            "data": {
                "id": "sub_01h2x3example",
                "status": "canceled",
                "canceled_at": "2026-05-28T12:00:00Z",
            },
        },
        "Paddle — transaction_completed": {
            "event_id": "evt_sample_tx_completed",
            "event_type": "transaction.completed",
            "data": {
                "id": "txn_01h2x3example",
                "status": "completed",
                "customer_id": "cus_01h2x3example",
                "currency_code": "USD",
                "total": "29.99",
            },
        },
        "Generic — scan_complete": {
            "event": "scan_complete",
            "risk_score": 72,
            "severity": "HIGH",
            "total_keyword_hits": 4,
            "suspicious_url_count": 2,
            "is_phishing": True,
            "email_preview": "Your account has been compromised...",
        },
        "Generic — alert_triggered": {
            "event": "alert_triggered",
            "severity": "CRITICAL",
            "message": "Phishing campaign detected targeting payroll department",
            "threat_count": 12,
            "suggested_action": "Block all suspicious senders immediately",
        },
    }

    if event_type == "Custom JSON":
        payload_str = st.text_area("JSON payload", "{\n  \"event\": \"custom\",\n  \"data\": {}\n}",
                                   height=200, key="wht_custom_json")
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            st.error("Invalid JSON")
            payload = None
    else:
        payload = payloads.get(event_type, {})
        payload_str = json.dumps(payload, indent=2)
        st.code(payload_str, language="json")

    col_a, col_b = st.columns(2)
    with col_a:
        target_endpoint = st.text_input("Target URL (optional, leave empty for local)",
                                        value="http://localhost:8080/webhook",
                                        key="wht_target")
    with col_b:
        include_signature = st.checkbox("Include Paddle-Signature header", value=True,
                                        key="wht_sig")

    if st.button("🚀 Send Test Event", type="primary", use_container_width=True):
        if not payload:
            st.error("No valid payload to send.")
            st.stop()
        import requests
        headers = {"Content-Type": "application/json"}
        if include_signature:
            secret = ENV.PADDLE_WEBHOOK_SECRET or "test_secret"
            ts = str(int(time.time()))
            to_sign = ts + "." + json.dumps(payload, separators=(",", ":"))
            sig = hmac.new(secret.encode(), to_sign.encode(), hashlib.sha256).hexdigest()
            headers["Paddle-Signature"] = f"ts={ts};h1={sig}"

        if not _is_safe_url(target_endpoint):
            st.error("❌ Target URL resolves to an internal/private address. Blocked for security.")
            st.stop()

        try:
            resp = requests.post(target_endpoint, json=payload, headers=headers, timeout=10)
            st.markdown(f"**Status:** {resp.status_code}")
            st.markdown("**Response:**")
            try:
                st.json(resp.json())
            except Exception:
                st.code(resp.text)
        except requests.RequestException as e:
            st.error(f"Request failed: {e}")
