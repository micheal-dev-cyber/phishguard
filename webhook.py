# webhook.py
"""
Standalone Paddle webhook receiver.

Designed to be deployed as a separate service (Render, Railway, etc.)
since Streamlit Cloud does not expose a persistent HTTP server.

Usage:
    pip install flask
    export PADDLE_API_KEY=...
    export PADDLE_WEBHOOK_SECRET=...
    python webhook.py

Or via environment variables / .env file.
"""

import json
import logging
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs

# Ensure the project root is on sys.path so we can import src.*
sys.path.insert(0, str(Path(__file__).parent.resolve()))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phishguard-webhook")

# ── Paddle imports ─────────────────────────────────────────────────────────
try:
    from flask import Flask, jsonify, request
except ImportError:
    print("Flask is required. Install with: pip install flask")
    sys.exit(1)

try:
    from src.paddle_billing import handle_webhook_event, verify_webhook_signature
except ImportError as e:
    print(f"Could not import Paddle billing module: {e}")
    sys.exit(1)

# ── Gumroad imports (optional — gracefully degrade if billing module missing) ─
try:
    from src.billing.gumroad import GumroadProvider, is_gumroad_configured
    from src.billing.service import BillingService
    _gumroad_available = True
except ImportError:
    _gumroad_available = False

try:
    from src.detector import analyze_email
except ImportError:
    analyze_email = None

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    """Receive Paddle webhook events."""
    signature = request.headers.get("Paddle-Signature", "")
    body = request.get_data()

    if not signature:
        logger.warning("Missing Paddle-Signature header")
        return jsonify({"error": "Missing signature"}), 401

    if not verify_webhook_signature(body, signature):
        logger.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 401

    try:
        payload = request.get_json(force=True)
    except Exception:
        logger.error("Invalid JSON body")
        return jsonify({"error": "Invalid JSON"}), 400

    event_type = payload.get("event_type", "unknown")
    logger.info(f"Received event: {event_type}")

    try:
        result = handle_webhook_event(payload)
        logger.info(f"Handled {event_type}: {result}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error handling {event_type}: {e}")
        return jsonify({"error": str(e)}), 500


# ── Gumroad Webhook ──────────────────────────────────────────────────────
@app.route("/webhooks/gumroad", methods=["POST"])
def gumroad_webhook():
    """Receive Gumroad subscription events (JSON or form-encoded)."""
    if not _gumroad_available:
        return jsonify({"error": "Gumroad billing module not available"}), 500
    if not is_gumroad_configured():
        return jsonify({"error": "Gumroad not configured"}), 503

    # Handle both JSON (Resource Subscriptions) and form-encoded (Ping URL)
    content_type = request.content_type or ""
    if "application/json" in content_type:
        body = request.get_data()
    else:
        raw = dict(request.form)
        payload = {}
        # Normalize Ping URL field names to match Resource Subs format
        field_map = {"sale_id": "id", "subscription_id": "subscription_id"}
        for k, v in raw.items():
            key = field_map.get(k, k)
            payload[key] = v[0] if isinstance(v, (list, tuple)) else v
        body = json.dumps(payload).encode("utf-8")

    headers = {k: v for k, v in request.headers.items()}

    provider = GumroadProvider()
    service = BillingService(provider)
    result = service.process_webhook(body, headers)

    logger.info(f"Gumroad webhook result: {result}")
    return jsonify(result), 200


# ── Paddle Webhook (legacy) ──────────────────────────────────────────────
@app.route("/webhook", methods=["POST"])


@app.route("/analyze", methods=["POST"])
def analyze():
    """API endpoint for the browser extension to scan email/page text."""
    if analyze_email is None:
        return jsonify({"error": "Detection engine unavailable"}), 500

    data = request.get_json(force=True, silent=True)
    if not data or not data.get("text", "").strip():
        return jsonify({"error": "Missing 'text' field"}), 400

    text = data["text"][:10000]
    try:
        results = analyze_email(text)
        return jsonify({
            "risk_score": results.get("risk_score", 0),
            "severity": results.get("severity", "LOW"),
            "total_keyword_hits": results.get("total_keyword_hits", 0),
            "url_count": results.get("url_count", 0),
            "suspicious_url_count": results.get("suspicious_url_count", 0),
            "urgency": [],
            "threats": [],
            "requests": [],
            "impersonation": [],
            "suspicious_urls": [u["url"] for u in results.get("suspicious_urls", [])],
        })
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({"error": "Analysis failed", "status": "error"}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "paddle-webhook"})


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "PhishGuard Webhook Server",
        "endpoints": {
            "POST /webhooks/gumroad": "Receive Gumroad subscription events",
            "POST /webhook": "Receive Paddle subscription events (legacy)",
            "POST /analyze": "Scan email/page text for threats",
            "POST /analyze": "Scan email/page text for threats",
            "POST /scan-webhook": "Receive forwarded email via webhook, scan, reply with verdict",
            "POST /api/v1/scim/Users": "SCIM 2.0 — Create user",
            "GET /api/v1/scim/Users": "SCIM 2.0 — List users",
            "GET /api/v1/scim/Users/:id": "SCIM 2.0 — Get user",
            "DELETE /api/v1/scim/Users/:id": "SCIM 2.0 — Deactivate user",
            "GET /health": "Health check",
        }
    })


@app.route("/api/v1/scim/Users", methods=["GET", "POST"])
@app.route("/api/v1/scim/Users/<int:user_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
def scim_users(user_id=None):
    """SCIM 2.0 provisioning endpoint."""
    from src.scim import handle_scim_request
    body = request.get_json(force=True, silent=True) if request.method in ("POST", "PUT", "PATCH") else None
    path = request.path
    result = handle_scim_request(request.method, path, body)
    status = 200
    if "status" in result:
        status = int(result["status"])
    elif request.method == "POST":
        status = 201
    elif request.method == "DELETE":
        status = 204
        return "", 204
    return jsonify(result), status


@app.route("/scan-webhook", methods=["POST"])
def scan_webhook():
    """Receive a forwarded email via webhook, scan it, and optionally email back the verdict."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    email_text = data.get("email_text", data.get("text", ""))
    sender = data.get("sender", "")
    recipient = data.get("recipient", "")
    reply_to = data.get("reply_to", recipient)

    if not email_text:
        return jsonify({"error": "Missing 'email_text' or 'text' field"}), 400

    try:
        from src.alerting import send_email
        from src.detector import analyze_email
        from src.env import ENV

        results = analyze_email(email_text[:20000])
        verdict = {
            "risk_score": results.get("risk_score", 0),
            "severity": results.get("severity", "LOW"),
            "total_keyword_hits": results.get("total_keyword_hits", 0),
            "suspicious_urls": [u["url"] for u in results.get("suspicious_urls", [])],
            "is_phishing": results.get("risk_score", 0) >= 50,
        }

        # Auto-reply with verdict if recipient is configured
        if reply_to and verdict["is_phishing"]:
            smtp_host = ENV.SMTP_HOST
            smtp_port = ENV.SMTP_PORT
            smtp_user = ENV.SMTP_USER
            smtp_pass = ENV.SMTP_PASS
            if smtp_user and smtp_pass:
                subject = f"🔍 PhishGuard Scan Result — {verdict['severity']} ({verdict['risk_score']}/100)"
                body = (
                    f"PhishGuard scanned a forwarded email from {sender or 'unknown'}.\n\n"
                    f"Risk Score: {verdict['risk_score']}/100\n"
                    f"Severity: {verdict['severity']}\n"
                    f"Keyword Hits: {verdict['total_keyword_hits']}\n"
                    f"Suspicious URLs: {len(verdict['suspicious_urls'])}\n\n"
                    f"Verdict: {'⚠️ PHISHING DETECTED' if verdict['is_phishing'] else '✅ No phishing indicators'}\n\n"
                    f"Full details: {ENV.APP_URL or 'http://localhost:8501'}\n"
                )
                send_email(smtp_host, smtp_port, smtp_user, smtp_pass,
                           smtp_user, reply_to, subject, body)
                verdict["reply_sent"] = True

        logger.info("Scan-webhook processed for %s → score %s", sender or "unknown", verdict["risk_score"])
        return jsonify(verdict), 200

    except Exception as e:
        logger.error("Scan-webhook error: %s", e)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    logger.info(f"Starting Paddle webhook server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
