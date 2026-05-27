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

import os
import sys
import json
import logging
from pathlib import Path

# Ensure the project root is on sys.path so we can import src.*
sys.path.insert(0, str(Path(__file__).parent.resolve()))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("paddle-webhook")

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("Flask is required. Install with: pip install flask")
    sys.exit(1)

try:
    from src.paddle_billing import verify_webhook_signature, handle_webhook_event
except ImportError as e:
    print(f"Could not import Paddle billing module: {e}")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    """Receive Paddle webhook events."""
    signature = request.headers.get("Paddle-Signature", "") or request.headers.get("Paddle-Signature", "")
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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "paddle-webhook"})


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "PhishGuard Paddle Webhook",
        "endpoints": {
            "POST /webhook": "Receive Paddle subscription events",
            "GET /health": "Health check",
        }
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    logger.info(f"Starting Paddle webhook server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
