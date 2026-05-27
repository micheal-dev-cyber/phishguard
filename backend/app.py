"""
PhishGuard AI — Legacy Flask API (deprecated)

This server is superseded by `api_gateway/main.py` (FastAPI) which provides
full key auth, rate limiting, and enterprise features.

Kept for backward compatibility with existing integrations.
Consider migrating to: uvicorn api_gateway.main:app --port 8080
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from flask import Flask, request, jsonify
from flask_cors import CORS
from src.detector import analyze_email
from src.database import save_analysis

app = Flask(__name__)
CORS(app)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data or not data.get("text", "").strip():
        return jsonify({"error": "Missing 'text' field"}), 400

    text = data["text"][:10000]
    results = analyze_email(text)
    save_analysis(results, text)
    return jsonify(results)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "phishguard-legacy-api"})


@app.route("/")
def index():
    return jsonify({
        "service": "PhishGuard AI — Legacy API",
        "endpoints": {
            "POST /analyze": "Analyse text for phishing indicators",
            "GET /health": "Health check",
        },
        "note": "Superseded by api_gateway/main.py (FastAPI)",
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
