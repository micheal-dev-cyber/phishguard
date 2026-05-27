"""
PhishGuard AI — Zero-dependency API Proxy for Chrome Extension

A minimal HTTP server (stdlib only — no Flask/FastAPI) that the Chrome
extension can call for text analysis. Runs alongside the Streamlit app.

Usage:
    # Default (port 8080):
    python api_proxy.py

    # Custom port:
    python api_proxy.py --port 9090

    # With environment:
    DATABASE_URL=phishguard.db python api_proxy.py

The extension's background.js should point to:
    const PHISHGUARD_API = "http://127.0.0.1:8080";
"""

import os
import sys
import json
import argparse
import http.server
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.resolve()))

from src.detector import analyze_email
from src.database import save_analysis


class APIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write("[api_proxy] %s\n" % (format % args))

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return b""
        return self.rfile.read(length)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return self._send_json({
                "status": "ok",
                "service": "phishguard-api-proxy",
                "version": "3.0.0",
            })
        if parsed.path == "/":
            return self._send_json({
                "service": "PhishGuard AI — API Proxy",
                "endpoints": {
                    "POST /api/v1/scan": "Analyse text for phishing indicators",
                    "GET /health": "Health check",
                },
            })
        self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path not in ("/api/v1/scan", "/analyze"):
            return self._send_json({"error": "Not found"}, 404)

        try:
            body = json.loads(self._read_body().decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._send_json({"error": "Invalid JSON"}, 400)

        text = (body.get("text") or "").strip()
        if not text:
            return self._send_json({"error": "Missing 'text' field"}, 400)

        text = text[:10000]
        results = analyze_email(text)
        save_analysis(results, text)

        return self._send_json(results)


def main():
    parser = argparse.ArgumentParser(description="PhishGuard API Proxy")
    parser.add_argument("--port", type=int, default=int(os.getenv("API_PROXY_PORT", "8080")))
    args = parser.parse_args()

    server = http.server.HTTPServer(("127.0.0.1", args.port), APIHandler)
    print(f"[api_proxy] Listening on http://127.0.0.1:{args.port}")
    print(f"[api_proxy] POST /api/v1/scan  → analyze text")
    print(f"[api_proxy] GET  /health       → health check")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[api_proxy] Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
