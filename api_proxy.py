"""
PhishGuard AI — Enterprise API Proxy (stdlib only)

Endpoints:
  POST /api/v1/scan          Multi-layered phishing scan (requires X-PhishGuard-Key)
  POST /api/v1/report-phish  Webhook for Outlook/Gmail add-in (requires X-PhishGuard-Key)
  GET  /health               Health check (no key required)
  GET  /                     Service index

Usage:
  python api_proxy.py                    # default port 8080
  python api_proxy.py --port 9090
"""

import os
import sys
import json
import argparse
import http.server
import logging
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.resolve()))

from src.enterprise_api import handle_scan_request
from src.database import save_analysis

logging.basicConfig(level=logging.INFO, format="[api_proxy] %(message)s")
logger = logging.getLogger("api-proxy")

PROTECTED_ENDPOINTS = {"/api/v1/scan", "/api/v1/report-phish"}


class APIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info(format % args)

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

    def _authenticate(self):
        from src.api_keys import authenticate_request
        auth = authenticate_request(dict(self.headers))
        if not auth["allowed"]:
            self._send_json(
                {"error": auth["error"], "code": auth["status"], "tier": auth.get("tier")},
                status=auth["status"],
            )
            return None
        return auth

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-PhishGuard-Key")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            return self._send_json({
                "status": "ok",
                "service": "phishguard-api-proxy",
                "version": "3.0.0",
            })

        if parsed.path.startswith("/api/v1/campaign/track/open"):
            qs = parse_qs(parsed.query)
            cid = qs.get("cid", [None])[0]
            email = qs.get("email", [None])[0]
            if cid and email:
                from src.campaign_engine import record_open
                record_open(int(cid), email)
                self.send_response(204)
            else:
                self._send_json({"error": "Missing cid or email"}, 400)
            return

        if parsed.path == "/":
            return self._send_json({
                "service": "PhishGuard AI — API Proxy",
                "endpoints": {
                    "POST /api/v1/scan":         "Multi-layered phishing scan (key required)",
                    "POST /api/v1/report-phish":  "Report phish webhook for add-ins (key required)",
                    "GET /health":                "Health check",
                },
            })
        self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path not in PROTECTED_ENDPOINTS and parsed.path != "/analyze":
            return self._send_json({"error": "Not found"}, 404)

        # ── API key authentication for protected endpoints ────────────────
        if parsed.path in PROTECTED_ENDPOINTS:
            auth = self._authenticate()
            if auth is None:
                return

        try:
            body = json.loads(self._read_body().decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._send_json({"error": "Invalid JSON"}, 400)

        # ── POST /api/v1/report-phish (Outlook/Gmail add-in webhook) ─────
        if parsed.path == "/api/v1/report-phish":
            return self._handle_report_phish(body, auth)

        # ── POST /api/v1/scan & /analyze ─────────────────────────────────
        result = handle_scan_request(body)
        if "error" in result:
            return self._send_json(result, 400)

        # Persist to DB
        if result["verdict"].get("risk_score", 0) >= 25:
            text = (body.get("text") or "").strip()[:10000]
            from src.detector import analyze_email
            save_analysis(analyze_email(text), text)

        return self._send_json(result)

    def _handle_report_phish(self, body: dict, auth: dict):
        raw_email = body.get("raw_email", "")
        headers_raw = body.get("headers", "")
        subject = body.get("subject", "")
        sender = body.get("sender", "")
        recipients = body.get("recipients", "")
        reporter = body.get("reporter", auth.get("username", "unknown"))

        text_to_scan = raw_email or body.get("body", "")

        # Run full detection pipeline
        scan_result = handle_scan_request({"text": text_to_scan[:10000]})
        verdict = scan_result.get("verdict", {})
        layers = scan_result.get("layers", {})

        risk_score = verdict.get("risk_score", 0)
        severity = verdict.get("severity", "UNKNOWN")
        ai_prob = verdict.get("ai_written_probability", 0)
        aitm_conf = verdict.get("aitm_confidence", 0)

        # DNA match check
        dna_matched = 0
        if text_to_scan:
            try:
                from src.phishing_dna import flagged_as_known_phishing
                import streamlit as st
                dna_known, _ = flagged_as_known_phishing(text_to_scan, st.session_state)
                dna_matched = 1 if dna_known else 0
            except Exception:
                pass

        # Persist to reported_phish table
        _save_reported_phish(
            reporter_email=reporter,
            raw_headers=headers_raw[:2000] if headers_raw else "",
            raw_body=text_to_scan[:5000],
            subject=subject,
            sender=sender,
            recipients=recipients,
            risk_score=risk_score,
            severity=severity,
            ai_probability=ai_prob,
            aitm_confidence=aitm_conf,
            dna_match=dna_matched,
        )

        return self._send_json({
            "status": "logged",
            "verdict": verdict,
            "layers": {
                "heuristic": layers.get("heuristic"),
                "ai_text_detection": layers.get("ai_text_detection"),
                "aitm_detection": layers.get("aitm_detection"),
            },
            "dna_matched": bool(dna_matched),
        })


def _save_reported_phish(**kwargs):
    import sqlite3
    from pathlib import Path as _Path
    db = _Path(__file__).parent / "data" / "phishguard.db"
    conn = sqlite3.connect(str(db))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS reported_phish (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_email  TEXT NOT NULL,
            raw_headers     TEXT,
            raw_body        TEXT,
            subject         TEXT,
            sender          TEXT,
            recipients      TEXT,
            risk_score      INTEGER DEFAULT 0,
            severity        TEXT DEFAULT 'UNKNOWN',
            ai_probability  REAL DEFAULT 0,
            aitm_confidence INTEGER DEFAULT 0,
            dna_match       INTEGER DEFAULT 0,
            source          TEXT DEFAULT 'webhook',
            reported_at     TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute(
        "INSERT INTO reported_phish (reporter_email, raw_headers, raw_body, subject, sender, "
        "recipients, risk_score, severity, ai_probability, aitm_confidence, dna_match) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (kwargs["reporter_email"], kwargs["raw_headers"], kwargs["raw_body"],
         kwargs["subject"], kwargs["sender"], kwargs["recipients"],
         kwargs["risk_score"], kwargs["severity"], kwargs["ai_probability"],
         kwargs["aitm_confidence"], kwargs["dna_match"]),
    )
    conn.commit()
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="PhishGuard Enterprise API Proxy")
    parser.add_argument("--port", type=int, default=int(os.getenv("API_PROXY_PORT", "8080")))
    args = parser.parse_args()

    server = http.server.HTTPServer(("127.0.0.1", args.port), APIHandler)
    print(f"[api_proxy] PhishGuard Enterprise API — http://127.0.0.1:{args.port}")
    print(f"[api_proxy] POST /api/v1/scan          (X-PhishGuard-Key required)")
    print(f"[api_proxy] POST /api/v1/report-phish   (X-PhishGuard-Key required)")
    print(f"[api_proxy] GET  /health                (no key required)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[api_proxy] Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
