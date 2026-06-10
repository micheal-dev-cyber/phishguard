"""
PhishGuard AI — Enterprise API Proxy (stdlib only)

Endpoints:
  POST /api/v1/scan                Multi-layered phishing scan (key required)
  POST /api/v1/report-phish        Webhook for Outlook/Gmail add-in (key required)
  GET  /api/v1/metrics/summary     Overall platform metrics (no key)
  GET  /api/v1/feedback/stats      Feedback loop FP/FN stats (no key)
  GET  /api/v1/detection/rules     Detection rules listing (no key)
  GET  /api/v1/billing/revenue-summary  Subscription revenue summary (no key)
  POST /api/v1/logs/ingest         Ingest telemetry/event log (no key)
  GET  /api/v1/health/status       Detailed health status (no key)
  GET  /health                     Health check (no key)
  GET  /                           Service index

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
from src.ratelimit import check_rate_limit, get_rate_limit_remaining
from src.json_logger import setup_json_logging

setup_json_logging()

logging.basicConfig(level=logging.INFO, format="[api_proxy] %(message)s")
logger = logging.getLogger("api-proxy")

PROTECTED_ENDPOINTS = {"/api/v1/scan", "/api/v1/report-phish"}
RATE_LIMIT = {"max": 60, "window": 60}  # 60 requests per minute per IP


def _client_ip(handler):
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]


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

        # ── Per-IP rate limiting ─────────────────────────────────────────
        ip = _client_ip(self)
        if not check_rate_limit(f"api:{ip}", RATE_LIMIT["max"], RATE_LIMIT["window"]):
            remaining = get_rate_limit_remaining(f"api:{ip}", RATE_LIMIT["max"], RATE_LIMIT["window"])
            return self._send_json({"error": "rate_limited", "remaining": remaining}, 429)

        if parsed.path == "/health":
            return self._send_json({
                "status": "ok",
                "service": "phishguard-api-proxy",
                "version": "3.0.0",
            })

        if parsed.path == "/api/v1/health/status":
            return self._handle_health_status()

        if parsed.path == "/api/v1/metrics/summary":
            return self._handle_metrics_summary()

        if parsed.path == "/api/v1/feedback/stats":
            return self._handle_feedback_stats()

        if parsed.path == "/api/v1/detection/rules":
            return self._handle_detection_rules()

        if parsed.path == "/api/v1/billing/revenue-summary":
            return self._handle_billing_revenue()

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

        if parsed.path == "/api/v1/openapi.json":
            return self._serve_openapi()

        if parsed.path == "/":
            return self._send_json({
                "service": "PhishGuard AI — API Proxy",
                "endpoints": {
                    "POST /api/v1/scan":                "Multi-layered phishing scan (key required)",
                    "POST /api/v1/report-phish":         "Report phish webhook for add-ins (key required)",
                    "GET /api/v1/metrics/summary":       "Overall platform metrics",
                    "GET /api/v1/feedback/stats":        "Feedback loop FP/FN stats",
                    "GET /api/v1/detection/rules":       "Detection rules listing",
                    "GET /api/v1/billing/revenue-summary": "Subscription revenue summary",
                    "POST /api/v1/logs/ingest":          "Ingest telemetry events",
                    "GET /api/v1/health/status":         "Detailed health status",
                    "GET /api/v1/openapi.json":          "OpenAPI 3.0 specification",
                    "GET /health":                       "Health check",
                },
            })
        self._send_json({"error": "Not found"}, 404)

    def _serve_openapi(self):
        path = Path(__file__).parent / "openapi.yaml"
        if path.exists():
            import yaml
            try:
                spec = yaml.safe_load(path.read_text(encoding="utf-8"))
                return self._send_json(spec)
            except Exception:
                pass
        return self._send_json({"error": "Spec not available"}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)

        # ── Per-IP rate limiting ─────────────────────────────────────────
        ip = _client_ip(self)
        if not check_rate_limit(f"api:{ip}", RATE_LIMIT["max"], RATE_LIMIT["window"]):
            remaining = get_rate_limit_remaining(f"api:{ip}", RATE_LIMIT["max"], RATE_LIMIT["window"])
            return self._send_json({"error": "rate_limited", "remaining": remaining}, 429)

        if parsed.path == "/api/v1/logs/ingest":
            return self._handle_logs_ingest()

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

    def _handle_metrics_summary(self):
        from src.database import get_valuation_summary as _get_val
        from src.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT COUNT(*) as total FROM analyses")
            total_analyses = c.fetchone()["total"]
            c.execute("SELECT COUNT(*) as total FROM tenants")
            total_tenants = c.fetchone()["total"]
            c.execute("SELECT COUNT(*) as total FROM threat_intel")
            total_threats = c.fetchone()["total"]
            c.execute("SELECT COUNT(*) as total FROM reported_phish")
            total_reported = c.fetchone()["total"]
        finally:
            conn.close()
        val = _get_val()
        return self._send_json({
            "total_analyses": total_analyses,
            "total_tenants": total_tenants,
            "total_threats": total_threats,
            "total_reported_phish": total_reported,
            "valuation": val,
        })

    def _handle_feedback_stats(self):
        from src.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT COUNT(*) as total FROM feedback_loop")
            total = c.fetchone()["total"]
            c.execute("SELECT COUNT(*) FROM feedback_loop WHERE user_label='fp'")
            fps = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM feedback_loop WHERE user_label='fn'")
            fns = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM feedback_loop WHERE user_label='correct'")
            correct = c.fetchone()[0]
        except Exception:
            total = fps = fns = correct = 0
        finally:
            conn.close()
        total_labeled = fps + fns + correct
        return self._send_json({
            "total": total,
            "false_positives": fps,
            "false_negatives": fns,
            "correct": correct,
            "accuracy": round(correct / total_labeled * 100, 1) if total_labeled else 0,
        })

    def _handle_detection_rules(self):
        from src.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM custom_rules ORDER BY id DESC LIMIT 100")
            rules = [dict(r) for r in c.fetchall()]
        except Exception:
            rules = []
        conn.close()
        return self._send_json({"rules": rules, "count": len(rules)})

    def _handle_billing_revenue(self):
        from src.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT plan, status, COUNT(*) as count FROM paddle_subscriptions GROUP BY plan, status")
            rows = [dict(r) for r in c.fetchall()]
        except Exception:
            rows = []
        conn.close()
        total_active = sum(r["count"] for r in rows if r["status"] == "active")
        plans = {"starter": 29, "business": 99, "consultant": 199, "enterprise": 499}
        mrr = sum(plans.get(r["plan"], 0) * r["count"] for r in rows if r["status"] == "active")
        return self._send_json({
            "subscriptions": rows,
            "total_active": total_active,
            "mrr": mrr,
            "arr": mrr * 12,
        })

    def _handle_logs_ingest(self):
        try:
            body = json.loads(self._read_body().decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._send_json({"error": "Invalid JSON"}, 400)
        event = body.get("event", body.get("action", "unknown"))
        username = body.get("username", "api")
        detail = body.get("detail", json.dumps(body))
        from src.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO usage_log (username, action, timestamp, risk_score) "
            "VALUES (?, ?, datetime('now'), ?)",
            (username, event, body.get("risk_score", 0)),
        )
        conn.commit()
        conn.close()
        return self._send_json({"status": "logged", "event": event})

    def _handle_health_status(self):
        from src.db import get_connection
        checks = {}
        try:
            conn = get_connection()
            conn.execute("SELECT 1")
            conn.close()
            checks["database"] = "ok"
        except Exception as e:
            checks["database"] = str(e)
        try:
            import importlib
            for mod in ["src.detector", "src.ai_analyzer", "src.jury_engine"]:
                importlib.import_module(mod)
            checks["modules"] = "ok"
        except Exception as e:
            checks["modules"] = str(e)
        from src.env import ENV
        checks["paddle_configured"] = ENV.paddle_configured
        checks["llm_providers"] = sum(1 for k in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY"] if getattr(ENV, k, ""))
        return self._send_json({
            "status": "ok" if checks.get("database") == "ok" else "degraded",
            "service": "phishguard-api-proxy",
            "version": "3.0.0",
            "checks": checks,
        })

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
