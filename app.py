import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡",
                   layout="wide", initial_sidebar_state="collapsed")

# ── Plausible Analytics ─────────────────────────────────────────────────────
st.markdown(
    '<script defer data-domain="sabersouihi-phishguard-ai.hf.space" src="https://plausible.io/js/script.js"></script>',
    unsafe_allow_html=True,
)

# ── PWA Manifest ────────────────────────────────────────────────────────────
st.markdown(
    '<link rel="manifest" href="/static/manifest.json">'
    '<meta name="theme-color" content="#3b82f6">'
    '<meta name="apple-mobile-web-app-capable" content="yes">',
    unsafe_allow_html=True,
)

# ── SSO Callback Handler (OIDC redirect) ────────────────────────────────────
_sso_code = st.query_params.get("code")
_sso_state = st.query_params.get("state", "")
if _sso_code:
    try:
        from src.sso import SSOManager
        _sso = SSOManager()
        _info = _sso.handle_callback(_sso_code, state=_sso_state)
        if _info and _info.get("email"):
            from src.tenants import create_tenant, verify_tenant
            _username = _info["email"].split("@")[0].replace(".", "_")
            _existing = verify_tenant(_username, _info["email"])
            if not _existing:
                create_tenant(_username, _info["email"], email=_info["email"], plan="trial")
            st.session_state["authenticated"] = True
            st.session_state["username"] = _username
            st.session_state["plan"] = "trial"
            st.session_state["is_admin"] = False
            st.session_state["email"] = _info["email"]
            st.query_params.clear()
            st.rerun()
    except Exception as e:
        import logging
        logging.getLogger("phishguard").warning(f"SSO callback failed: {e}")

# ── All src.* imports go AFTER set_page_config to avoid Streamlit init issues ──
# Core imports (critical — no fallback, must succeed)
from src.auth import check_password, logout  # noqa: E402
from src.database import check_scan_quota, get_history, init_db, save_analysis  # noqa: E402
from src.db import get_connection  # noqa: E402
from src.detector import analyze_email  # noqa: E402
from src.env import ENV, get_config_status, log_config_status  # noqa: E402
from src.tenants import (  # noqa: E402
    PLANS,
    check_quota,
    create_tenant,
    delete_tenant,
    get_all_tenants,
    get_usage_all_tenants,
    log_usage,
    set_password,
    update_tenant,
)


# Secondary imports (wrapped — may fail on minimal installs)
def _safe_import(mod, names, fallback=None):
    try:
        m = __import__(mod, fromlist=names)
        result = {}
        for name in names:
            if hasattr(m, name):
                result[name] = getattr(m, name)
            else:
                result[name] = (lambda *a, **kw: fallback) if fallback is not None else (lambda *a, **kw: None)
        return result
    except Exception:
        return {name: (lambda *a, **kw: fallback) if fallback is not None else (lambda *a, **kw: None) for name in names}

_ai = _safe_import('src.ai_analyzer', ['analyze_screenshot', 'generate_ai_report', 'simulate_phishing'])
analyze_screenshot = _ai['analyze_screenshot']
generate_ai_report = _ai['generate_ai_report']
simulate_phishing = _ai['simulate_phishing']

_alerts = _safe_import('src.alerts', ['get_alert_log', 'send_threat_alert'])
get_alert_log = _alerts['get_alert_log']
send_threat_alert = _alerts['send_threat_alert']

_b2b = _safe_import('src.b2b_gateway', ['MockAPIGateway', 'get_tier_config'])
MockAPIGateway = _b2b['MockAPIGateway']
get_tier_config = _b2b['get_tier_config']

_brand = _safe_import('src.brand_impersonation', ['run_brand_impersonation_check'])
_run_brand_check = _brand['run_brand_impersonation_check']

_copilot = _safe_import('src.copilot', ['SUGGESTED_PROMPTS', 'get_copilot_response'])
SUGGESTED_PROMPTS = _copilot['SUGGESTED_PROMPTS']
get_copilot_response = _copilot['get_copilot_response']

_email_parser = _safe_import('src.email_parser', ['parse_email_file'])
parse_email_file = _email_parser['parse_email_file']

_header = _safe_import('src.header_auth', ['analyze_auth_headers'])
analyze_auth_headers = _header['analyze_auth_headers']

_jury = _safe_import('src.jury_engine', ['compute_ensemble_score', 'evaluate_corporate_jury', 'evaluate_linguistic_jury'])
compute_ensemble_score = _jury['compute_ensemble_score']
evaluate_corporate_jury = _jury['evaluate_corporate_jury']
evaluate_linguistic_jury = _jury['evaluate_linguistic_jury']

_osint = _safe_import('src.osint', ['run_osint'])
run_osint = _osint['run_osint']

_report = _safe_import('src.report_generator', ['generate_pdf_report'])
generate_pdf_report = _report['generate_pdf_report']

_sess = _safe_import('src.session_manager', ['list_sessions', 'revoke_all_sessions', 'revoke_session'])
list_sessions = _sess['list_sessions']
revoke_all_sessions = _sess['revoke_all_sessions']
revoke_session = _sess['revoke_session']

_threat = _safe_import('src.threat_intel', ['check_multiple_urls', 'get_threat_summary'])
check_multiple_urls = _threat['check_multiple_urls']
get_threat_summary = _threat['get_threat_summary']

_scorer = _safe_import('src.threat_scorer', ['compute_combined_threat_score'])
compute_combined_threat_score = _scorer['compute_combined_threat_score']

_xai = _safe_import('src.xai_analyzer', ['analyze_psychological_triggers', 'format_xai_report'])
analyze_psychological_triggers = _xai['analyze_psychological_triggers']
format_xai_report = _xai['format_xai_report']

# Paddle billing (wrapped with sensible fallbacks)
try:
    from src.paddle_billing import (
        cancel_subscription,
        generate_checkout_url as paddle_generate_checkout_url,
        get_customer_portal_url,
        get_invoices,
        get_local_subscription as paddle_get_local_subscription,
        get_price_id,
        get_subscription,
        pause_subscription,
        resume_subscription,
        update_subscription_plan,
        verify_transaction,
    )
    from src.paddle_billing import is_configured as paddle_configured
except Exception:
    def paddle_configured(): return False
    def paddle_generate_checkout_url(*a, **kw): return None
    def verify_transaction(*a, **kw): return None
    def paddle_get_local_subscription(*a, **kw): return None
    def get_subscription(*a, **kw): return None
    def get_price_id(*a, **kw): return None
    def get_customer_portal_url(*a, **kw): return None
    def get_invoices(*a, **kw): return []
    pause_subscription = cancel_subscription = resume_subscription = update_subscription_plan = lambda *a, **kw: False

# Gumroad billing (new provider)
try:
    from src.billing.gumroad import GumroadProvider, is_gumroad_configured
    from src.billing.service import BillingService
    from src.billing.config import get_plan, get_yearly_savings_pct, get_all_plans as get_billing_plans
    _gumroad_provider = GumroadProvider()
    billing_service = BillingService(_gumroad_provider)
    def gumroad_configured(): return is_gumroad_configured()
except Exception:
    def gumroad_configured(): return False
    billing_service = None
    def get_plan(*a, **kw): return None
    def get_yearly_savings_pct(*a, **kw): return 0
    def get_billing_plans(): return []

# Determine active billing provider
def _billing_service():
    if gumroad_configured():
        return billing_service
    return None

# Remaining secondary imports
_camp = _safe_import('src.campaign_engine', ['create_campaign', 'generate_llm_template', 'get_campaign_results', 'get_campaigns', 'get_templates', 'launch_campaign'])
create_campaign = _camp['create_campaign']
generate_llm_template = _camp['generate_llm_template']
get_campaign_results = _camp['get_campaign_results']
get_campaigns = _camp['get_campaigns']
get_templates = _camp['get_templates']
launch_campaign = _camp['launch_campaign']

_cr = _safe_import('src.custom_rules', ['add_rule', 'list_rules', 'remove_rule', 'toggle_rule'])
add_rule = _cr['add_rule']
list_rules = _cr['list_rules']
remove_rule = _cr['remove_rule']
toggle_rule = _cr['toggle_rule']

_gdpr = _safe_import('src.gdpr', ['check_consent', 'delete_user_data', 'export_user_data', 'record_consent', 'revoke_consent'])
check_consent = _gdpr['check_consent']
delete_user_data = _gdpr['delete_user_data']
export_user_data = _gdpr['export_user_data']
record_consent = _gdpr['record_consent']
revoke_consent = _gdpr['revoke_consent']

_i18n = _safe_import('src.i18n', ['SUPPORTED_LANGUAGES', 't'])
SUPPORTED_LANGUAGES = _i18n.get('SUPPORTED_LANGUAGES', {'en': 'English'})
if not isinstance(SUPPORTED_LANGUAGES, dict):
    SUPPORTED_LANGUAGES = {'en': 'English'}
t = _i18n.get('t', lambda s, **kw: s)
if not callable(t):
    t = lambda s, **kw: s

_integrations = _safe_import('src.integrations', ['get_available_providers', 'list_integrations', 'remove_integration', 'save_integration'])
get_available_providers = _integrations['get_available_providers']
list_integrations = _integrations['list_integrations']
remove_integration = _integrations['remove_integration']
save_integration = _integrations['save_integration']

_ip = _safe_import('src.ip_allowlist', ['add_ip_rule', 'list_ip_rules', 'remove_ip_rule'])
add_ip_rule = _ip['add_ip_rule']
list_ip_rules = _ip['list_ip_rules']
remove_ip_rule = _ip['remove_ip_rule']

from src.database import record_scan as lb_record_scan  # noqa: E402

_leaderboard = _safe_import('src.leaderboard', ['render_leaderboard'])
render_leaderboard = _leaderboard['render_leaderboard']

_notif = _safe_import('src.notifications', ['push_notification', 'unread_count'])
push_notification = _notif['push_notification']
unread_count = _notif['unread_count']

_rl = _safe_import('src.ratelimit', ['check_rate_limit', 'get_rate_limit_remaining'])
check_rate_limit = _rl['check_rate_limit']
get_rate_limit_remaining = _rl['get_rate_limit_remaining']

# ── RBAC permissions ────────────────────────────────────────────────────────
_rbac = _safe_import('src.rbac', ['init_rbac'])
init_rbac = _rbac['init_rbac']

_ret = _safe_import('src.retention', ['get_retention_policy', 'purge_old_data', 'set_retention_policy'])
get_retention_policy = _ret['get_retention_policy']
purge_old_data = _ret['purge_old_data']
set_retention_policy = _ret['set_retention_policy']

_analytics = _safe_import('src.ui_founder_analytics', ['render_founder_analytics'])
render_founder_analytics = _analytics['render_founder_analytics']

_wr = _safe_import('src.weekly_report', ['generate_weekly_report'])
generate_weekly_report = _wr['generate_weekly_report']

_ws = _safe_import('src.workspace', ['create_workspace', 'get_members', 'invite_member', 'list_workspaces', 'remove_member'])
create_workspace = _ws['create_workspace']
get_members = _ws['get_members']
invite_member = _ws['invite_member']
list_workspaces = _ws['list_workspaces']
remove_member = _ws['remove_member']

# Init core systems
try:
    init_rbac()
except Exception:
    pass

# ── Structured JSON logging (opt-in via JSON_LOG=true) ──────────────────────
from src.json_logger import setup_json_logging  # noqa: E402

setup_json_logging()

# ── Enterprise component imports (with guards for optional deps) ──
try:
    from src.threat_intel_sharing import (
        check_collective_immunity,
        get_all_active_indicators,
        immunise_from_analysis,
    )
    _HAS_STIX = True
except Exception:
    _HAS_STIX = False

try:
    from src.sender_profiler import (
        detect_behavioural_anomaly,
        get_all_profiles_summary,
    )
    _HAS_SENDER_PROFILER = True
except Exception:
    _HAS_SENDER_PROFILER = False

try:
    from src.ocr_homograph import (
        check_url_for_homograph,
    )
    _HAS_OCR = True
except Exception:
    _HAS_OCR = False

try:
    from src.url_sandbox import (
        analyse_url_sandbox_sync,
        get_sandbox_history,
    )
    _HAS_URL_SANDBOX = True
except Exception:
    _HAS_URL_SANDBOX = False

# ── Initialize analytics tables on startup ─────────────────────────────────
try:
    from src.analytics import init_analytics_db
    init_analytics_db()
except Exception:
    pass

# ── Paddle Webhook endpoint (mounted on Streamlit's Tornado server) ───────
try:
    import tornado.web
    from streamlit.web.server import Server

    from src.paddle_billing import handle_webhook_event, verify_webhook_signature

    class _PaddleWebhookHandler(tornado.web.RequestHandler):
        def prepare(self):
            if self.request.method != "POST":
                self.set_status(405)
                self.finish({"error": "Method not allowed"})
                return
            body = self.request.body
            sig = self.request.headers.get("Paddle-Signature", "")
            if not sig:
                self.set_status(401)
                self.finish({"error": "Missing signature"})
                return
            if not verify_webhook_signature(body, sig):
                self.set_status(401)
                self.finish({"error": "Invalid signature"})
                return
            try:
                payload = json.loads(body)
            except Exception:
                self.set_status(400)
                self.finish({"error": "Invalid JSON"})
                return
            try:
                result = handle_webhook_event(payload)
                print(f"[paddle-webhook] {payload.get('event_type','?')}: {result}")
                self.write(result)
            except Exception as e:
                print(f"[paddle-webhook] Error: {e}")
                self.set_status(500)
                self.finish({"error": str(e)})

    class _SubscribeHandler(tornado.web.RequestHandler):
        def prepare(self):
            if self.request.method != "POST":
                self.set_status(405)
                self.finish({"error": "Method not allowed"})
                return
            import sqlite3
            email = self.get_body_argument("email", "")
            if not email or "@" not in email:
                self.set_status(400)
                self.finish({"error": "Invalid email"})
                return
            try:
                db = sqlite3.connect("data/phishguard.db")
                db.execute("CREATE TABLE IF NOT EXISTS email_subscribers (email TEXT PRIMARY KEY, created_at TEXT DEFAULT (datetime('now')))")
                db.execute("INSERT OR IGNORE INTO email_subscribers (email) VALUES (?)", (email,))
                db.commit()
                db.close()
            except Exception:
                pass
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Headers", "Content-Type")
            self.set_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.write({"status": "ok"})
        def options(self):
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Headers", "Content-Type")
            self.set_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.finish()

    # ════════════════════════════════════════════════════════════════
    # EMAIL OPEN TRACKING PIXEL
    # ════════════════════════════════════════════════════════════════
    TRACKING_GIF = (
        b"GIF89a\x01\x00\x01\x00\x80\x01\x00\x00\x00\x00\xff\xff\xff"
        b"!\xf9\x04\x01\x0a\x00\x01\x00\x44\x00\x00"
    )

    class _TrackingHandler(tornado.web.RequestHandler):
        def get(self, email_id):
            try:
                import sqlite3
                from datetime import datetime, timezone
                db = sqlite3.connect("data/phishguard.db")
                db.execute("CREATE TABLE IF NOT EXISTS outreach (id INTEGER PRIMARY KEY, opened_at TEXT)")
                now = datetime.now(timezone.utc).isoformat()
                ip = self.request.remote_ip
                ua = self.request.headers.get("User-Agent", "")
                db.execute(
                    "UPDATE outreach SET opened_at = COALESCE(opened_at, ?) WHERE id = ?",
                    (now, int(email_id))
                )
                if db.total_changes == 0:
                    db.execute("INSERT OR IGNORE INTO outreach (id, opened_at) VALUES (?, ?)", (int(email_id), now))
                db.commit()
                db.close()
                print(f"[track] email_id={email_id} ip={ip} ua={ua[:50]}")
            except Exception as e:
                print(f"[track] Error: {e}")
            self.set_header("Content-Type", "image/gif")
            self.set_header("Content-Length", str(len(TRACKING_GIF)))
            self.set_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.set_header("Pragma", "no-cache")
            self.set_header("Access-Control-Allow-Origin", "*")
            self.write(TRACKING_GIF)

    class _HealthHandler(tornado.web.RequestHandler):
        def get(self):
            self.set_header("Content-Type", "application/json")
            self.write({"status": "ok", "service": "phishguard"})

    _orig_start = Server.start
    def _patched_start(self, *args, **kwargs):
        self._tornado.add_handlers(r".*", [
            (r"/webhook", _PaddleWebhookHandler),
            (r"/subscribe", _SubscribeHandler),
            (r"/track/([0-9]+)", _TrackingHandler),
            (r"/health", _HealthHandler),
        ])
        return _orig_start(self, *args, **kwargs)
    Server.start = _patched_start
except Exception:
    pass  # Webhook unavailable (missing deps or paddle not installed)

if not check_password():
    st.stop()

# ── Data caching (60s TTL) ──────────────────────────────────────────────────
@st.cache_data(ttl=60)
def _cached_history(limit: int = 500):
    return get_history(limit)

@st.cache_data(ttl=60)
def _cached_threats(limit: int = 10):
    from src.admin import get_recent_threats as _gt
    return _gt(limit)

@st.cache_data(ttl=60)
def _cached_all_analyses(limit: int = 100):
    from src.admin import get_all_analyses as _ga
    return _ga(limit)

theme = st.session_state.get("theme", "dark")
from src.ui_theme import apply_theme  # noqa: E402

apply_theme(theme)
from src.ui_design_system import (  # noqa: E402
    empty_state,
    inject_design_system,
    section_title,
    stat_card,
    url_box,
)

inject_design_system(theme)

init_db()
try:
    from src.analytics import init_analytics_db
    init_analytics_db()
except Exception:
    pass
log_config_status()

# ── Start background task queue worker ──────────────────────────────────────
try:
    from src.database import save_analysis
    from src.enterprise_api import handle_scan_request
    from src.task_queue import register_task, start_worker, store_result

    def _handle_scan_mailbox(payload):
        max_per_run = payload.get("max_per_run", 10)
        from src.inbox_scanner import scan_inbox, scan_unseen
        emails = scan_unseen(None, None, None, None, max_emails=max_per_run)
        results = []
        for e in emails[:max_per_run]:
            body = e.get("body", "")
            result = handle_scan_request({"text": body[:10000], "sender": e.get("sender", "")})
            v = result.get("verdict", {})
            results.append({"subject": e.get("subject", ""), "score": v.get("risk_score", 0), "severity": v.get("severity", "UNKNOWN")})
        import json

        from src.task_queue import get_connection as tq_conn
        conn = tq_conn()
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS task_results (task_id INTEGER PRIMARY KEY, result TEXT)")
        c.execute("INSERT OR REPLACE INTO task_results (task_id, result) VALUES (?, ?)",
                  (payload.get("_task_id", 0), json.dumps({"emails_scanned": len(results), "results": results})))
        conn.commit()
        conn.close()

    register_task("scan_mailbox", _handle_scan_mailbox)
    start_worker()
except Exception as e:
    import logging
    logging.getLogger("phishguard").warning(f"Task queue worker failed: {e}")

# ── Start scheduler for recurring scans ────────────────────────────────────
try:
    from src.scheduler import start_scheduler
    start_scheduler()
except Exception as e:
    import logging
    logging.getLogger("phishguard").warning(f"Scheduler failed to start: {e}")

# ── Start real-time notification poller ─────────────────────────────────────
if "notification_check" not in st.session_state:
    st.session_state["notification_check"] = 0

# ── Startup health check + config banner (admin only) ─────────────────────
from src.smtp_validation import smtp_config_status
_smtp_status = smtp_config_status()
if not _smtp_status["configured"]:
    import logging
    logging.getLogger("phishguard").warning(
        "SMTP not configured at startup. Missing: %s  — email verification, password reset, and welcome emails disabled.",
        ", ".join(_smtp_status["missing"]),
    )

if st.session_state.get("is_admin"):
    cfg_status = get_config_status()
    missing = [k for k, v in cfg_status.items() if isinstance(v, dict) and not v["configured"]]
    issues = []
    if missing:
        issues.append(("Missing API keys", missing))
    if not _smtp_status["configured"]:
        issues.append(("SMTP not configured", _smtp_status["missing"]))
    if issues:
        import logging
        logger = logging.getLogger("phishguard")
        with st.sidebar.expander("⚠️ Configuration Status", expanded=True):
            for title, keys in issues:
                st.caption(f"{title}:")
                for key in keys:
                    st.markdown(f"- `{key}`")
            st.caption("Set these via env vars or HF Space → Settings → Variables and secrets.")
            st.caption("The app will still run — features needing these keys will gracefully degrade.")

username = st.session_state.get("username", "user")
plan     = st.session_state.get("plan", "trial")
is_admin = st.session_state.get("is_admin", False)

# ── Session timeout (30 min inactivity) ─────────────────────────────────────
now = datetime.now()
last_active = st.session_state.get("last_active")
if last_active:
    elapsed = (now - last_active).total_seconds()
    if elapsed > 1800:
        for key in ["authenticated", "username", "plan", "is_admin", "email", "last_active"]:
            st.session_state.pop(key, None)
        st.warning("⏰ Session expired due to inactivity. Please log in again.")
        st.rerun()
st.session_state["last_active"] = now

# ── Onboarding Wizard ────────────────────────────────────────────────────────
if st.session_state.get("show_onboarding", False):
    from src.ui_onboarding import render_onboarding
    render_onboarding(username)
    st.stop()

# ── Header ───────────────────────────────────────────────────────────────────
col_title, col_quota, col_user = st.columns([2, 2, 1])

with col_title:
    st.markdown(
        "<div style='display:flex;align-items:center;gap:10px;margin-top:6px'>"
        "<span style='font-size:1.8rem'>🛡</span>"
        "<div><div style='font-size:1.4rem;font-weight:800;color:var(--text-primary,#f1f5f9);"
        "letter-spacing:-0.03em'>PhishGuard AI</div>"
        "<div style='font-size:0.75rem;color:var(--text-secondary,#94a3b8);margin-top:-2px'>"
        "AI-Powered Phishing & Threat Detection</div></div></div>",
        unsafe_allow_html=True
    )

with col_quota:
    q = check_quota(username, plan)
    plan_label = PLANS.get(plan, PLANS["trial"])["label"]
    limit_display = "∞" if plan == "enterprise" else str(q["limit"])
    bar_color = "#ef4444" if q["pct"] >= 90 else "#f59e0b" if q["pct"] >= 70 else "#3b82f6"
    bar_width = q["pct"] if plan != "enterprise" else 0

    st.markdown(
        f"<div style='background:#111827;border:1px solid #1e293b;border-radius:10px;"
        f"padding:8px 14px;margin-top:6px'>"
        f"<div style='display:flex;justify-content:space-between;font-size:0.7rem;"
        f"color:#94a3b8;margin-bottom:4px'>"
        f"<span style='font-weight:600'>{plan_label}</span>"
        f"<span>{q['usage']} / {limit_display} scans</span></div>"
        f"<div class='pg-quota-bg'><div class='pg-quota-fill' "
        f"style='width:{bar_width}%;background:{bar_color}'></div></div></div>",
        unsafe_allow_html=True
    )

with col_user:
    from src.notifications import unread_count
    n_count = unread_count(username)
    from src.ui_theme import render_theme_toggle

    st.markdown(
        f"<div style='display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:6px'>"
        f"<span style='font-size:0.8rem;color:#64748b'>👤 {username}</span>"
        + (
            f"<span style='background:#ef4444;color:#fff;border-radius:100px;"
            f"padding:1px 7px;font-size:0.65rem;font-weight:700'>{n_count}</span>"
            if n_count else ""
        ) +
        "</div>",
        unsafe_allow_html=True
    )

    col_nav1, col_nav2, col_nav3 = st.columns(3)
    with col_nav1:
        if st.button("⬆ Upgrade", key="upgrade_btn_header", use_container_width=True):
            st.session_state["show_upgrade"] = True
            st.rerun()
    with col_nav2:
        render_theme_toggle()
    with col_nav3:
        if st.button("🚪 Logout", key="logout_btn", use_container_width=True):
            logout()

    lang = st.session_state.get("lang", "en")
    selected_lang = st.selectbox(
        "Language", list(SUPPORTED_LANGUAGES.keys()),
        index=list(SUPPORTED_LANGUAGES.keys()).index(lang) if lang in SUPPORTED_LANGUAGES else 0,
        format_func=lambda k: SUPPORTED_LANGUAGES.get(k, k),
        label_visibility="collapsed",
        key="lang_selector",
    )
    if selected_lang != lang:
        st.session_state["lang"] = selected_lang
        st.rerun()

st.divider()

# ── Handle Paddle checkout return ────────────────────────────────────────────
qp = st.query_params
if qp.get("checkout") == "completed" and qp.get("transaction_id"):
    txn_id = qp["transaction_id"]
    with st.spinner("Verifying payment..."):
        txn = verify_transaction(txn_id)
    if txn and txn.get("status") in ("completed", "paid"):
        custom = txn.get("custom_data", {}) or {}
        txn_plan = custom.get("plan", "starter")
        update_tenant(username, plan=txn_plan)
        st.session_state["plan"] = txn_plan
        st.success(f"✅ Payment confirmed! Your account has been upgraded to **{PLANS[txn_plan]['label']}** plan.")
        st.query_params.clear()
        st.rerun()
    else:
        st.warning("⏳ Payment received but verification is pending. The webhook will process it shortly.")
        st.query_params.clear()

# ── Upgrade section ──────────────────────────────────────────────────────────
if st.session_state.get("show_upgrade") and plan != "enterprise":
    with st.container():
        st.markdown("## ⬆ Upgrade Your Plan")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Choose a plan that fits your needs. "
            "All plans include AI-powered phishing detection.</p>",
            unsafe_allow_html=True
        )

        billing_available = paddle_configured() or gumroad_configured()
        if not billing_available:
            st.warning(
                "⚠️ Payment processing is not configured. "
                "Contact the administrator to set up billing."
            )
            if st.button("← Back", key="upgrade_back_no"):
                st.session_state["show_upgrade"] = False
                st.rerun()
            st.stop()

        # Billing cycle toggle
        billing_cycle = st.session_state.get("billing_cycle", "monthly")
        col_t1, col_t2, col_t3 = st.columns([1, 1, 1])
        with col_t2:
            cycle_opts = ["Monthly", "Yearly"]
            cycle_idx = 1 if billing_cycle == "yearly" else 0
            selected = st.segmented_control(
                "Billing cycle", cycle_opts, default=cycle_opts[cycle_idx],
                label_visibility="collapsed", key="billing_cycle_toggle",
            )
            new_cycle = "yearly" if selected == "Yearly" else "monthly"
            if new_cycle != billing_cycle:
                st.session_state["billing_cycle"] = new_cycle
                st.rerun()

        cols = st.columns(2)
        from src.billing.config import get_plan as _get_billing_plan, get_yearly_savings_pct as _yearly_savings
        for i, pkey in enumerate(["starter", "business"]):
            with cols[i]:
                pcfg = _get_billing_plan(pkey)
                if not pcfg:
                    continue
                featured = pkey == "business"
                is_yearly = billing_cycle == "yearly"
                price = f"${pcfg.price_yearly}/yr" if is_yearly else f"${pcfg.price_monthly}/mo"
                savings = _yearly_savings(pkey)
                border = "2px solid #3b82f6" if featured else "1px solid rgba(255,255,255,0.1)"
                bg = "linear-gradient(160deg, #040f24, #071530)" if featured else "#0f172a"
                st.markdown(
                    "<div style='background:" + bg + ";border:" + border + ";"
                    "border-radius:16px;padding:28px 20px;text-align:center;"
                    "position:relative;height:100%'>"
                    + ("<div style='position:absolute;top:-10px;left:50%;transform:translateX(-50%);"
                       "background:#3b82f6;color:#020818;font-size:10px;font-weight:700;"
                       "padding:4px 16px;border-radius:100px;letter-spacing:0.1em'>"
                       "MOST POPULAR</div>" if featured else "")
                    + ("<div style='position:absolute;top:-10px;right:20px;"
                       "background:#22c55e;color:#020818;font-size:10px;font-weight:700;"
                       "padding:4px 10px;border-radius:100px'>"
                       f"Save {savings}%</div>" if is_yearly and savings > 0 else "")
                    + "<div style='color:#94a3b8;font-size:0.9rem;font-weight:600;"
                       "letter-spacing:0.05em;margin-bottom:8px'>" + pcfg.label + "</div>"
                    + "<div style='color:#f0f6ff;font-size:2.4rem;font-weight:800;"
                       "margin-bottom:4px'>" + price + "</div>"
                    + "<div style='color:#475569;font-size:0.75rem;margin-bottom:20px;"
                       "font-family:monospace'>" + ("per year" if is_yearly else "per month") + "</div>"
                    + "<ul style='list-style:none;padding:0;margin:0 0 24px;text-align:left'>"
                    + "".join("<li style='color:#94a3b8;font-size:0.8rem;padding:4px 0;"
                              "border-bottom:1px solid rgba(255,255,255,0.04)'>→ " + f + "</li>"
                              for f in pcfg.features)
                    + "</ul></div>",
                    unsafe_allow_html=True
                )

                already_on = plan == pkey
                if already_on:
                    st.success("✅ Current Plan")
                else:
                    if st.button("⬆ Subscribe — " + pcfg.label, key="sub_" + pkey + "_" + billing_cycle, use_container_width=True, type="primary"):
                        with st.spinner("Creating checkout session..."):
                            base = ENV.APP_URL or getattr(getattr(st, 'context', None), 'headers', {}).get("Origin", "http://localhost:8501")
                            success_url = base + "/?checkout=completed"

                            if gumroad_configured() and billing_service:
                                from src.billing.models import CheckoutRequest
                                req = CheckoutRequest(
                                    username=username,
                                    plan_name=pkey,
                                    billing_cycle=billing_cycle,
                                    success_url=success_url,
                                )
                                resp = billing_service.create_checkout(req)
                                url = resp.url if resp else None
                            else:
                                url = paddle_generate_checkout_url(username, pkey, success_url=success_url)
                        if url:
                            st.session_state["checkout_url"] = url
                            st.session_state["checkout_plan"] = pkey
                            st.rerun()
                        else:
                            st.error("Could not create checkout. Please try again.")

        # If checkout URL is set, show proceed button
        checkout_url = st.session_state.get("checkout_url")
        if checkout_url:
            cplan = st.session_state["checkout_plan"]
            st.divider()
            st.markdown(f"### 🛒 Ready to subscribe to **{PLANS[cplan]['label']}**")
            provider_name = "Gumroad" if gumroad_configured() else "Paddle"
            st.info(
                f"You will be redirected to {provider_name}'s secure checkout. "
                "After payment, you'll be returned here and your plan will upgrade automatically."
            )
            col_pay, col_cancel = st.columns([1, 1])
            with col_pay:
                st.link_button("💳 Proceed to Checkout", checkout_url, use_container_width=True, type="primary")
            with col_cancel:
                if st.button("Cancel", use_container_width=True):
                    st.session_state.pop("checkout_url", None)
                    st.session_state.pop("checkout_plan", None)
                    st.rerun()

        st.divider()
        if st.button("← Back to Dashboard", use_container_width=True):
            st.session_state["show_upgrade"] = False
            st.session_state.pop("checkout_url", None)
            st.session_state.pop("checkout_plan", None)
            st.rerun()
        st.stop()
    st.stop()

# ── Weekly Report Check ─────────────────────────────────────────────────────
try:
    from src.weekly_report import check_and_send_weekly
    _email = st.session_state.get("email", "")
    _wr_key = f"weekly_report_{username}"
    if _email and _wr_key not in st.session_state:
        st.session_state[_wr_key] = True
        check_and_send_weekly(username, _email)
except Exception as e:
    logger.warning("Weekly report check failed: %s", e)

# ── Sidebar Navigation Guide ──────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:10px;margin-bottom:12px'>"
        f"<span style='font-size:1.6rem'>🛡</span>"
        f"<div><div style='font-weight:700;font-size:1.05rem'>{username}</div>"
        f"<div style='font-size:0.7rem;color:#64748b'>{PLANS.get(plan, PLANS['trial'])['label']}</div></div></div>",
        unsafe_allow_html=True
    )
    st.markdown("<hr style='border-color:#1e293b;margin:8px 0'>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px'>Analysis</div>", unsafe_allow_html=True)
    st.markdown("→ <span style='color:#94a3b8'>Scan</span> · <span style='color:#94a3b8'>Compare</span> · <span style='color:#94a3b8'>Dashboard</span> · <span style='color:#94a3b8'>Copilot</span>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;margin-top:10px;margin-bottom:4px'>Intelligence</div>", unsafe_allow_html=True)
    st.markdown("→ <span style='color:#94a3b8'>Threat Intel</span> · <span style='color:#94a3b8'>Campaigns</span>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;margin-top:10px;margin-bottom:4px'>Education</div>", unsafe_allow_html=True)
    st.markdown("→ <span style='color:#94a3b8'>Training</span> · <span style='color:#94a3b8'>Leaderboard</span>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;margin-top:10px;margin-bottom:4px'>Investigation</div>", unsafe_allow_html=True)
    st.markdown("→ <span style='color:#94a3b8'>PDF Report</span> · <span style='color:#94a3b8'>STIX Export</span>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;margin-top:10px;margin-bottom:4px'>Developers</div>", unsafe_allow_html=True)
    st.markdown("→ <span style='color:#94a3b8'>API</span> · <span style='color:#94a3b8'>Webhooks</span>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;margin-top:10px;margin-bottom:4px'>Account</div>", unsafe_allow_html=True)
    st.markdown("→ <span style='color:#94a3b8'>Billing</span> · <span style='color:#94a3b8'>Settings</span>", unsafe_allow_html=True)
    if is_admin:
        st.markdown("<div style='font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;margin-top:10px;margin-bottom:4px'>Admin</div>", unsafe_allow_html=True)
        st.markdown("→ <span style='color:#94a3b8'>Admin Panel</span>", unsafe_allow_html=True)
    st.sidebar.markdown("<hr style='border-color:#1e293b;margin:8px 0'>", unsafe_allow_html=True)

# ── Tabs ─────────────────────────────────────────────────────────────────────
# Consolidated navigation: 10 major tabs with sub-navigation via radio groups
if is_admin:
    tabs = st.tabs([
        "🔍 Scan", "📊 Dashboard", "🤖 Copilot", "🛡️ Threat Intel", "🎯 Campaigns",
        "🎓 Training", "🔌 Developers", "💳 Billing", "⚙️ Settings", "🔧 Admin",
    ])
    tab_scan, tab_dash, tab_copilot, tab_threat, tab_campaigns, tab_train, tab_dev, tab_billing, tab_settings, tab_admin = tabs
else:
    tabs = st.tabs([
        "🔍 Scan", "📊 Dashboard", "🤖 Copilot", "🛡️ Threat Intel", "🎯 Campaigns",
        "🎓 Training", "🔌 Developers", "💳 Billing", "⚙️ Settings",
    ])
    tab_scan, tab_dash, tab_copilot, tab_threat, tab_campaigns, tab_train, tab_dev, tab_billing, tab_settings = tabs
    tab_admin = None

# Backward-compat aliases for existing content blocks
tab1 = tab_scan
tab2 = tab_scan
tab3 = tab_dash
tab4 = tab_copilot
billing_tab = tab_billing
settings_tab = tab_settings
training_tab = tab_train
champions_tab = tab_train
history_tab = tab_dash
tab_stix = tab_threat
tab_sender = tab_threat
tab_sandbox = tab_threat
tab_ocr = tab_threat
tab_api_docs = tab_dev
tab_webhook = tab_dev
tab_soc = tab_dash
tab_timeline = tab_dash
if is_admin:
    tab5 = tab_admin
    tab6 = tab_admin
    tab_audit = tab_admin
    tab_perf = tab_admin
    tab_ma = tab_admin

# ── Sub-navigation radio groups for composite tabs ──────────────────────────
with tab_scan:
    st.radio("", ["Email Text", "Inbox Scanner", "Compare Emails"], key="scan_mode", horizontal=True, label_visibility="collapsed")
with tab_dash:
    st.radio("", ["Overview", "History", "SOC", "Timeline"], key="dash_mode", horizontal=True, label_visibility="collapsed")
with tab_threat:
    st.radio("", ["STIX Intelligence", "Sender Profiler", "URL Sandbox", "OCR Detection"], key="threat_mode", horizontal=True, label_visibility="collapsed")
with tab_train:
    st.radio("", ["Training Tools", "Leaderboard"], key="train_mode", horizontal=True, label_visibility="collapsed")
with tab_dev:
    st.radio("", ["API Reference", "Webhook Tester"], key="dev_mode", horizontal=True, label_visibility="collapsed")
if is_admin:
    with tab_admin:
        st.radio("", ["Dashboard", "Team", "Audit", "Performance", "M&A"], key="admin_mode", horizontal=True, label_visibility="collapsed")

# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — ANALYZER
# ═════════════════════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — INBOX SCANNER
# ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("scan_mode", "Email Text") == "Inbox Scanner":
    with tab2:
        from src.inbox_scanner import scan_inbox, scan_unseen

        st.markdown("## 📥 Inbox Scanner")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Connect to your email account "
            "via IMAP to scan real inbox messages. Supports Gmail (App Password) "
            "and Outlook 365.</p>",
            unsafe_allow_html=True
        )
        st.divider()

        with st.expander("🔌 Connection Settings", expanded=True):
            col_imap1, col_imap2, col_imap3 = st.columns([2, 1, 1])
            with col_imap1:
                imap_host = st.text_input("IMAP Server", "imap.gmail.com", key="scan_imap_host")
            with col_imap2:
                imap_port = st.number_input("Port", 993, key="scan_imap_port")
            with col_imap3:
                imap_ssl = st.checkbox("SSL/TLS", True, key="scan_imap_ssl")
            col_imap4, col_imap5, col_imap6 = st.columns(3)
            with col_imap4:
                imap_user = st.text_input("Email Address", key="scan_imap_user")
            with col_imap5:
                imap_pass = st.text_input("Password / App Password", type="password", key="scan_imap_pass")
            with col_imap6:
                imap_folder = st.text_input("Folder", "INBOX", key="scan_imap_folder")
            col_imap7, col_imap8 = st.columns(2)
            with col_imap7:
                imap_hours = st.slider("Look back (hours)", 1, 168, 24, key="scan_imap_hours")
            with col_imap8:
                imap_max = st.slider("Max emails", 1, 100, 20, key="scan_imap_max")

        col_scan1, col_scan2 = st.columns(2)
        with col_scan1:
            if st.button("📩 Fetch Recent Emails", type="primary", use_container_width=True):
                if not imap_user or not imap_pass:
                    st.error("Email and password required.")
                    st.stop()
                with st.spinner("Connecting and fetching..."):
                    emails = scan_inbox(imap_host, imap_port, imap_user, imap_pass,
                                        imap_folder, imap_hours, imap_max)
                st.session_state["scanned_emails"] = emails
                st.session_state["scan_results"] = []
                st.rerun()
        with col_scan2:
            if st.button("📩 Fetch Unseen Only", use_container_width=True):
                if not imap_user or not imap_pass:
                    st.error("Email and password required.")
                    st.stop()
                with st.spinner("Scanning for unseen messages..."):
                    emails = scan_unseen(imap_host, imap_port, imap_user, imap_pass,
                                         imap_folder, imap_max)
                st.session_state["scanned_emails"] = emails
                st.session_state["scan_results"] = []
                st.rerun()

        if st.button("🔌 Disconnect", use_container_width=True):
            st.session_state.pop("scanned_emails", None)
            st.session_state.pop("scan_results", None)
            st.rerun()

        st.divider()

        scanned = st.session_state.get("scanned_emails", [])
        if scanned:
            st.markdown(f"**{len(scanned)} email(s) fetched**")
            email_options = [f"[{e.get('date', '')[:17]}] {e.get('subject', '(no subject)')} "
                             f"— {e.get('sender', '')}" for e in scanned]
            selected_idx = st.selectbox("Select an email to scan", range(len(email_options)),
                                        format_func=lambda i: email_options[i] if i < len(email_options) else "",
                                        key="imap_select")

            if selected_idx is not None and selected_idx < len(scanned):
                sel = scanned[selected_idx]
                st.markdown(f"**From:** {sel.get('sender', '')}")
                st.markdown(f"**Subject:** {sel.get('subject', '')}")
                st.markdown(f"**Date:** {sel.get('date', '')}")
                with st.expander("📄 View Body", expanded=False):
                    st.text(sel.get('body', '')[:2000])

                if st.button("🔍 Scan This Email", type="primary", use_container_width=True):
                    from src.enterprise_api import handle_scan_request
                    body = sel.get('body', '')
                    with st.spinner("Running multi-layered analysis..."):
                        result = handle_scan_request({"text": body, "sender": sel.get('sender', '')})
                    st.session_state["imap_scan_result"] = result
                    st.rerun()

            if st.session_state.get("imap_scan_result"):
                r = st.session_state["imap_scan_result"]
                v = r.get("verdict", {})
                st.divider()
                score = v.get("risk_score", 0)
                severity = v.get("severity", "UNKNOWN")
                color = {"SAFE": "#22c55e", "LOW": "#3b82f6", "MEDIUM": "#eab308",
                         "HIGH": "#f97316", "CRITICAL": "#ef4444"}.get(severity, "#94a3b8")
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e3a5f;"
                    f"border-radius:12px;padding:20px;margin:12px 0'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                    f"<span style='color:{color};font-size:1.4rem;font-weight:800'>"
                    f"{severity}</span>"
                    f"<span style='color:#94a3b8;font-size:2rem;font-weight:800'>"
                    f"{score}/100</span></div>"
                    f"<div style='margin-top:12px'>"
                    f"<span class='tag'>AI-written: {v.get('ai_written_probability', 0):.0%}</span>"
                    f"<span class='tag'>AitM: {v.get('aitm_confidence', 0):.0%}</span>"
                    f"<span class='tag'>Confidence: {v.get('confidence', 0):.0%}</span>"
                    f"</div></div>", unsafe_allow_html=True
                )
        else:
            st.info("Connect and fetch emails to begin scanning.")

    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("scan_mode", "Email Text") == "Compare Emails":
    with tab1:
        st.markdown("## 🔄 Compare Emails Side-by-Side")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Paste two emails to compare their "
            "phishing risk levels and understand which is more suspicious.</p>",
            unsafe_allow_html=True
        )
        st.divider()

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("##### 📧 Email A")
            email_a = st.text_area("Paste email A content", height=200,
                                    label_visibility="collapsed", key="email_a_input",
                                    placeholder="Paste the first email here...")
            st.checkbox("🔬 Show technical details for Email A", value=False, key="show_tech_a")
        with col_b:
            st.markdown("##### 📧 Email B")
            email_b = st.text_area("Paste email B content", height=200,
                                    label_visibility="collapsed", key="email_b_input",
                                    placeholder="Paste the second email here...")
            st.checkbox("🔬 Show technical details for Email B", value=False, key="show_tech_b")

        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
        with col_btn2:
            compare_btn = st.button("🔄 Compare Emails", use_container_width=True, type="primary")

        if compare_btn:
            if not email_a.strip() or not email_b.strip():
                st.warning("Please paste both emails before comparing.")
            else:
                with st.spinner("Analyzing both emails..."):
                    from src.detector import analyze_email
                    result_a = analyze_email(email_a)
                    result_b = analyze_email(email_b)

                from src.compare_emails import compare_email_analyses, get_verdict_text
                comparison = compare_email_analyses(result_a, result_b)

                st.divider()
                st.markdown("## 🔄 Comparison Results")

                verdict = get_verdict_text(comparison)
                more = comparison["differences"]["more_suspicious"]
                if more == "similar":
                    st.info(verdict)
                elif more == "A":
                    st.error(verdict)
                else:
                    st.error(verdict)

                col_s1, col_s2, col_s3 = st.columns(3)
                a_data = comparison["email_a"]
                b_data = comparison["email_b"]
                with col_s1:
                    st.metric("Email A Risk Score", f"{a_data['score']}/100",
                              delta=f"{a_data['score'] - b_data['score']:+d} vs B")
                with col_s2:
                    st.metric("Email B Risk Score", f"{b_data['score']}/100",
                              delta=f"{b_data['score'] - a_data['score']:+d} vs A")
                with col_s3:
                    st.metric("Score Difference", f"{comparison['differences']['score_diff']} pts")

                st.divider()

                with st.expander("📊 Detailed Comparison", expanded=True):
                    for reason in comparison["differences"]["reasons"]:
                        st.markdown(f"- {reason}")

                st.divider()

                col_c1, col_c2 = st.columns(2)
                with col_c1:
                    a_color = a_data.get("severity_color", "#94a3b8")
                    st.markdown(
                        f"<div style='background:#111827;border:1px solid {a_color}44;"
                        f"border-radius:10px;padding:12px 16px'>"
                        f"<div style='color:{a_color};font-weight:700;font-size:1.1rem'>Email A — {a_data['severity']}</div>"
                        f"<div style='color:#94a3b8;font-size:13px'>"
                        f"Keywords: {a_data['keyword_hits']} | "
                        f"Suspicious URLs: {a_data['suspicious_urls']} | "
                        f"URLs: {a_data['url_count']} | "
                        f"Attachments: {'Yes' if a_data['has_attachments'] else 'No'}"
                        f"</div>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
                with col_c2:
                    b_color = b_data.get("severity_color", "#94a3b8")
                    st.markdown(
                        f"<div style='background:#111827;border:1px solid {b_color}44;"
                        f"border-radius:10px;padding:12px 16px'>"
                        f"<div style='color:{b_color};font-weight:700;font-size:1.1rem'>Email B — {b_data['severity']}</div>"
                        f"<div style='color:#94a3b8;font-size:13px'>"
                        f"Keywords: {b_data['keyword_hits']} | "
                        f"Suspicious URLs: {b_data['suspicious_urls']} | "
                        f"URLs: {b_data['url_count']} | "
                        f"Attachments: {'Yes' if b_data['has_attachments'] else 'No'}"
                        f"</div>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                st.session_state["compare_a"] = result_a
                st.session_state["compare_b"] = result_b
                st.session_state["compare_results"] = comparison

elif st.session_state.get("scan_mode", "Email Text") == "Email Text":
    with tab1:
        from src.ui_analyzer import render_analyzer_tab
        render_analyzer_tab(username, plan)

    # ═════════════════════════════════════════════════════════════════════════════
    # TAB 3 — HOME DASHBOARD
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("dash_mode", "Overview") == "Overview":
    with tab3:
        # ── Onboarding Checklist ───────────────────────────────────────────────
        _chk_account = st.session_state.get("checklist_account", False)
        _chk_first_scan = st.session_state.get("checklist_first_scan", False)
        _chk_first_report = st.session_state.get("checklist_first_report", False)
        _chk_invite = st.session_state.get("checklist_invite", False)
        _chk_upgrade = st.session_state.get("checklist_upgrade", False)

        checklist_items = [
            ("☐", "Create account", _chk_account, "✅", "Account created"),
            ("☐", "Run your first scan", _chk_first_scan, "✅", "First scan complete"),
            ("☐", "Generate your first report", _chk_first_report, "✅", "Report generated"),
            ("☐", "Invite a teammate", _chk_invite, "✅", "Teammate invited"),
            ("☐", "Explore upgrade options", _chk_upgrade, "✅", "Plan reviewed"),
        ]
        completed_count = sum(1 for _, _, done, _, _ in checklist_items if done)
        if completed_count < 5:
            checklist_html = '<div style="background:linear-gradient(145deg,#0a0f1a,#0f1a2a);border:1px solid #1e293b;border-radius:14px;padding:16px 20px;margin-bottom:20px">'
            checklist_html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'
            checklist_html += '<span style="color:#f0f6ff;font-weight:700;font-size:14px">🚀 Getting Started</span>'
            checklist_html += f'<span style="color:#3b82f6;font-size:12px;font-weight:600">{completed_count}/5</span></div>'
            checklist_html += '<div style="background:#1e293b;border-radius:6px;height:4px;overflow:hidden;margin-bottom:12px">'
            checklist_html += f'<div style="background:linear-gradient(90deg,#3b82f6,#22c55e);width:{completed_count*20}%;height:100%;border-radius:6px"></div></div>'
            for item in checklist_items:
                unchecked, label, done, checked, done_label = item
                icon = checked if done else unchecked
                color = "#22c55e" if done else "#64748b"
                checklist_html += f'<div style="display:flex;align-items:center;gap:8px;padding:4px 0"><span style="color:{color}">{icon}</span><span style="color:{color};font-size:13px">{done_label if done else label}</span></div>'
            checklist_html += '</div>'
            st.markdown(checklist_html, unsafe_allow_html=True)

        # ── Hero: Security Score + Quick Actions ───────────────────────────────
        history = _cached_history(500)
        if history:
            scores = [row[1] for row in history]
            severities = [row[2] for row in history]
            total_scans = len(history)
            avg_score = round(sum(scores) / total_scans, 1) if total_scans else 0
            critical_count = sum(1 for s in severities if s == "CRITICAL")
            high_count = sum(1 for s in severities if s == "HIGH")
            threats_neutralized = critical_count + high_count
            safe_count = sum(1 for s in severities if s == "LOW")
            safe_pct = round(safe_count / total_scans * 100, 1) if total_scans else 0
            health = "🟢 Healthy" if avg_score < 30 else "🟡 Moderate" if avg_score < 60 else "🔴 At Risk"
        else:
            total_scans = 0; avg_score = 0; critical_count = 0; high_count = 0  # noqa: E702
            threats_neutralized = 0; safe_count = 0; safe_pct = 100; health = "🟢 No Data"  # noqa: E702

        hero_col1, hero_col2 = st.columns([1.3, 1])
        with hero_col1:
            score_color = "#22c55e" if avg_score < 30 else "#eab308" if avg_score < 60 else "#ef4444"
            st.markdown(
                f"<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);border:1px solid #1e293b;"
                f"border-radius:16px;padding:20px 24px;margin-bottom:16px'>"
                f"<div style='display:flex;align-items:center;gap:20px'>"
                f"<div style='text-align:center'>"
                f"<div style='font-size:2.2rem;font-weight:800;color:{score_color};line-height:1'>{avg_score}</div>"
                f"<div style='font-size:0.7rem;color:#64748b;margin-top:2px'>/ 100</div>"
                f"</div>"
                f"<div style='flex:1'>"
                f"<div style='display:flex;align-items:center;gap:8px'>"
                f"<span style='font-size:1.1rem;font-weight:700;color:#f0f6ff'>Security Posture</span>"
                f"<span style='background:{score_color}20;color:{score_color};font-size:0.7rem;"
                f"padding:1px 8px;border-radius:100px;font-weight:600'>{health}</span>"
                f"</div>"
                f"<div style='color:#64748b;font-size:0.75rem;margin-top:2px'>"
                f"{total_scans} scans · {threats_neutralized} threats · {safe_pct}% clean</div>"
                f"</div></div></div>", unsafe_allow_html=True
            )
        with hero_col2:
            qa_cols = st.columns(3)
            with qa_cols[0]:
                if st.button("🔍 Analyze", use_container_width=True, key="dash_analyze", help="Scan an email for phishing"):
                    st.session_state["active_tab"] = 0
                    st.rerun()
            with qa_cols[1]:
                if st.button("📥 Inbox", use_container_width=True, key="dash_inbox", help="Scan your email inbox"):
                    st.session_state["active_tab"] = 1
                    st.rerun()
            with qa_cols[2]:
                if st.button("🤖 Copilot", use_container_width=True, key="dash_copilot", help="Ask AI about threats"):
                    st.session_state["active_tab"] = 3
                    st.rerun()

        # ── Usage bar + Upgrade callout ────────────────────────────────────────
        q = check_quota(username, plan)
        plan_label = PLANS.get(plan, PLANS["trial"])["label"]
        limit_display = "∞" if plan == "enterprise" else str(q["limit"])
        bar_color = "#ef4444" if q["pct"] >= 90 else "#f59e0b" if q["pct"] >= 70 else "#3b82f6"
        st.markdown(
            f"<div style='background:#111827;border:1px solid #1e293b;border-radius:12px;padding:12px 20px;margin-bottom:16px;display:flex;align-items:center;gap:16px'>"
            f"<span style='color:#94a3b8;font-size:0.8rem;font-weight:600;min-width:50px'>{plan_label}</span>"
            f"<div style='flex:1;height:6px;background:#1e293b;border-radius:100px;overflow:hidden'>"
            f"<div style='width:{min(q['pct'],100)}%;height:100%;background:{bar_color};border-radius:100px'></div></div>"
            f"<span style='color:{bar_color};font-size:0.75rem;font-weight:600;min-width:80px'>{q['used']} / {limit_display}</span>"
            + ("<a href='#' onclick='alert(\"switch to billing tab\")' style='color:#f59e0b;font-size:0.75rem;text-decoration:none;font-weight:600' onclick=''>⬆ Upgrade</a>" if q['pct'] >= 70 else "") +
            "</div>", unsafe_allow_html=True
        )

        # ── Main content: Stats or empty state ─────────────────────────────────
        if not history:
            st.markdown(empty_state(
                "📊",
                "No scan data yet",
                "Run your first phishing analysis to see analytics, trends, and SOC metrics here.",
                "🔍 Analyze an Email",
            ), unsafe_allow_html=True)
            if st.button("🔍 Analyze an Email", key="empty_dash_cta", use_container_width=True):
                st.session_state["active_tab"] = 0
                st.rerun()
        else:
            # ── Metric cards row ─────────────────────────────────────────────
            col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
            col_m1.metric("📊 Total Scans", total_scans)
            col_m2.metric("🎯 Avg Risk Score", f"{avg_score}/100")
            col_m3.metric("🛡 Threats Found", threats_neutralized, delta_color="inverse")
            col_m4.metric("🔴 Critical", critical_count, delta_color="inverse")
            col_m5.metric("✅ Safe %", f"{safe_pct}%")

            st.divider()

            # ── Recent Threats Timeline ──────────────────────────────────────
            st.markdown("#### 🕐 Recent Threats")
            recent = history[:5]
            _sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            for row in recent:
                ts, sc, sev, kw, su, preview = row
                emoji = _sev_emoji.get(sev, "⚪")
                color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(sev, "#94a3b8")
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e293b;border-radius:10px;"
                    f"padding:10px 14px;margin:4px 0;display:flex;align-items:center;gap:12px'>"
                    f"<span style='font-size:1.2rem'>{emoji}</span>"
                    f"<div style='flex:1'>"
                    f"<span style='color:{color};font-weight:600;font-size:0.85rem'>{sev}</span>"
                    f"<span style='color:#64748b;font-size:0.8rem;margin-left:8px'>Score {sc}/100</span>"
                    f"</div>"
                    f"<div style='color:#475569;font-size:0.75rem'>{ts[:16]}</div>"
                    f"<code style='color:#64748b;font-size:0.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{preview[:40]}</code>"
                    f"</div>", unsafe_allow_html=True
                )

            st.divider()

            # ── Weekly Digest ──────────────────────────────────────────────
            st.markdown("#### 📬 7-Day Summary")
            def _is_recent(ts: str, days: int = 7) -> bool:
                try:
                    return (datetime.now() - datetime.strptime(ts[:10], "%Y-%m-%d")).days < days
                except (ValueError, IndexError):
                    return False
            weekly_scores = [row[1] for row in history if _is_recent(row[0])] if history else []
            if weekly_scores:
                w_total = len(weekly_scores)
                w_crit = sum(1 for row in history if row[2] == "CRITICAL" and _is_recent(row[0]))
                w_high = sum(1 for row in history if row[2] == "HIGH" and _is_recent(row[0]))
                w_avg = round(sum(weekly_scores) / w_total, 1)
                w_col1, w_col2, w_col3, w_col4 = st.columns(4)
                w_col1.metric("7-Day Scans", w_total)
                w_col2.metric("Avg Score", f"{w_avg}/100")
                w_col3.metric("Critical", w_crit, delta_color="inverse")
                w_col4.metric("High", w_high, delta_color="inverse")
            else:
                st.info("No scans in the last 7 days.")

            # ── Advanced section (collapsible) ──────────────────────────────
            with st.expander("📋 Advanced Tools & Data", expanded=False):
                sub_tabs = st.tabs(["📊 SOC Analytics", "📋 Threat Log", "📥 Export Data", "📄 Compliance"])
                with sub_tabs[0]:
                    from src.ui_analytics import render_analytics_tab
                    render_analytics_tab()
                with sub_tabs[1]:
                    st.markdown(f"**Threat Log — Recent {min(total_scans, 50)} Scans**")
                    for row in history[:50]:
                        ts, sc, sev, kw, su, preview = row
                        emoji = _sev_emoji.get(sev, "⚪")
                        st.markdown(f"{emoji} **{sev}** | Score {sc}/100 | {ts[:16]} | KW: {kw} | URLs: {su} | `{preview[:50]}`")
                with sub_tabs[2]:
                    col_ex1, col_ex2, col_ex3 = st.columns(3)
                    with col_ex1:
                        import csv
                        import io
                        out = io.StringIO()
                        w = csv.writer(out)
                        w.writerow(["Timestamp", "Risk Score", "Severity", "Keyword Hits", "Suspicious URLs", "Preview"])
                        w.writerows(history)
                        st.download_button("📥 CSV", out.getvalue(), "phishguard_analytics.csv", "text/csv", use_container_width=True)
                    with col_ex2:
                        import json
                        json_data = json.dumps(
                            [{"timestamp": r[0], "risk_score": r[1], "severity": r[2], "keyword_hits": r[3], "suspicious_urls": r[4], "preview": r[5]} for r in history],
                            indent=2
                        )
                        st.download_button("📥 JSON", json_data, "phishguard_analytics.json", "application/json", use_container_width=True)
                    with col_ex3:
                        last_results = st.session_state.get("results")
                        if last_results:
                            result_json = json.dumps(last_results, indent=2, default=str)
                            st.download_button("📥 Last Analysis", result_json, "phishguard_last_analysis.json", "application/json", use_container_width=True)
                with sub_tabs[3]:
                    st.markdown("**Compliance Reports**")
                    col_cr1, col_cr2 = st.columns(2)
                    with col_cr1:
                        cr_standard = st.selectbox("Standard", ["soc2", "gdpr", "hipaa"], format_func=lambda x: x.upper(), key="cr_standard")
                    with col_cr2:
                        cr_days = st.slider("Period (days)", 7, 365, 90, key="cr_days")
                    whitelabel_enabled = st.checkbox("🔏 White-Label Branding", key="whitelabel_toggle", help="Remove PhishGuard watermarks for client delivery.")
                    if whitelabel_enabled:
                        _has_wl = "white_label" in PLANS.get(plan, {}).get("features", [])
                        if not _has_wl:
                            st.markdown(
                                "<div style='background:linear-gradient(135deg,#1a0a1a,#2a0f2a);border:2px solid #a855f7;"
                                "border-radius:16px;padding:24px 20px;text-align:center;margin:12px 0'>"
                                "<div style='font-size:2rem;margin-bottom:6px'>💼</div>"
                                "<div style='color:#f0f6ff;font-size:1rem;font-weight:700;margin-bottom:4px'>Consultant License Required</div>"
                                "<div style='color:#94a3b8;font-size:0.85rem'>White-label reports are exclusive to the <strong>Consultant License</strong>. Rebrand reports with your own company logo for commercial client delivery.</div>"
                                "</div>", unsafe_allow_html=True
                            )
                    if st.button("📄 Generate Report", type="primary", use_container_width=True):
                        from src.compliance_reports import ComplianceReport
                        with st.spinner(f"Generating {cr_standard.upper()} report..."):
                            report = ComplianceReport(standard=cr_standard, org_name=username, date_range_days=cr_days)
                            pdf_bytes = report.generate()
                        st.session_state["compliance_report"] = pdf_bytes
                        st.session_state["compliance_standard"] = cr_standard
                        st.rerun()
                    if st.session_state.get("compliance_report"):
                        label = "🕊 Download White-Label" if whitelabel_enabled else "📥 Download PDF"
                        st.success(f"{st.session_state['compliance_standard'].upper()} report ready!")
                        st.download_button(label, st.session_state["compliance_report"], f"phishguard_{st.session_state['compliance_standard']}_{datetime.now().strftime('%Y%m%d')}.pdf", "application/pdf", use_container_width=True)


    # ═════════════════════════════════════════════════════════════════════════════
    # TAB 4 — AI COPILOT
    # ═════════════════════════════════════════════════════════════════════════════
with tab4:
    from src.providers import get_available_provider
    _active = get_available_provider()
    _badge = {"groq": "🟢 Groq (free)", "openrouter": "🟢 OpenRouter (free)", "openai": "🟡 OpenAI", "anthropic": "🟡 Anthropic", "none": "🔴 No AI provider"}.get(_active, "🔴 No AI provider")
    st.markdown("## 🤖 AI Security Copilot")
    st.markdown(
        f"<p style='color:#64748b;margin-top:-8px;margin-bottom:24px'>"
        f"Ask anything about phishing, threats, or email security. "
        f"<span style='float:right;font-size:12px;background:#111827;padding:2px 10px;border-radius:12px;border:1px solid #1e3a5f'>{_badge}</span>"
        f"</p>",
        unsafe_allow_html=True
    )

    # Init chat history
    if "copilot_messages" not in st.session_state:
        st.session_state["copilot_messages"] = []

    messages = st.session_state["copilot_messages"]
    current_results = st.session_state.get("results", None)

    # Context banner if analysis exists
    if current_results:
        score    = current_results["risk_score"]
        severity = current_results["severity"]
        color    = current_results["severity_color"]
        st.markdown(
            "<div style='background:#111827;border:1px solid #1e3a5f;"
            "border-radius:10px;padding:10px 16px;margin-bottom:20px;"
            "display:flex;align-items:center;gap:12px'>"
            "<span style='font-size:1.2rem'>📊</span>"
            "<span style='color:#94a3b8;font-size:13px'>"
            "Analysis loaded — Risk Score <strong style='color:" + color + "'>" +
            str(score) + "/100 " + severity + "</strong>. "
            "Copilot has full context.</span>"
            "</div>",
            unsafe_allow_html=True
        )

    # Suggested prompts when chat is empty
    if not messages:
        st.markdown(
            "<p style='color:#475569;font-size:13px;margin-bottom:12px'>"
            "💡 Try one of these:</p>",
            unsafe_allow_html=True
        )
        cols = st.columns(2)
        for i, prompt in enumerate(SUGGESTED_PROMPTS):
            with cols[i % 2]:
                if st.button(prompt, key="sugg_" + str(i), use_container_width=True):
                    st.session_state["copilot_messages"].append(
                        {"role": "user", "content": prompt}
                    )
                    with st.spinner("Copilot is thinking..."):
                        reply = get_copilot_response(
                            st.session_state["copilot_messages"],
                            results=current_results
                        )
                    st.session_state["copilot_messages"].append(
                        {"role": "assistant", "content": reply}
                    )
                    st.rerun()
        st.divider()

    # Render chat history
    for msg in messages:
        role    = msg["role"]
        content = msg["content"]
        if role == "user":
            import html
            st.markdown(
                "<div style='display:flex;justify-content:flex-end;margin:8px 0'>"
                "<div style='background:#1e3a5f;border-radius:14px 14px 2px 14px;"
                "padding:12px 18px;max-width:75%;color:#e2e8f0;font-size:14px'>"
                + html.escape(content) +
                "</div></div>",
                unsafe_allow_html=True
            )
        else:
            import html
            safe_content = html.escape(content)
            st.markdown(
                "<div style='display:flex;justify-content:flex-start;margin:8px 0'>"
                "<div style='background:#111827;border:1px solid #1e3a5f;"
                "border-radius:14px 14px 14px 2px;padding:14px 18px;"
                "max-width:80%;color:#e2e8f0;font-size:14px;line-height:1.6'>"
                + safe_content.replace("\n", "<br>") +
                "</div></div>",
                unsafe_allow_html=True
            )

    # Input area
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    col_input, col_send, col_clear = st.columns([6, 1, 1])
    with col_input:
        user_input = st.text_input(
            "copilot_input", label_visibility="collapsed",
            placeholder="Ask the copilot anything about this threat...",
            key="copilot_text"
        )
    with col_send:
        send_btn = st.button("→ Send", use_container_width=True, type="primary")
    with col_clear:
        if st.button("🗑 Clear", use_container_width=True):
            st.session_state["copilot_messages"] = []
            st.rerun()

    if send_btn and user_input.strip():
        st.session_state["copilot_messages"].append(
            {"role": "user", "content": user_input.strip()}
        )
        with st.spinner("Copilot is thinking..."):
            reply = get_copilot_response(
                st.session_state["copilot_messages"],
                results=current_results
            )
        st.session_state["copilot_messages"].append(
            {"role": "assistant", "content": reply}
        )
        st.rerun()

# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 — ADMIN DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
if is_admin:
    if st.session_state.get("admin_mode", "Dashboard") == "Dashboard":
            with tab5:
                st.markdown("## ⚙ Admin Dashboard")
                st.markdown(
                    "<p style='color:#94a3b8'>Only visible to admin account</p>",
                    unsafe_allow_html=True
                )
                if st.button("🔄 Refresh", key="refresh_admin"):
                    _cached_threats.clear()
                    st.cache_data.clear()
                    st.rerun()

                with st.expander("📊 Founder Analytics", expanded=True):
                    render_founder_analytics()
                st.divider()

                # ── Risk Trend Chart (last 100 analyses) ────────────────────────────
                st.markdown("### 📈 Risk Score Trend")
                try:
                    _aconn = get_connection()
                    _ac = _aconn.cursor()
                    _ac.execute("SELECT risk_score, timestamp FROM analyses ORDER BY id DESC LIMIT 100")
                    _trend_rows = list(reversed(_ac.fetchall()))
                    _aconn.close()
                    if _trend_rows:
                        _scores = [r[0] for r in _trend_rows]
                        _times = [r[1][11:19] if r[1] else str(i) for i, r in enumerate(_trend_rows)]
                        fig_trend = go.Figure(go.Scatter(
                            x=_times, y=_scores, mode="lines+markers",
                            line=dict(color="#60a5fa", width=2),
                            marker=dict(color=_scores, colorscale="RdYlGn_r", size=6),
                            hovertemplate="Score: %{y}<extra></extra>",
                        ))
                        fig_trend.add_hline(y=75, line_dash="dash", line_color="#ff4444",
                                             annotation_text="CRITICAL threshold")
                        fig_trend.add_hline(y=50, line_dash="dash", line_color="#ffaa00",
                                             annotation_text="HIGH threshold")
                        fig_trend.update_layout(
                            height=250, paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                            margin=dict(t=10, b=10, l=10, r=10),
                            xaxis_title="Time", yaxis_title="Risk Score",
                            yaxis=dict(range=[0, 100], gridcolor="#1e3a5f"),
                            xaxis=dict(showgrid=False),
                        )
                        st.plotly_chart(fig_trend, use_container_width=True)
                except Exception:
                    pass

                # ── Top Threats Table ───────────────────────────────────────────────
                col_th1, col_th2 = st.columns(2)
                with col_th1:
                    st.markdown("### 🔥 Top Threats This Month")
                    try:
                        _aconn2 = get_connection()
                        _ac2 = _aconn2.cursor()
                        _ac2.execute(
                            "SELECT email_preview, risk_score, COUNT(*) as cnt FROM analyses "
                            "WHERE timestamp > datetime('now', '-30 days') "
                            "GROUP BY email_preview ORDER BY cnt DESC LIMIT 5"
                        )
                        _top = _ac2.fetchall()
                        _aconn2.close()
                        if _top:
                            for i, (preview, score, cnt) in enumerate(_top, 1):
                                st.markdown(
                                    f"<div style='background:#111827;border:1px solid #1e3a5f;"
                                    f"border-radius:6px;padding:6px 10px;margin:3px 0;font-size:12px'>"
                                    f"<span style='color:#475569'>#{i}</span> "
                                    f"<span style='color:#e2e8f0'>{preview[:50]}</span> "
                                    f"<span style='color:#60a5fa'>×{cnt}</span> "
                                    f"<span style='color:#ff4444'>score {score}</span>"
                                    f"</div>", unsafe_allow_html=True
                                )
                        else:
                            st.info("No data this month.")
                    except Exception:
                        st.info("No data yet.")

                with col_th2:
                    st.markdown("### 📊 Scan Volume by Severity (30d)")
                    try:
                        _aconn3 = get_connection()
                        _ac3 = _aconn3.cursor()
                        _ac3.execute(
                            "SELECT severity, COUNT(*) as cnt FROM analyses "
                            "WHERE timestamp > datetime('now', '-30 days') "
                            "GROUP BY severity ORDER BY CASE severity "
                            "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
                        )
                        _vol = _ac3.fetchall()
                        _aconn3.close()
                        if _vol:
                            _labels = [r[0] for r in _vol]
                            _values = [r[1] for r in _vol]
                            _colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                                       "MEDIUM": "#ffaa00", "LOW": "#44aa44"}
                            _bar_c = [_colors.get(lb, "#60a5fa") for lb in _labels]
                            fig_vol = go.Figure(go.Bar(
                                x=_labels, y=_values, marker_color=_bar_c,
                                text=_values, textposition="outside",
                            ))
                            fig_vol.update_layout(
                                height=250, paper_bgcolor="rgba(0,0,0,0)",
                                plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                                margin=dict(t=10, b=10, l=10, r=10),
                                xaxis=dict(showgrid=False),
                                yaxis=dict(gridcolor="#1e3a5f", title="Count"),
                            )
                            st.plotly_chart(fig_vol, use_container_width=True)
                        else:
                            st.info("No data this month.")
                    except Exception:
                        st.info("No data yet.")

                st.divider()
                st.markdown("### 🚨 Recent Critical & High Threats")
                threats = _cached_threats(10)
                if not threats:
                    st.info("No critical or high threats detected yet.")
                else:
                    for row in threats:
                        ts, sc, sv, kh, su, preview = row
                        with st.expander(f"**{sv}** — Score {sc}/100 — {ts[:16]}"):
                            ca, cb, cc = st.columns(3)
                            ca.metric("Risk Score", sc)
                            cb.metric("Keyword Hits", kh)
                            cc.metric("Suspicious URLs", su)
                            st.markdown(
                                "<div class='url-box' style='color:#94a3b8'>📧 " +
                                preview + "...</div>",
                                unsafe_allow_html=True
                            )

                st.divider()
                col_ref, col_exp = st.columns(2)
                with col_ref:
                    if st.button("🔄 Refresh Dashboard", use_container_width=True):
                        st.rerun()
                with col_exp:
                    all_a = _cached_all_analyses(100)
                    if all_a:
                        import csv
                        import io
                        out = io.StringIO()
                        w = csv.writer(out)
                        w.writerow(["ID", "Timestamp", "Risk Score", "Severity",
                                     "Keyword Hits", "Suspicious URLs", "Preview"])
                        w.writerows(all_a)
                        st.download_button(
                            "📥 Export CSV", out.getvalue(),
                            "phishguard_analyses.csv", "text/csv",
                            use_container_width=True
                        )

                # ── API Gateway Management ──────────────────────────────────────────
                st.divider()
                st.markdown("### 🔐 REST API Gateway")
                st.caption(
                    "Manage API keys for programmatic access. "
                    "Keys grant tier-based rate limits and feature access."
                )

                try:
                    import json
                    from pathlib import Path
                    keys_path = Path(__file__).parent / "api_gateway" / "api_keys.json"
                    if keys_path.exists():
                        with open(keys_path) as f:
                            keys_data = json.load(f)
                        api_keys = keys_data.get("api_keys", [])
                    else:
                        api_keys = []
                except Exception:
                    api_keys = []

                if api_keys:
                    st.markdown("**Registered API Keys:**")
                    for ak in api_keys:
                        key_val = ak.get("key", "")[:16] + "..." if ak.get("key") else ""
                        tier = ak.get("tier", "trial")
                        client = ak.get("client", "unknown")
                        active = ak.get("active", False)
                        dot = "🟢" if active else "🔴"
                        st.markdown(
                            f"<div style='background:#111827;border:1px solid #1e3a5f;"
                            f"border-radius:8px;padding:8px 12px;margin:4px 0;font-size:13px'>"
                            f"{dot} <code>{key_val}</code> · {client} · {tier} tier</div>",
                            unsafe_allow_html=True,
                        )
                else:
                    st.info("No API keys configured. Create `api_gateway/api_keys.json` to enable the REST API.")

                st.markdown("**REST API Endpoints:**")
                base_url = ENV.APP_URL or "https://phishguard.ai"
                st.code(
                    f"# Analyse email via API\n"
                    f"curl -X POST {base_url}/api/v1/scan \\\n"
                    f"  -H \"X-API-Key: your-api-key\" \\\n"
                    f"  -H \"Content-Type: application/json\" \\\n"
                    f"  -d '{{\"text\": \"Suspicious email content...\"}}'\n\n"
                    f"# Health check\n"
                    f"curl {base_url}/health",
                    language="bash",
                )

            # ── Feedback Loop ─────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🔄 Feedback Loop (FP/FN Tracking)")
    st.markdown(
        "<p style='color:#64748b;font-size:13px'>Track false positives and false "
        "negatives to improve detection accuracy over time.</p>",
        unsafe_allow_html=True
    )

    from src.feedback import get_feedback_history, get_feedback_stats, mark_feedback

    fb_stats = get_feedback_stats()
    col_fb1, col_fb2, col_fb3, col_fb4 = st.columns(4)
    with col_fb1:
        st.metric("Total Feedback", fb_stats["total"])
    with col_fb2:
        st.metric("False Positives", fb_stats["false_positives"])
    with col_fb3:
        st.metric("False Negatives", fb_stats["false_negatives"])
    with col_fb4:
        st.metric("Accuracy", f'{fb_stats["accuracy"]}%')

    st.markdown("#### Recent Feedback")
    fb_history = get_feedback_history(50)
    if fb_history:
        import pandas as pd
        df = pd.DataFrame(fb_history)
        st.dataframe(
            df[["id", "email_preview", "user_label", "risk_score", "created_at"]],
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("No feedback recorded yet.")

    st.divider()
    st.markdown("#### Submit Feedback")
    col_fb5, col_fb6, col_fb7 = st.columns([1, 1, 2])
    with col_fb5:
        fb_analysis_id = st.number_input("Analysis ID", min_value=0, step=1, key="fb_aid")
    with col_fb6:
        fb_label = st.selectbox("Label", ["fp", "fn", "correct"], key="fb_label")
    with col_fb7:
        fb_notes = st.text_input("Notes (optional)", key="fb_notes")
    if st.button("💾 Submit Feedback", type="primary", use_container_width=True):
        result = mark_feedback(int(fb_analysis_id), fb_label, fb_notes)
        if result["status"] == "ok":
            st.success(f"Feedback #{result['feedback_id']} recorded!")
            st.rerun()
        else:
            st.error(f"Error: {result.get('error')}")

    if is_admin:
        if st.session_state.get("admin_mode", "Dashboard") == "Dashboard":
            st.divider()
            with st.expander("📋 Task Queue Monitor", expanded=False):
                from src.ui_task_queue import render_task_queue_ui
                render_task_queue_ui()

    # ── A/B Testing ─────────────────────────────────────────────────────
    if is_admin:
        st.divider()
        with st.expander("🔬 A/B Testing", expanded=False):
            st.caption("Run side-by-side detection rule comparisons.")
            from src.ab_testing import ABTest, list_active_tests, promote_variant, stop_test
            col_ab1, col_ab2 = st.columns(2)
            with col_ab1:
                ab_name = st.text_input("Test name", placeholder="keyword_boost_v2", key="ab_name")
            with col_ab2:
                if st.button("➕ Create Test", use_container_width=True) and ab_name:
                    ABTest(ab_name, owner=username, description="Manual A/B test")
                    from src.audit_log import log_action
                    log_action(username, "ab_test_create", detail=f"test={ab_name}")
                    st.success(f"Test '{ab_name}' created")
                    st.rerun()
            active = list_active_tests()
            if active:
                st.markdown("##### Active Tests")
                for t in active:
                    col_t1, col_t2, col_t3, col_t4 = st.columns([2, 1, 1, 1])
                    with col_t1:
                        st.markdown(f"**{t['test_name']}** — {t.get('description', '')[:60]}")
                    with col_t2:
                        if st.button("📊 Results", key=f"ab_res_{t['id']}", use_container_width=True):
                            from src.ab_testing import ABTest
                            _ab = ABTest(t['test_name'])
                            _results = _ab.get_results()
                            st.session_state[f"ab_results_{t['id']}"] = _results
                            st.rerun()
                    with col_t3:
                        if st.button("🏆 Promote Winner", key=f"ab_prom_{t['id']}", use_container_width=True):
                            promote_variant(t['test_name'])
                            from src.audit_log import log_action
                            log_action(username, "ab_test_promote", detail=f"test={t['test_name']}")
                            st.success(f"Winner promoted for '{t['test_name']}'")
                            st.rerun()
                    with col_t4:
                        if st.button("⏹ Stop", key=f"ab_stop_{t['id']}", use_container_width=True):
                            stop_test(t['test_name'])
                            from src.audit_log import log_action
                            log_action(username, "ab_test_stop", detail=f"test={t['test_name']}")
                            st.rerun()
                    _res_key = f"ab_results_{t['id']}"
                    if _res_key in st.session_state and st.session_state[_res_key]:
                        _ab_data = st.session_state[_res_key]
                        if isinstance(_ab_data, list) and _ab_data:
                            st.dataframe(_ab_data, use_container_width=True)
                        elif isinstance(_ab_data, dict) and _ab_data.get("results"):
                            st.json(_ab_data)

    # ── Login Lockout Management ──────────────────────────────────────────
    if is_admin:
        st.divider()
        with st.expander("🔒 Login Lockout Management", expanded=False):
            st.caption("View locked accounts and manually unlock users.")
            from src.tenants import unlock_user
            try:
                _conn = get_connection()
                _c = _conn.cursor()
                _c.execute(
                    "SELECT la.username, COUNT(*), MAX(la.timestamp) "
                    "FROM login_attempts la "
                    "WHERE la.success = 0 AND la.timestamp > ? "
                    "GROUP BY la.username HAVING COUNT(*) >= 5",
                    (time.time() - 900,)
                )
                _locked = _c.fetchall()
                _conn.close()
            except Exception:
                _locked = []
            if _locked:
                st.warning(f"🔒 {len(_locked)} user(s) currently locked out")
                for lu in _locked:
                    _lu_name, _lu_count, _lu_ts = lu
                    _remaining = int(900 - (time.time() - _lu_ts))
                    col_l1, col_l2, col_l3 = st.columns([2, 1, 1])
                    with col_l1:
                        st.markdown(f"**{_lu_name}** — {_lu_count} failed attempts")
                    with col_l2:
                        st.caption(f"Locked {_remaining}s remaining")
                    with col_l3:
                        if st.button("🔓 Unlock", key=f"unlock_{_lu_name}",
                                     use_container_width=True):
                            from src.audit_log import log_action
                            unlock_user(_lu_name)
                            log_action(username, "unlock_user", target=_lu_name,
                                       detail="Manual unlock by admin")
                            st.success(f"Unlocked {_lu_name}")
                            st.rerun()
            else:
                st.success("No users currently locked out")

        # ── Audit Log ─────────────────────────────────────────────────────
        st.divider()
        with st.expander("📋 Audit Log", expanded=False):
            st.caption("Track all admin actions for compliance and forensics.")
            from src.audit_log import get_audit_log, log_action
            audit_rows = get_audit_log(limit=200)
            if not audit_rows:
                st.info("No audit events recorded yet.")
            else:
                for a_row in audit_rows:
                    st.markdown(
                        f"<div style='background:#111827;border:1px solid #1e3a5f;"
                        f"border-radius:6px;padding:6px 10px;margin:3px 0;font-size:12px'>"
                        f"<span style='color:#475569;font-family:monospace'>{a_row['timestamp'][:19]}</span> "
                        f"<span style='color:#60a5fa'>{a_row['actor']}</span> "
                        f"<span style='color:#e2e8f0'>→ {a_row['action']}</span>"
                        f"{(' · <span style=color:#94a3b8>' + a_row['target'] + '</span>') if a_row['target'] else ''}"
                        f"</div>",
                        unsafe_allow_html=True
                    )

        # ── Workspace / RBAC Management ────────────────────────────────────
        st.divider()
        with st.expander("🏢 Workspace & RBAC", expanded=False):
            st.caption("Manage workspaces (orgs) and team member roles.")
            ws_list = list_workspaces(username)
            if not ws_list:
                st.info("You are not a member of any workspace yet.")
                with st.form("create_ws_form"):
                    ws_name = st.text_input("Workspace name", placeholder="Acme Corp")
                    if st.form_submit_button("➕ Create Workspace", type="primary"):
                        if ws_name:
                            r = create_workspace(ws_name, username)
                            if r["success"]:
                                from src.audit_log import log_action
                                log_action(username, "workspace_create", detail=f"workspace={ws_name}")
                                st.success(f"Workspace '{ws_name}' created!")
                                st.rerun()
                            else:
                                st.error(r.get("error", "Creation failed"))
                        else:
                            st.warning("Enter a name.")
            else:
                for ws in ws_list:
                    with st.container():
                        st.markdown(f"**{ws['name']}** — your role: `{ws['role']}`")
                        if ws["role"] in ("admin",):
                            members = get_members(ws["id"])
                            if members:
                                st.markdown("**Members:**")
                                for m in members:
                                    st.markdown(
                                        f"<div style='background:#111827;border:1px solid #1e3a5f;"
                                        f"border-radius:6px;padding:4px 8px;margin:2px 0;font-size:12px'>"
                                        f"<b>{m['username']}</b> — {m['role']} "
                                        f"<span style='color:#475569'>(by {m['invited_by']})</span>"
                                        f"</div>", unsafe_allow_html=True
                                    )
                                    if m["username"] != username:
                                        if st.button(f"🗑 Remove {m['username']}",
                                                     key=f"rm_{ws['id']}_{m['username']}",
                                                     use_container_width=True):
                                            remove_member(ws["id"], m["username"])
                                            from src.audit_log import log_action
                                            log_action(username, "workspace_remove_member",
                                                       detail=f"workspace_id={ws['id']},target={m['username']}")
                                            st.rerun()
                            with st.form(f"invite_{ws['id']}"):
                                invite_user = st.text_input("Username to invite",
                                                              placeholder="johndoe")
                                invite_role = st.selectbox("Role", ["viewer", "analyst", "admin"])
                                if st.form_submit_button("📨 Invite", type="primary"):
                                    if invite_user:
                                        r = invite_member(ws["id"], invite_user, invite_role, username)
                                        if r["success"]:
                                            from src.audit_log import log_action
                                            log_action(username, "workspace_invite",
                                                       detail=f"workspace_id={ws['id']},target={invite_user},role={invite_role}")
                                            st.success(f"Invited {invite_user} as {invite_role}")
                                            st.rerun()
                                        else:
                                            st.error(r.get("error", "Invite failed"))
                                    else:
                                        st.warning("Enter a username.")

        # ── Plugin Manager ──────────────────────────────────────────────────
        st.divider()
        from src.ui_plugins import render_plugin_manager_ui
        render_plugin_manager_ui()

        # ── Bulk User Import/Export ────────────────────────────────────────
        st.divider()
        from src.ui_bulk_users import render_bulk_users_ui
        render_bulk_users_ui()

        # ── System Health ────────────────────────────────────────────────────
        st.divider()
        from src.ui_health import render_health_ui
        render_health_ui()

if is_admin:
    if st.session_state.get("admin_mode", "Dashboard") == "Team":
            with tab6:
                st.markdown("## 👥 Client Management")
                st.divider()

                # Usage overview
                st.markdown("### 📊 This Month's Usage")
                usage_rows = get_usage_all_tenants()
                if usage_rows:
                    for row in usage_rows:
                        uname, uplan, uemail, uactive, uanalyses = row
                        plan_info = PLANS.get(uplan, PLANS["trial"])
                        ulimit    = plan_info["analyses_per_month"]
                        upct      = min(100, int(uanalyses / ulimit * 100)) if ulimit < 99999 else 0
                        ubar_c    = "#ff4444" if upct >= 90 else "#ffaa00" if upct >= 70 else "#60a5fa"
                        udisplay  = "∞" if uplan == "enterprise" else str(ulimit)
                        dot       = "🟢" if uactive else "🔴"
                        st.markdown(
                            "<div style='background:#111827;border:1px solid #1e3a5f;"
                            "border-radius:10px;padding:12px 16px;margin:6px 0'>"
                            "<div style='display:flex;justify-content:space-between;margin-bottom:6px'>"
                            "<span style='color:#e2e8f0;font-weight:500'>" + dot + " " + uname + "</span>"
                            "<span style='color:#94a3b8;font-size:12px'>" +
                            plan_info["label"] + " · " + (uemail or "no email") + "</span>"
                            "<span style='color:#94a3b8;font-size:12px'>" +
                            str(uanalyses) + " / " + udisplay + " analyses</span>"
                            "</div>"
                            "<div style='background:#1e3a5f;border-radius:4px;height:6px'>"
                            "<div style='background:" + ubar_c + ";border-radius:4px;height:6px;"
                            "width:" + str(upct) + "%'></div>"
                            "</div></div>",
                            unsafe_allow_html=True
                        )

                st.divider()

                # Add new client
                st.markdown("### ➕ Add New Client")
                with st.form("add_client_form"):
                    nc1, nc2 = st.columns(2)
                    new_username = nc1.text_input("Username")
                    new_password = nc2.text_input("Password", type="password")
                    nc3, nc4 = st.columns(2)
                    new_email = nc3.text_input("Email (optional)")
                    new_plan  = nc4.selectbox(
                        "Plan", list(PLANS.keys()),
                        format_func=lambda k: PLANS[k]["label"] + " — " + PLANS[k]["price"]
                    )
                    new_notes = st.text_input(
                        "Notes (optional)",
                        placeholder="Company name, contract ref..."
                    )
                    if st.form_submit_button("✅ Create Client", type="primary"):
                        if new_username and new_password:
                            ok = create_tenant(
                                new_username, new_password, new_email,
                                new_plan, notes=new_notes
                            )
                            if ok:
                                from src.audit_log import log_action
                                log_action(username, "create_user", target=new_username,
                                           detail=f"plan={new_plan}")
                                # Send verification email if email provided
                                if new_email:
                                    try:
                                        from src.email_verify import (
                                            create_verification,
                                            send_verification_email,
                                        )
                                        base = ENV.APP_URL or st.secrets.get("base_url", "http://localhost:8501")
                                        vt = create_verification(new_username, new_email)
                                        send_verification_email(new_email, f"{base}/?verify={vt['token']}")
                                    except Exception:
                                        pass
                                st.success(
                                    f'Client "{new_username}" created on '
                                    f'{PLANS[new_plan]["label"]} plan.'
                                )
                                st.rerun()
                            else:
                                st.error(f'Username "{new_username}" already exists.')
                        else:
                            st.warning("Username and password are required.")

                st.divider()

                # Manage existing clients
                st.markdown("### 🛠 Manage Existing Clients")
                tenants = get_all_tenants()
                for row in tenants:
                    tid, uname, uemail, uplan, uactive, uadmin, ucreated, unotes = row
                    if uname == username:
                        continue  # don't show self
                    plan_label = PLANS.get(uplan, PLANS["trial"])["label"]
                    status_str = "🟢 Active" if uactive else "🔴 Suspended"
                    with st.expander(f"**{uname}** — {plan_label} — {status_str}"):
                        m1, m2 = st.columns(2)
                        with m1:
                            st.markdown("**Email:** " + (uemail or "—"))
                            st.markdown("**Created:** " + (ucreated[:10] if ucreated else "—"))
                            st.markdown("**Notes:** " + (unotes or "—"))
                        with m2:
                            plan_keys = list(PLANS.keys())
                            cur_idx   = plan_keys.index(uplan) if uplan in plan_keys else 0
                            new_plan_val = st.selectbox(
                                "Change plan", plan_keys,
                                index=cur_idx,
                                key="plan_" + uname,
                                format_func=lambda k: PLANS[k]["label"]
                            )
                            if st.button("💾 Save Plan", key="save_" + uname):
                                from src.audit_log import log_action
                                update_tenant(uname, plan=new_plan_val)
                                log_action(username, "change_plan", target=uname,
                                           detail=f"{uplan} → {new_plan_val}")
                                st.success(f'Plan updated to {PLANS[new_plan_val]["label"]}')
                                st.rerun()

                            new_pw = st.text_input(
                                "New password", type="password",
                                key="pw_" + uname
                            )
                            if st.button("🔑 Reset Password", key="rpw_" + uname):
                                if new_pw:
                                    from src.audit_log import log_action
                                    set_password(uname, new_pw)
                                    log_action(username, "reset_password", target=uname)
                                    st.success("Password updated.")
                                else:
                                    st.warning("Enter a new password first.")

                        b1, b2, b3 = st.columns(3)
                        if uactive:
                            if b1.button("⏸ Suspend", key="sus_" + uname):
                                from src.audit_log import log_action
                                update_tenant(uname, is_active=0)
                                log_action(username, "suspend_user", target=uname)
                                st.warning(f"{uname} suspended.")
                                st.rerun()
                        else:
                            if b1.button("▶ Reactivate", key="act_" + uname):
                                from src.audit_log import log_action
                                update_tenant(uname, is_active=1)
                                log_action(username, "reactivate_user", target=uname)
                                st.success(f"{uname} reactivated.")
                                st.rerun()
                        if b3.button("🗑 Delete", key="del_" + uname):
                            from src.audit_log import log_action
                            delete_tenant(uname)
                            log_action(username, "delete_user", target=uname)
                            st.error(f"{uname} deleted.")
                            st.rerun()

                st.divider()
                st.markdown("### 📬 Recent Alert History")
                alert_rows = get_alert_log(limit=30)
                if not alert_rows:
                    st.info("No alerts sent yet. Alerts fire automatically when a HIGH or CRITICAL threat is detected for a client with an email address set.")
                else:
                    for ar in alert_rows:
                        al_user, al_email, al_subject, al_sev, al_score, al_sent, al_ok = ar
                        dot = "🟢" if al_ok else "🔴"
                        sev_color = "#ff4444" if al_sev == "CRITICAL" else "#ff8800"
                        st.markdown(
                            "<div style=\'background:#111827;border:1px solid #1e3a5f;"
                            "border-radius:10px;padding:12px 16px;margin:4px 0;"
                            "display:flex;justify-content:space-between;align-items:center\'>"
                            "<span style=\'color:#e2e8f0\'>" + dot + " <b>" + al_user + "</b> → " + al_email + "</span>"
                            "<span style=\'color:" + sev_color + ";font-size:12px;font-weight:700\'>" + al_sev + " " + str(al_score) + "/100</span>"
                            "<span style=\'color:#475569;font-size:11px;font-family:monospace\'>" + al_sent[:16] + "</span>"
                            "</div>",
                            unsafe_allow_html=True
                        )

        # ═════════════════════════════════════════════════════════════════════════════
        # TAB 6/4 — BILLING & SUBSCRIPTION
        # ═════════════════════════════════════════════════════════════════════════════
with billing_tab:
    st.markdown("## 💳 Billing & Subscription")
    st.divider()

    plan_info = PLANS.get(plan, PLANS["trial"])
    q = check_quota(username, plan)

    # ── Current Plan + Subscription Status Card ───────────────────────────
    # Try both old (Paddle) and new (billing service) subscription lookups
    sub = paddle_get_local_subscription(username)
    if not sub and billing_service:
        _bsub = billing_service.get_user_subscription(username)
        if _bsub:
            sub = {
                "subscription_id": _bsub.provider_subscription_id,
                "plan": _bsub.plan_name,
                "status": _bsub.status,
                "billing_cycle": _bsub.billing_cycle,
                "next_billed_at": _bsub.next_billing_date or "",
                "billing_provider": _bsub.billing_provider,
            }
    paddle_avail = paddle_configured()
    gumroad_avail = gumroad_configured()

    status_tag = ""
    status_color = "#22c55e"
    if sub:
        s = sub.get("status", "")
        if s == "active":
            status_tag = "🟢 Active"
        elif s == "cancelled":
            status_tag = "⏹ Cancelled"
            status_color = "#ef4444"
        elif s == "expired":
            status_tag = "⏹ Expired"
            status_color = "#ef4444"
        elif s == "refunded":
            status_tag = "🔴 Refunded"
            status_color = "#ef4444"
        elif s == "past_due":
            status_tag = "🔴 Past Due"
            status_color = "#ef4444"
        else:
            status_tag = s.capitalize()

    bar_color = "#3b82f6" if q["pct"] < 70 else "#f59e0b" if q["pct"] < 90 else "#ef4444"

    billing_provider_label = "Gumroad" if gumroad_avail else ("Paddle" if paddle_avail else "")

    st.markdown(
        "<div style='background:linear-gradient(135deg,#0f172a,#1a1f2e);"
        "border:1px solid #1e3a5f;border-radius:16px;padding:28px 32px;margin-bottom:20px'>"
        "<div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px'>"
        "<div>"
        "<div style='color:#64748b;font-size:0.7rem;text-transform:uppercase;"
        "letter-spacing:0.1em;margin-bottom:2px'>Current Plan"
        + (f" · via {billing_provider_label}" if billing_provider_label else "")
        + "</div>"
        "<div style='color:#f0f6ff;font-size:2rem;font-weight:800'>"
        + plan_info["label"] + "</div>"
        "<div style='color:#94a3b8;font-size:1rem;margin-top:2px'>"
        + plan_info["price"] + "</div>"
        "</div>"
        "<div style='text-align:right;min-width:180px'>"
        + (f"<div style='color:{status_color};font-size:0.85rem;font-weight:600;margin-bottom:6px'>{status_tag}</div>"
           if status_tag else "")
        + "<div style='color:#94a3b8;font-size:0.85rem;margin-bottom:4px'>"
        + str(q["usage"]) + " / " + str(q["limit"]) + " analyses this month</div>"
        f"<div style='background:#1e3a5f;border-radius:4px;height:8px;width:160px;margin:0 0 4px auto'>"
        f"<div style='background:{bar_color};border-radius:4px;height:8px;width:"
        + str(min(q["pct"], 100)) + "%'></div></div>"
        + (f"<div style='color:{bar_color};font-size:0.75rem;font-weight:600'>{q['pct']}% used"
           + (" · <span style='color:#f59e0b'>⬆ <a href='#upgrade-options' style='color:#f59e0b;text-decoration:none'>Upgrade</a></span>"
              if q["pct"] >= 70 else "")
           + "</div>" if plan != "enterprise" else "<div style='color:#22c55e;font-size:0.75rem'>Unlimited</div>")
        + "</div></div>"
        + (f"<div style='color:#64748b;font-size:0.75rem;margin-top:12px;border-top:1px solid #1e293b;padding-top:10px'>"
           f"Subscription ID: <code style='color:#94a3b8'>{sub['subscription_id']}</code>"
           + (f" · Billing cycle: <strong>{sub.get('billing_cycle', 'N/A')}</strong>" if sub.get('billing_cycle') else "")
           + (f" · Next billing: <strong>{sub.get('next_billed_at', 'N/A')}</strong>" if sub.get('next_billed_at') else "")
           + "</div>" if sub and sub.get('subscription_id') else "")
        + "</div>",
        unsafe_allow_html=True
    )

    # ── Subscription Management Actions ───────────────────────────────────
    if sub and sub.get("subscription_id"):
        sub_id = sub["subscription_id"]
        sub_status = sub.get("status", "")

        # Gumroad cancellation
        if gumroad_avail and billing_service and sub.get("billing_provider") in ("gumroad", ""):
            col_m1, col_m2 = st.columns([1, 1])
            with col_m1:
                if sub_status == "active" and st.button("⏹ Cancel Subscription", key="gumroad_cancel", use_container_width=True):
                    ok = billing_service.cancel_subscription(username)
                    if ok:
                        st.success("Subscription cancelled. You retain access until end of billing period.")
                        st.rerun()
                    else:
                        st.error("Failed to cancel. Please contact support.")
            with col_m2:
                if st.button("🔧 Manage on Gumroad", use_container_width=True):
                    st.info("Visit gumroad.com to manage your subscription.")
        elif paddle_avail:
            if sub_id.startswith("sub_"):
                remote = get_subscription(sub_id) if paddle_avail else None
                if remote:
                    sub_status = remote.get("status", sub_status)

                col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                with col_m1:
                    if sub_status == "active" and st.button("⏸ Pause", key="sub_pause", use_container_width=True):
                        if pause_subscription(sub_id):
                            st.success("Subscription paused.")
                            st.rerun()
                        else:
                            st.error("Failed to pause subscription.")
                with col_m2:
                    if sub_status == "paused" and st.button("▶ Resume", key="sub_resume", use_container_width=True):
                        if resume_subscription(sub_id):
                            st.success("Subscription resumed.")
                            st.rerun()
                        else:
                            st.error("Failed to resume subscription.")
                with col_m3:
                    if sub_status not in ("cancelled",) and st.button("⏹ Cancel", key="sub_cancel", use_container_width=True):
                        if cancel_subscription(sub_id):
                            st.success("Subscription cancelled. You retain access until end of billing period.")
                            st.rerun()
                        else:
                            st.error("Failed to cancel subscription.")
                with col_m4:
                    if paddle_avail and remote and remote.get("customer_id"):
                        portal_url = get_customer_portal_url(remote["customer_id"])
                        if portal_url:
                            st.link_button("🔧 Manage Billing", portal_url, use_container_width=True)

        # ── Plan Change ────────────────────────────────────────────────────
        if sub_status == "active":
            st.markdown("#### Change Plan")
            plans_for_change = [p for p in ("starter", "business", "consultant") if p != plan and get_price_id(p)]
            if plans_for_change:
                cols_change = st.columns(len(plans_for_change))
                for ci, pkey in enumerate(plans_for_change):
                    with cols_change[ci]:
                        if st.button(f"Switch to {PLANS[pkey]['label']} ({PLANS[pkey]['price']})",
                                     key=f"change_{pkey}", use_container_width=True):
                            if update_subscription_plan(sub_id, pkey):
                                st.success(f"Plan changed to {PLANS[pkey]['label']}!")
                                st.rerun()
                            else:
                                st.error("Failed to change plan.")

        # ── Invoice History ────────────────────────────────────────────────
        if remote and remote.get("customer_id"):
            st.divider()
            st.markdown("### 📄 Invoice History")
            invoices = get_invoices(remote["customer_id"])
            if invoices:
                for inv in invoices:
                    inv_total_str = str(inv.get("total") or "0")
                    inv_total = int(inv_total_str) / 100 if inv_total_str.isdigit() else inv_total_str
                    st.markdown(
                        f"<div style='background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;"
                        f"padding:10px 16px;margin:4px 0;font-size:13px;display:flex;justify-content:space-between'>"
                        f"<span style='color:#94a3b8'>{inv.get('number', inv['id'][:12])}</span>"
                        f"<span style='color:#22c55e;font-weight:600'>{inv_total} {inv['currency']}</span>"
                        f"<span style='color:#475569'>{inv.get('paid_at', '')[:10]}</span>"
                        + (f"<a href='{inv['invoice_url']}' target='_blank' style='color:#60a5fa'>PDF</a>"
                           if inv.get('invoice_url') else "")
                        + "</div>",
                        unsafe_allow_html=True
                    )
            else:
                st.caption("No invoices yet.")

    # ── Per-Mailbox Pricing Calculator ─────────────────────────────────────
    st.markdown("<div class='section-title'>📬 Per-Mailbox Pricing Calculator</div>",
                unsafe_allow_html=True)
    _mb = st.slider("Number of mailboxes / users", 5, 5000, 50, key="mb_slider")
    if _mb <= 200:
        _rate = 4.00
        _tier_label = "Business"
    elif _mb <= 2000:
        _rate = 3.25
        _tier_label = "Business+"
    else:
        _rate = 2.50
        _tier_label = "Enterprise"
    _monthly = _mb * _rate
    _annual = _monthly * 12
    st.markdown(
        f"<div style='background:linear-gradient(135deg,#0a1628,#0f1f3d);"
        f"border:1px solid #3b82f644;border-radius:14px;padding:20px 24px;margin-bottom:20px'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center'>"
        f"<div>"
        f"<div style='color:#94a3b8;font-size:12px'>Tier</div>"
        f"<div style='color:#f0f6ff;font-size:1.2rem;font-weight:700'>{_tier_label}</div>"
        f"<div style='color:#60a5fa;font-size:0.85rem'>${_rate:.2f}/mailbox/mo</div>"
        f"</div>"
        f"<div style='text-align:right'>"
        f"<div style='color:#94a3b8;font-size:12px'>Monthly Invoice</div>"
        f"<div style='color:#22c55e;font-size:2rem;font-weight:800'>${_monthly:,.2f}</div>"
        f"<div style='color:#475569;font-size:0.75rem'>${_annual:,.2f}/year</div>"
        f"</div></div></div>",
        unsafe_allow_html=True
    )
    st.caption(f"Rate: ${_rate:.2f}/mailbox/mo × {_mb} mailboxes = ${_monthly:,.2f}/mo")

    # ── API Prepaid Credits Overage ────────────────────────────────────────
    quota_status = check_scan_quota(username)
    st.markdown("<div class='section-title'>⛽ API Prepaid Credits</div>",
                unsafe_allow_html=True)
    col_cr1, col_cr2, col_cr3 = st.columns(3)
    with col_cr1:
        st.metric("Daily API Calls Used", quota_status.get("used", 0), help="API calls today")
    with col_cr2:
        st.metric("Daily Limit", quota_status.get("limit", 100), help="Your daily API quota")
    with col_cr3:
        remaining = max(0, quota_status.get("limit", 100) - quota_status.get("used", 0))
        st.metric("Remaining", remaining, delta_color="inverse")
    _top_up = st.number_input("Purchase prepaid credits (1,000 credits = $49)", min_value=0, max_value=10000, step=1000, value=0, key="credit_topup")
    if _top_up > 0 and st.button(f"💳 Purchase {_top_up:,} Credits for ${_top_up//1000*49:,}", key="buy_credits_btn"):
        from src.database import buy_credits
        buy_credits(username, _top_up)
        st.success(f"✅ {_top_up:,} credits added to your account!")
        st.rerun()

    if plan == "enterprise":
        st.success("🌟 You are on the **Enterprise** plan — unlimited analyses, all features enabled.")
    else:
        # ── Smart upgrade suggestion ──────────────────────────────────────────
        if q["pct"] >= 70:
            tier_order = ["starter", "business", "consultant", "enterprise"]
            plan_keys = [p for p in tier_order if PLANS[p]["analyses_per_month"] > PLANS[plan]["analyses_per_month"]]
            if plan_keys:
                suggested = plan_keys[0]
                st.info(
                    f"💡 **You've used {q['pct']}% of your {plan_info['label']} quota.** "
                    f"Consider upgrading to **{PLANS[suggested]['label']}** "
                    f"({PLANS[suggested]['analyses_per_month']} analyses/mo) "
                    f"for only **{PLANS[suggested]['price']}**."
                )

        st.markdown("<div id='upgrade-options'></div>", unsafe_allow_html=True)

        # ── Plan comparison table ─────────────────────────────────────────────
        from src.billing.config import get_plan as _cmp_get_plan
        plan_keys = ["starter", "business", "consultant", "enterprise"]
        upgrade_options = []
        for pkey in plan_keys:
            pcfg = _cmp_get_plan(pkey)
            if pcfg:
                upgrade_options.append(
                    (pkey, pcfg.label,
                     f"${pcfg.price_monthly}/mo", f"${pcfg.price_yearly}/yr",
                     pcfg.features)
                )
            else:
                upgrade_options.append((pkey, pkey.capitalize(), "—", "—", []))

        annual_pricing = st.checkbox("Show annual pricing (save ~17%)", key="annual_toggle",
                                     help="Annual plans billed yearly at ~10 months' cost")

        upgrade_cols = st.columns(len(upgrade_options))
        for i, (pkey, plabel, pprice, pannual, pfeatures) in enumerate(upgrade_options):
            with upgrade_cols[i]:
                featured = pkey == "business"
                already_on = plan == pkey
                border_style = "2px solid #3b82f6" if featured else "1px solid rgba(255,255,255,0.08)"
                bg = "linear-gradient(160deg, #040f24, #071530)" if featured else "#0f172a"
                display_price = pannual if annual_pricing else pprice
                price_suffix = "/yr" if annual_pricing else "/mo"
                st.markdown(
                    "<div style='background:" + bg + ";border:" + border_style + ";"
                    "border-radius:16px;padding:24px 16px;text-align:center;"
                    "height:300px;position:relative'>"
                    + ("<div style='position:absolute;top:-10px;left:50%;transform:translateX(-50%);"
                       "background:#3b82f6;color:#020818;font-size:9px;font-weight:700;"
                       "padding:3px 14px;border-radius:100px'>BEST VALUE</div>" if featured else "")
                    + "<div style='color:#94a3b8;font-weight:600;margin-bottom:6px'>" + plabel + "</div>"
                    + "<div style='color:#f0f6ff;font-size:1.8rem;font-weight:800;margin-bottom:2px'>" + display_price + "</div>"
                    + "<div style='color:#475569;font-size:0.65rem;margin-bottom:14px'>" + price_suffix + "</div>"
                    + "".join("<div style='color:#94a3b8;font-size:0.75rem;padding:3px 0'>→ " + f + "</div>" for f in pfeatures)
                    + "</div>",
                    unsafe_allow_html=True
                )
                if already_on:
                    st.success("✅ Current Plan")
                elif pkey == "enterprise":
                    if st.button("📞 Contact Sales", key="bill_contact_" + pkey, use_container_width=True):
                        st.session_state["show_upgrade"] = True
                        st.rerun()
                else:
                    if st.button("⬆ Upgrade", key="bill_up_" + pkey, use_container_width=True):
                        st.session_state["show_upgrade"] = True
                        st.rerun()

    # ── B2B Enterprise Gateway ──────────────────────────────────────────────
    st.divider()
    st.markdown("<div class='section-title'>🔐 B2B Enterprise Gateway</div>",
                unsafe_allow_html=True)
    tier_cfg = get_tier_config(plan)
    features_list = tier_cfg.get("features", [])
    st.markdown(
        f"**Tier:** `{plan}` | **Plan label:** {tier_cfg['label']} | "
        f"**Rate limit:** {tier_cfg['rate_per_minute']} req/min | "
        f"**Concurrent:** {tier_cfg['concurrent_sessions']} sessions | "
        f"**Monthly quota:** {tier_cfg['scans_per_month']}"
    )
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        st.markdown("**Feature access:**")
        all_features = ["basic_scan", "threat_intel", "osint", "ai_report",
                        "pdf_export", "email_alerts", "api_access",
                        "team_access", "priority_support", "white_label",
                        "sla", "custom_integration"]
        for feat in all_features:
            allowed = feat in features_list
            icon = "✅" if allowed else "❌"
            st.markdown(f"{icon} `{feat}`")
    with col_b2:
        st.markdown("**Rate limit simulation:**")
        mock_gw = MockAPIGateway()
        mock_gw.register_key("demo_key", username, plan)
        result = mock_gw.call_endpoint("demo_key", "/v1/analyze")
        st.code(f"Mock API /v1/analyze → code={result.get('code', 'N/A')} | "
                f"status={result.get('status', 'N/A')} | "
                f"{result.get('message', '')}",
                language="text")
        if result.get("code") == 429:
            st.warning("⛔ Rate limit hit! Upgrade or wait for window reset.")
        elif result.get("code") == 403:
            st.warning("⛔ Feature not available on current plan.")
        else:
            st.info("✅ Gateway healthy — within rate limits.")

    # ── API Key Management ─────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🔑 API Key Management")
    st.markdown(
        "<p style='color:#64748b;font-size:13px'>Generate and manage X-PhishGuard-Key "
        "credentials for programmatic access to the API proxy.</p>",
        unsafe_allow_html=True
    )

    from src.api_keys import delete_api_key, generate_api_key, init_api_keys_table
    init_api_keys_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, key_prefix, tier, is_active, created_at, last_used FROM api_keys WHERE username = ? ORDER BY id DESC", (username,))
    user_keys = c.fetchall()
    conn.close()

    if user_keys:
        st.markdown("**Your API Keys:**")
        for k_row in user_keys:
            kid, kprefix, ktier, kactive, kcreated, klast = k_row
            status = "🟢 Active" if kactive else "🔴 Revoked"
            last_used_str = klast[:19] if klast else "Never"
            col_k0, col_k1, col_k2, col_k3, col_k4 = st.columns([2, 2, 1, 1, 1])
            col_k0.code(f"{kprefix}...", language="text")
            col_k1.caption(f"Last used: {last_used_str}")
            col_k2.markdown(f"`{ktier}`")
            col_k3.markdown(status)
            if col_k4.button("🗑 Revoke", key=f"revoke_{kid}"):
                from src.audit_log import log_action
                conn2 = get_connection()
                c2 = conn2.cursor()
                c2.execute("SELECT key_hash FROM api_keys WHERE id = ?", (kid,))
                row2 = c2.fetchone()
                conn2.close()
                if row2:
                    delete_api_key(row2[0])
                    log_action(username, "revoke_api_key", detail=f"key_id={kid}")
                st.rerun()
    else:
        st.info("No API keys yet. Generate one below.")
    col_gen, col_tier = st.columns([2, 1])
    with col_gen:
        if st.button("🔑 Generate New API Key", type="primary", use_container_width=True):
            result = generate_api_key(username, plan)
            if "api_key" in result:
                st.session_state["new_api_key"] = result["api_key"]
                st.rerun()
            else:
                st.error(result.get("error", "Failed to generate key"))
    with col_tier:
        st.caption(f"Tier: `{plan}`")

    if st.session_state.get("new_api_key"):
        st.success("Key generated! Copy it now — it won't be shown again.")
        st.code(st.session_state["new_api_key"], language="text")
        if st.button("✅ Done — Clear key from screen"):
            st.session_state.pop("new_api_key", None)
            st.rerun()

    st.divider()
    st.markdown(
        "<p style='color:#475569;font-size:0.8rem;text-align:center'>"
        "Payments processed securely by <strong>Paddle</strong>. "
        "Paddle is the merchant of record for all transactions.<br>"
        "Need help? Contact support.</p>",
        unsafe_allow_html=True
    )

# ═════════════════════════════════════════════════════════════════════════════
# TAB 7/5 — SETTINGS
# ═════════════════════════════════════════════════════════════════════════════
with settings_tab:
    st.markdown("## ⚙ Account Settings")
    st.divider()

    col_s1, col_s2 = st.columns([1, 1])

    with col_s1:
        st.markdown("### 👤 Profile")
        st.markdown(f"**Username:** `{username}`")
        st.markdown(f"**Plan:** {PLANS.get(plan, PLANS['trial'])['label']}")

        st.divider()
        st.markdown("### 📧 Email for Alerts")
        current_email = st.session_state.get("email", "")
        new_email = st.text_input(
            "Email address",
            value=current_email,
            placeholder="you@example.com",
            label_visibility="collapsed",
            key="settings_email"
        )
        if st.button("💾 Save Email", type="primary", use_container_width=True):
            update_tenant(username, email=new_email)
            st.session_state["email"] = new_email
            st.success("✅ Email updated. HIGH/CRITICAL alerts will be sent here.")

        if current_email:
            st.caption(f"Current: {current_email}")
            st.info("💡 Alerts fire automatically when an analysis scores HIGH or CRITICAL.")
        # Email verification status
        try:
            from src.email_verify import (
                create_verification,
                is_email_verified,
                send_verification_email,
            )
            if not is_email_verified(username):
                if current_email:
                    st.warning("📧 Email not verified. Some features are restricted.")
                    if st.button("📨 Resend Verification Email", use_container_width=True):
                        base = ENV.APP_URL or st.secrets.get("base_url", "http://localhost:8501")
                        vt = create_verification(username, current_email)
                        r = send_verification_email(vt["email"], f"{base}/?verify={vt['token']}")
                        if r.get("success"):
                            st.success("Verification email sent!")
                        else:
                            st.error(f"Failed to send: {r.get('error', 'SMTP not configured')}")
                else:
                    st.info("📧 Save an email above to enable email verification.")
        except Exception:
            pass

    with col_s2:
        st.markdown("### 🔑 Security")
        st.markdown("#### Change Password")
        pw1 = st.text_input("New password", type="password", placeholder="Enter new password", key="pw_new", label_visibility="collapsed")
        pw2 = st.text_input("Confirm password", type="password", placeholder="Confirm new password", key="pw_confirm", label_visibility="collapsed")
        if st.button("🔄 Update Password", type="primary", use_container_width=True):
            if not pw1:
                st.warning("Enter a new password.")
            elif pw1 != pw2:
                st.error("Passwords do not match.")
            elif len(pw1) < 6:
                st.warning("Password must be at least 6 characters.")
            else:
                set_password(username, pw1)
                st.success("✅ Password updated successfully.")

        st.divider()
        st.markdown("#### 🔐 Multi-Factor Auth (TOTP)")
        try:
            from src.mfa import disable_mfa, enable_mfa, is_mfa_enabled, setup_mfa
            mfa_enrolled = is_mfa_enabled(username)
            if mfa_enrolled:
                st.success("✅ MFA is enabled on your account.")
                if st.button("🗑 Disable MFA", use_container_width=True):
                    disable_mfa(username)
                    st.rerun()
            else:
                if "mfa_setup_secret" not in st.session_state:
                    if st.button("🔐 Set up MFA", use_container_width=True):
                        mfa_setup = setup_mfa(username)
                        st.session_state["mfa_setup_secret"] = mfa_setup["secret"]
                        st.session_state["mfa_setup_uri"] = mfa_setup["uri"]
                        st.rerun()
                else:
                    secret = st.session_state["mfa_setup_secret"]
                    uri = st.session_state["mfa_setup_uri"]
                    st.markdown(
                        "<div style='background:#0f172a;border:1px solid #1e3a5f;"
                        "border-radius:12px;padding:16px;text-align:center'>"
                        "<p style='color:#94a3b8;font-size:12px'>Scan with Google Authenticator, "
                        "Authy, or any TOTP app</p>",
                        unsafe_allow_html=True
                    )
                    st.code(secret, language="text")
                    st.markdown(
                        "<p style='color:#94a3b8;font-size:12px;text-align:center'>"
                        "Enter this key manually in your authenticator app, or use the URI below.</p>",
                        unsafe_allow_html=True
                    )
                    with st.expander("Show setup URI"):
                        st.code(uri, language="text")
                    verify_code = st.text_input("Enter 6-digit code to verify",
                                                 max_chars=6, label_visibility="collapsed",
                                                 key="mfa_verify_code")
                    col_mfa1, col_mfa2 = st.columns(2)
                    with col_mfa1:
                        if st.button("✅ Verify & Enable", use_container_width=True):
                            if verify_code:
                                if enable_mfa(username, verify_code):
                                    st.session_state.pop("mfa_setup_secret", None)
                                    st.session_state.pop("mfa_setup_uri", None)
                                    st.success("MFA enabled!")
                                    st.rerun()
                                else:
                                    st.error("Invalid code. Try again.")
                            else:
                                st.error("Enter the code from your authenticator app.")
                    with col_mfa2:
                        if st.button("Cancel", use_container_width=True):
                            st.session_state.pop("mfa_setup_secret", None)
                            st.session_state.pop("mfa_setup_uri", None)
                            st.rerun()
        except Exception:
            st.caption("MFA not available (pyotp not installed).")

        st.divider()
        st.markdown("#### Session")
        st.caption(f"Logged in as: **{username}**")
        if st.button("🚪 Logout", use_container_width=True):
            logout()

    st.divider()

    # ── Webhook Configuration ──────────────────────────────────────────────
    st.markdown("### 🔔 Slack / Teams Webhook Notifications")
    st.caption(
        "Configure a webhook URL to receive automated alerts when a scan "
        "scores **85+ (HIGH/CRITICAL)**. Supports Slack Incoming Webhooks and "
        "Microsoft Teams Incoming Webhooks."
    )

    wh_key = f"webhook_url_{username}"
    saved_wh_url = st.session_state.get(wh_key, "")
    webhook_url = st.text_input(
        "Webhook URL",
        value=saved_wh_url,
        placeholder="https://hooks.slack.com/services/... or https://outlook.office.com/webhook/...",
        label_visibility="collapsed",
        key="settings_webhook_url",
    )
    col_wh1, col_wh2 = st.columns([1, 3])
    with col_wh1:
        if st.button("💾 Save Webhook", type="primary", use_container_width=True):
            if webhook_url and not webhook_url.startswith("https://"):
                st.error("Webhook URL must use HTTPS.")
            elif webhook_url and not webhook_url.startswith(("https://hooks.slack.com/", "https://outlook.office.com/webhook/")):
                st.warning("⚠️ Unrecognized webhook provider. Only Slack and Teams are officially supported.")
            else:
                st.session_state[wh_key] = webhook_url
                st.success("Webhook URL saved. Alerts will be sent on HIGH/CRITICAL scans.")
    with col_wh2:
        if webhook_url:
            st.caption(f"Active: {webhook_url[:60]}...")
            if st.button("🔍 Test Webhook", use_container_width=True):
                from src.webhook_gateway import send_alert
                test_result = send_alert(
                    webhook_url,
                    score=95,
                    severity="CRITICAL",
                    triggers=["Urgency", "Authority Impersonation", "Fear"],
                    snippet="This is a test alert from PhishGuard AI at SecOpsNode AI.",
                    action="No action required — this is a test notification.",
                )
                if test_result.get("success"):
                    st.success("✅ Test alert sent successfully!")
                else:
                    st.error(f"Test failed: {test_result.get('error', 'Unknown error')}")

    st.divider()
    st.markdown("### 📬 Recent Alerts Sent to You")
    user_email = st.session_state.get("email", "")
    my_alerts = get_alert_log(username=username, limit=10) if user_email else []
    if not my_alerts:
        st.info("No alerts sent yet. Alerts are triggered automatically when a HIGH or CRITICAL threat is detected and you have an email saved above.")
    else:
        for ar in my_alerts:
            al_user, al_email, al_subject, al_sev, al_score, al_sent, al_ok = ar
            dot = "🟢" if al_ok else "🔴"
            sev_color = "#ff4444" if al_sev == "CRITICAL" else "#ff8800"
            st.markdown(
                "<div style='background:#111827;border:1px solid #1e3a5f;"
                    "border-radius:10px;padding:12px 16px;margin:4px 0;"
                    "display:flex;justify-content:space-between;align-items:center'>"
                    "<span style='color:#e2e8f0'>" + dot + " " + al_subject[:50] + "</span>"
                    "<span style='color:" + sev_color + ";font-size:12px;font-weight:700'>" + al_sev + " " + str(al_score) + "/100</span>"
                    "<span style='color:#475569;font-size:11px;font-family:monospace'>" + al_sent[:16] + "</span>"
                    "</div>",
                    unsafe_allow_html=True
                )

    # ── Auto-Quarantine Configuration ──────────────────────────────────────
    st.divider()
    st.markdown("### 🛡 Auto-Quarantine Rules")
    st.caption("Automatically flag and track emails above a risk threshold.")
    q_key = f"quarantine_threshold_{username}"
    if q_key not in st.session_state:
        st.session_state[q_key] = 70
    quarantine_threshold = st.slider(
        "Minimum risk score to auto-quarantine",
        min_value=0, max_value=100, value=st.session_state[q_key], step=5,
        key="quarantine_slider",
    )
    st.session_state[q_key] = quarantine_threshold
    st.caption(f"Emails scoring **{quarantine_threshold}+** will be marked with a quarantine badge in results.")
    q_list_key = f"quarantined_{username}"
    quarantined = st.session_state.get(q_list_key, [])
    if quarantined:
        st.markdown(f"**Quarantined emails:** {len(quarantined)}")
        for q in quarantined[-10:]:
            st.markdown(
                f"<div style='background:#2a0a0a;border:1px solid #ff4444;border-radius:8px;"
                f"padding:8px 12px;margin:4px 0;font-size:12px'>"
                f"🔴 Score {q['score']}/100 · {q['preview'][:60]}"
                f"<span style='color:#475569;display:block;font-size:10px'>{q.get('time','')}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
        if st.button("Clear Quarantine List", key="clear_q", use_container_width=True):
            st.session_state[q_list_key] = []
            st.rerun()
    else:
        st.info("No quarantined emails yet. Threshold-based tracking is active.")

    # ── Active Containment & SOAR Gateway ────────────────────────────────────
    st.divider()
    st.markdown("### 🚨 Active Containment & SOAR Gateway")
    _is_ent = plan == "enterprise"
    if not _is_ent:
        st.markdown(
            "<div style='background:#0a0f1a;border:2px solid #eab30844;border-radius:16px;"
            "padding:30px 24px;text-align:center;margin:12px 0'>"
            "<div style='font-size:2.5rem;margin-bottom:8px'>🔒</div>"
            "<div style='color:#f0f6ff;font-size:1.2rem;font-weight:700;margin-bottom:6px'>"
            "Enterprise SOAR Gateway Locked</div>"
            "<div style='color:#94a3b8;font-size:0.9rem;max-width:400px;margin:0 auto 16px auto'>"
            "Isolate compromised endpoints instantly via Active Directory & Cisco API integration. "
            "Upgrade to Enterprise Plan to enable automatic workstation quarantine.</div>"
            "<a href='#billing-tab' style='display:inline-block;"
            "background:linear-gradient(135deg,#eab308,#f59e0b);color:#0a0f1a;"
            "padding:10px 32px;border-radius:10px;text-decoration:none;font-weight:700;"
            "font-size:0.95rem'>⬆ Upgrade to Enterprise</a></div>",
            unsafe_allow_html=True,
        )
    else:
        from src.soar_gateway import (
            broadcast_slack_channel,
            disable_ad_account,
            get_soar_status,
            quarantine_host,
        )
        st.markdown(
            "<div style='background:#0a1628;border:1px solid #22c55e44;border-radius:14px;"
            "padding:18px 22px;margin-bottom:16px'>"
            "<div style='color:#22c55e;font-weight:700;font-size:1rem'>✅ SOAR Gateway Active</div>"
            "<div style='color:#94a3b8;font-size:13px'>Connected: Active Directory | Cisco Firepower | Slack Webhook</div>"
            "</div>",
            unsafe_allow_html=True,
        )
        soar_status = get_soar_status()
        col_s1, col_s2, col_s3 = st.columns(3)
        col_s1.metric("Hosts Quarantined", soar_status["quarantined_hosts"])
        col_s2.metric("AD Accounts Disabled", soar_status["disabled_accounts"])
        col_s3.metric("Alerts Broadcast", soar_status["broadcasts_sent"])

        with st.expander("🛡 Quarantine Host IP via Cisco Firewall", expanded=False):
            q_ip = st.text_input("Target IP address", placeholder="10.0.1.50", key="soar_ip")
            q_reason = st.text_input("Reason", "Phishing threat detected", key="soar_reason")
            if st.button("🚨 Execute Quarantine", type="primary", key="soar_q_btn"):
                with st.spinner("Communicating with Cisco Firepower..."):
                    res = quarantine_host(q_ip, q_reason)
                if res.success:
                    st.success(f"✅ {res.message}")
                    st.caption(f"Duration: {res.duration_ms}ms | ACL: {res.details.get('acl_rule', 'N/A')}")
                else:
                    st.error(f"❌ {res.message}")

        with st.expander("🔐 Disable Account in Active Directory", expanded=False):
            ad_user = st.text_input("AD Username", placeholder="jdoe", key="soar_ad_user")
            ad_domain = st.text_input("Domain", "CORP", key="soar_ad_domain")
            if st.button("🔐 Disable Account", type="primary", key="soar_ad_btn"):
                with st.spinner("Connecting to domain controller..."):
                    res = disable_ad_account(ad_user, ad_domain)
                if res.success:
                    st.success(f"✅ {res.message}")
                    st.caption(f"Duration: {res.duration_ms}ms | DC: {res.details.get('domain_controller', 'N/A')}")
                else:
                    st.error(f"❌ {res.message}")

        with st.expander("📢 Broadcast to SecOps Slack Channel", expanded=False):
            slack_ch = st.text_input("Slack Channel", "#secops-alerts", key="soar_slack_ch")
            slack_msg = st.text_area("Alert Message", "PhishGuard AI: Compromise confirmed — immediate action required.", key="soar_slack_msg")
            if st.button("📢 Send Broadcast", type="primary", key="soar_slack_btn"):
                with st.spinner("Pushing to Slack, PagerDuty, and OpsGenie..."):
                    res = broadcast_slack_channel(slack_ch, slack_msg)
                if res.success:
                    st.success(f"✅ {res.message}")
                    st.caption(f"Duration: {res.duration_ms}ms | Channels: {', '.join(res.details.get('integrations', []))}")
                else:
                    st.error(f"❌ {res.message}")

    # ── IMAP Worker Configuration ───────────────────────────────────────────
    st.divider()
    st.markdown("### 📬 IMAP Auto-Scan Worker")
    st.caption(
        "Configure an IMAP mailbox to automatically scan incoming emails. "
        "The worker fetches unseen messages, runs them through PhishGuard, "
        "and replies with a security verdict."
    )

    if "imap_cfg" not in st.session_state:
        st.session_state["imap_cfg"] = {
            "host": os.getenv("IMAP_HOST", ""),
            "user": os.getenv("IMAP_USER", ""),
            "pass": os.getenv("IMAP_PASS", ""),
        }

    imap_cfg = st.session_state["imap_cfg"]
    col_i1, col_i2, col_i3 = st.columns(3)
    with col_i1:
        imap_cfg["host"] = st.text_input("IMAP Host", value=imap_cfg["host"],
                                          placeholder="imap.example.com",
                                          key="imap_host")
    with col_i2:
        imap_cfg["user"] = st.text_input("IMAP Username", value=imap_cfg["user"],
                                          placeholder="user@example.com",
                                          key="imap_user")
    with col_i3:
        imap_cfg["pass"] = st.text_input("IMAP Password", type="password",
                                          value="********" if imap_cfg["pass"] else "",
                                          placeholder="password",
                                          key="imap_pass")

    if st.button("💾 Save IMAP Config", type="primary", use_container_width=True):
        st.session_state["imap_cfg"] = imap_cfg
        st.success("IMAP config saved to session. Run the worker via `python workers/imap_worker.py`")

    st.markdown("**Worker command:**")
    st.code(
        "# Set env vars and run the IMAP worker\n"
        f"set IMAP_HOST={imap_cfg['host'] or '<host>'}\n"
        f"set IMAP_USER={imap_cfg['user'] or '<user>'}\n"
        f"set IMAP_PASS=<password>\n"
        f"python workers/imap_worker.py",
        language="bash",
    )

    # ── Alerting Configuration ────────────────────────────────────────────
    st.divider()
    st.markdown("### 🔔 Alerting Configuration")
    st.markdown(
        "<p style='color:#64748b;font-size:13px'>Configure real-time alerts "
        "when phishing is detected. Supports Slack, Email, and Webhook.</p>",
        unsafe_allow_html=True
    )

    alert_method = st.selectbox("Alert Method", ["Slack", "Email", "Webhook"], key="alert_method")
    if alert_method == "Slack":
        slack_url = st.text_input("Slack Webhook URL", type="password",
                                  value=os.getenv("SLACK_WEBHOOK_URL", ""),
                                  key="slack_url")
        if st.button("🔔 Test Slack Alert", use_container_width=True):
            from src.alerting import send_slack
            res = send_slack(slack_url, "✅ Test alert from PhishGuard AI")
            if res["status"] == "ok":
                st.success("Slack test sent!")
            else:
                st.error(f"Slack error: {res.get('error')}")
    elif alert_method == "Email":
        col_ae1, col_ae2 = st.columns(2)
        with col_ae1:
            smtp_host = st.text_input("SMTP Host", os.getenv("SMTP_HOST", "smtp.gmail.com"),
                                      key="smtp_host")
            smtp_user = st.text_input("SMTP User", os.getenv("SMTP_USER", ""), key="smtp_user")
        with col_ae2:
            smtp_port = st.number_input("SMTP Port", int(os.getenv("SMTP_PORT", "587")),
                                        key="smtp_port")
            smtp_pass = st.text_input("SMTP Password", type="password", key="smtp_pass")
        alert_recipient = st.text_input("Alert Recipient Email", key="alert_rcpt")
        if st.button("🔔 Test Email Alert", use_container_width=True):
            from src.alerting import send_email
            res = send_email(smtp_host, int(smtp_port), smtp_user, smtp_pass,
                             smtp_user, [alert_recipient],
                             "PhishGuard Test Alert",
                             "This is a test alert from PhishGuard AI.")
            if res["status"] == "ok":
                st.success("Test email sent!")
            else:
                st.error(f"Email error: {res.get('error')}")
    elif alert_method == "Webhook":
        webhook_url = st.text_input("Webhook URL", key="webhook_url")
        if st.button("🔔 Test Webhook", use_container_width=True):
            from src.alerting import send_webhook
            res = send_webhook(webhook_url, {"test": True, "message": "PhishGuard test"})
            if res["status"] == "ok":
                st.success("Webhook test sent!")
            else:
                st.error(f"Webhook error: {res.get('error')}")

    alert_threshold = st.slider("Minimum risk score to trigger alert",
                                 0, 100, 50, key="alert_threshold")
    st.caption(f"Alerts will fire when risk score >= {alert_threshold}")

    # ── Enterprise: Graph API / Gmail OAuth2 Settings ──────────────────────
    st.divider()
    st.markdown("### 🔐 Microsoft Graph API (Replace IMAP Passwords)")
    st.caption("Configure OAuth2 via Microsoft Graph to scan mailboxes without storing IMAP passwords.")
    _graph_key = f"graph_enabled_{username}"
    if _graph_key not in st.session_state:
        st.session_state[_graph_key] = False
    st.checkbox("Enable Graph API scanning", key=_graph_key)
    if st.session_state[_graph_key]:
        _has_graph = bool(ENV.GRAPH_TENANT_ID and ENV.GRAPH_CLIENT_ID)
        if _has_graph:
            st.success("✅ Graph API credentials detected in environment.")
        else:
            st.info("Set GRAPH_TENANT_ID, GRAPH_CLIENT_ID, and GRAPH_CLIENT_SECRET in your .env file.")

    # ── Enterprise: Weekly Report Settings ─────────────────────────────────
    st.divider()
    st.markdown("### 📅 Weekly Security Report")
    st.caption("Receive a weekly PDF summary of threats detected in your organization.")
    _wr_enabled_key = f"weekly_report_enabled_{username}"
    if _wr_enabled_key not in st.session_state:
        st.session_state[_wr_enabled_key] = False
    st.checkbox("Enable weekly email report", key=_wr_enabled_key)
    if st.session_state[_wr_enabled_key] and st.session_state.get("email"):
        st.info(f"✅ Weekly reports will be sent to {st.session_state['email']}")

    # ── Enterprise: SIEM Integration Status ────────────────────────────────
    st.divider()
    st.markdown("### 📡 SIEM Integration")
    _siem_targets = []
    if ENV.SIEM_SPLUNK_HEC_URL:
        _siem_targets.append("Splunk")
    if ENV.SIEM_ELASTIC_CLOUD_ID:
        _siem_targets.append("Elastic")
    if ENV.SIEM_QRAZAR_URL:
        _siem_targets.append("QRadar")
    if _siem_targets:
        st.success(f"✅ SIEM connected: {', '.join(_siem_targets)}")
    else:
        st.info("Set SIEM_* env vars in .env to connect Splunk, Elastic, or QRadar.")

    # ── PWA / Mobile ───────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📱 Mobile App (PWA)")
    st.caption("Install PhishGuard as a mobile app for push notifications.")
    st.markdown(
        "<div style='background:#111827;border:1px solid #1e3a5f;border-radius:10px;"
        "padding:16px;text-align:center'>"
        "<div style='color:#94a3b8;font-size:13px;margin-bottom:8px'>"
        "Open this page in Chrome/Safari and select "
        "<strong>Add to Home Screen</strong> to install.</div>"
        "<div style='color:#475569;font-size:11px'>"
        "Or scan the QR code (coming soon)</div>"
        "</div>", unsafe_allow_html=True
    )

    # ── Custom Detection Rules ──────────────────────────────────────────────
    st.divider()
    st.markdown("### 🧩 Custom Detection Rules")
    st.caption("Add tenant-specific keyword, header, or regex rules to boost risk scores.")
    cr_col1, cr_col2 = st.columns([1, 1])
    with cr_col1:
        with st.form("add_rule_form"):
            cr_name = st.text_input("Rule name", placeholder="Detect competitor domain")
            cr_type = st.selectbox("Type", ["keyword", "header", "regex", "url_pattern"])
            cr_pattern = st.text_input("Pattern", placeholder=r"competitor\.com")
            cr_boost = st.slider("Risk boost", 5, 50, 10, step=5)
            if st.form_submit_button("➕ Add Rule", type="primary"):
                if cr_name and cr_pattern:
                    add_rule(username, cr_name, cr_type, cr_pattern, cr_boost)
                    st.rerun()
                else:
                    st.warning("Name and pattern required.")
    with cr_col2:
        st.markdown("**Your Rules:**")
        rules = list_rules(username)
        if not rules:
            st.info("No custom rules yet.")
        else:
            for r in rules:
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e3a5f;"
                    f"border-radius:6px;padding:4px 8px;margin:2px 0;font-size:12px'>"
                    f"{'🟢' if r['is_active'] else '🔴'} <b>{r['name']}</b> "
                    f"<span style='color:#94a3b8'>({r['rule_type']})</span> "
                    f"<span style='color:#60a5fa'>+{r['risk_boost']}</span>"
                    f"</div>", unsafe_allow_html=True
                )
                tc1, tc2 = st.columns([1, 1])
                with tc1:
                    if st.button("Toggle", key=f"tgl_rule_{r['id']}", use_container_width=True):
                        toggle_rule(r["id"])
                        st.rerun()
                with tc2:
                    if st.button("🗑", key=f"del_rule_{r['id']}", use_container_width=True):
                        remove_rule(r["id"])
                        st.rerun()

    # ── IP Allowlist ────────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🌐 IP Allowlist")
    st.caption("Restrict access to specific IP ranges (CIDR notation). Leave empty to allow all.")
    ip_col1, ip_col2 = st.columns([1, 1])
    with ip_col1:
        with st.form("add_ip_form"):
            ip_cidr = st.text_input("CIDR", placeholder="10.0.0.0/24")
            ip_label = st.text_input("Label", placeholder="Office VPN")
            if st.form_submit_button("➕ Add IP Rule", type="primary"):
                if ip_cidr:
                    try:
                        add_ip_rule(username, ip_cidr, ip_label)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Invalid CIDR: {e}")
                else:
                    st.warning("Enter a CIDR.")
    with ip_col2:
        st.markdown("**Allowlist:**")
        ip_rules = list_ip_rules(username)
        if not ip_rules:
            st.info("No IP restrictions (all IPs allowed).")
        else:
            for ir in ip_rules:
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e3a5f;"
                    f"border-radius:6px;padding:4px 8px;margin:2px 0;font-size:12px'>"
                    f"{ir['cidr']} <span style='color:#94a3b8'>{ir['label']}</span>"
                    f"</div>", unsafe_allow_html=True
                )
                if st.button("🗑 Remove", key=f"del_ip_{ir['id']}", use_container_width=True):
                    remove_ip_rule(ir["id"])
                    st.rerun()

    # ── Data Retention ──────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🗄 Data Retention Policy")
    st.caption("Auto-purge old data after a set number of days.")
    retention = get_retention_policy(username)
    ret_col1, ret_col2, ret_col3 = st.columns(3)
    with ret_col1:
        analysis_days = st.number_input("Analyses (days)", 1, 730, retention["analysis_days"], step=30)
    with ret_col2:
        audit_days = st.number_input("Audit logs (days)", 1, 730, retention["audit_days"], step=30)
    with ret_col3:
        alert_days = st.number_input("Alerts (days)", 1, 730, retention["alert_days"], step=30)
    ret_b1, ret_b2 = st.columns(2)
    with ret_b1:
        if st.button("💾 Save Retention Policy", type="primary", use_container_width=True):
            set_retention_policy(username, int(analysis_days), int(audit_days), int(alert_days))
            st.success("Retention policy updated.")
    with ret_b2:
        if st.button("🗑 Purge Old Data Now", use_container_width=True):
            result = purge_old_data(username)
            if result.get("purged"):
                st.success(f"Purged: {result.get('analyses', 0)} analyses, "
                           f"{result.get('audit', 0)} audit logs, {result.get('alerts', 0)} alerts.")
            else:
                st.info("Nothing to purge or policy disabled.")

    # ── Session Management ──────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🔐 Active Sessions")
    st.caption("View and manage active login sessions.")
    sessions = list_sessions(username)
    if not sessions:
        st.info("No active sessions recorded.")
    else:
        for s in sessions:
            from datetime import datetime as _dt
            created = _dt.fromtimestamp(s["created_at"]).strftime("%Y-%m-%d %H:%M") if s["created_at"] else "—"
            last_seen = _dt.fromtimestamp(s["last_seen"]).strftime("%Y-%m-%d %H:%M") if s["last_seen"] else "—"
            st.markdown(
                f"<div style='background:#111827;border:1px solid #1e3a5f;"
                f"border-radius:6px;padding:4px 8px;margin:2px 0;font-size:12px'>"
                f"{'🟢' if s['is_active'] else '🔴'} <code>{s['session_id']}</code> "
                f"<span style='color:#94a3b8'>{s['ip']} · {created} → {last_seen}</span>"
                f"</div>", unsafe_allow_html=True
            )
            if s["is_active"] and st.button("🚫 Revoke", key=f"rev_sess_{s['id']}", use_container_width=True):
                revoke_session(s["session_id"])
                st.rerun()
        if st.button("🚫 Revoke All Sessions", use_container_width=True):
            revoke_all_sessions(username)
            st.rerun()

    # ── Scheduled Email Digests ─────────────────────────────────────────────
    st.divider()
    st.markdown("### 📬 Scheduled Email Digests")
    st.caption("Automatically receive PDF/CSV reports via email on a schedule.")
    digest_freq = st.selectbox("Digest frequency", ["disabled", "daily", "weekly", "monthly"],
                                index=0, key="digest_freq")
    digest_format = st.selectbox("Format", ["pdf", "csv"], index=0, key="digest_format")
    if st.button("💾 Save Digest Settings", type="primary", use_container_width=True):
        st.session_state["digest_freq"] = digest_freq
        st.session_state["digest_format"] = digest_format
        st.success(f"Digest set to {digest_freq} ({digest_format}).")
    if digest_freq != "disabled" and st.session_state.get("email"):
        st.info(f"📧 {digest_freq.capitalize()} {digest_format.upper()} reports will be sent to {st.session_state['email']}.")
        if st.button("📤 Send Test Report Now", use_container_width=True):
            try:
                report_bytes = generate_weekly_report(username)
                st.download_button(
                    "📥 Download Test Report",
                    report_bytes,
                    f"phishguard_digest_{username}_{datetime.now().strftime('%Y%m%d')}.pdf",
                    "application/pdf",
                )
                st.success("Test report generated! Click to download.")
            except Exception as e:
                st.error(f"Report generation failed: {e}")
    elif digest_freq != "disabled" and not st.session_state.get("email"):
        st.warning("Save an email address in Profile above to receive digests.")

    # ── Auto-Responder ─────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🤖 Email Auto-Responder")
    st.caption("Automatically send a warning email to recipients when a HIGH/CRITICAL threat is detected.")
    ar_key = f"auto_responder_enabled_{username}"
    if ar_key not in st.session_state:
        st.session_state[ar_key] = False
    st.checkbox("Enable auto-responder", key=ar_key)
    if st.session_state[ar_key]:
        st.info("✅ Auto-responder is active. Warning emails will be sent for HIGH/CRITICAL scans.")

    # ── Integration Marketplace ────────────────────────────────────────────
    st.divider()
    st.markdown("### 🔌 Integration Marketplace")
    st.caption("One-click connectors for your security stack.")
    integrations = list_integrations(username)
    providers = get_available_providers()
    int_col1, int_col2 = st.columns([1, 1])
    with int_col1:
        st.markdown("**Available connectors:**")
        for pkey, pmeta in providers.items():
            existing = any(i["provider"] == pkey for i in integrations)
            status = "✅ Connected" if existing else "—"
            st.markdown(
                f"<div style='background:#111827;border:1px solid #1e3a5f;"
                f"border-radius:6px;padding:6px 10px;margin:3px 0;font-size:12px'>"
                f"{pmeta['icon']} <b>{pmeta['name']}</b> {status}"
                f"</div>", unsafe_allow_html=True
            )
    with int_col2:
        st.markdown("**Configure:**")
        connect_provider = st.selectbox("Select provider", list(providers.keys()),
                                         format_func=lambda k: providers[k]["name"],
                                         key="int_provider")
        if connect_provider:
            pmeta = providers[connect_provider]
            config_data = {}
            for field in pmeta["fields"]:
                config_data[field["key"]] = st.text_input(
                    field["label"], type="password" if field["type"] == "password" else "text",
                    key=f"int_{field['key']}",
                )
            col_c1, col_c2 = st.columns(2)
            with col_c1:
                if st.button("🔗 Connect", type="primary", use_container_width=True):
                    save_integration(username, connect_provider, config_data)
                    st.success(f"{pmeta['name']} connected!")
                    st.rerun()
            with col_c2:
                existing_int = next((i for i in integrations if i["provider"] == connect_provider), None)
                if existing_int and st.button("🗑 Disconnect", use_container_width=True):
                    remove_integration(username, connect_provider)
                    st.rerun()

    # ── GDPR Compliance ────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 🛡 GDPR Compliance")
    st.caption("Manage your data and consent preferences.")
    gdpr_tabs = st.tabs(["📥 Export My Data", "🗑 Delete My Account", "📋 Consent"])
    with gdpr_tabs[0]:
        st.markdown(
            "<p style='color:#94a3b8;font-size:13px'>Download all your personal data "
            "in JSON format, including account info, analyses, and audit logs.</p>",
            unsafe_allow_html=True,
        )
        if st.button("📥 Export All My Data", type="primary", use_container_width=True):
            with st.spinner("Gathering your data..."):
                data = export_user_data(username)
            st.json(data)
            st.success("✅ Export complete! Data shown above. Use the download button below.")
            import json
            st.download_button(
                "💾 Download JSON",
                json.dumps(data, indent=2, default=str),
                f"phishguard_export_{username}_{datetime.now().strftime('%Y%m%d')}.json",
                "application/json",
                use_container_width=True,
            )
    with gdpr_tabs[1]:
        st.error("⚠ This action is irreversible and will permanently delete all your data.")
        confirm = st.text_input(
            f'Type "DELETE {username}" to confirm',
            placeholder=f"DELETE {username}",
            key="gdpr_delete_confirm",
        )
        if st.button("🗑 Permanently Delete My Account", use_container_width=True):
            if confirm == f"DELETE {username}":
                result = delete_user_data(username)
                st.warning(f"Account deleted. {sum(result.values())} records removed.")
                logout()
            else:
                st.error("Confirmation text does not match.")
    with gdpr_tabs[2]:
        st.markdown(
            "<p style='color:#94a3b8;font-size:13px'>"
            "PhishGuard processes email content you submit for scanning. "
            "No data is shared with third parties for marketing.</p>",
            unsafe_allow_html=True,
        )
        has_consent = check_consent(username)
        if has_consent:
            st.success("✅ Consent granted for data processing.")
            if st.button("🔴 Revoke Consent", use_container_width=True):
                revoke_consent(username)
                st.rerun()
        else:
            st.warning("⚠ Consent not granted. Some features may be restricted.")
            if st.button("✅ Grant Consent", use_container_width=True):
                record_consent(username)
                st.rerun()

    # ── Scheduled Scans ────────────────────────────────────────────────────
    st.divider()
    from src.ui_scheduler import render_scheduler_ui
    render_scheduler_ui(username)

    # ── Notification Channels ──────────────────────────────────────────────
    st.divider()
    from src.ui_channels import render_notification_channels_ui
    render_notification_channels_ui(username)

    # ── Granular Webhook Routing ───────────────────────────────────────────
    st.divider()
    from src.ui_webhook_routing import render_webhook_routing_ui
    render_webhook_routing_ui(username)

    # ── Domain Verification ────────────────────────────────────────────────
    st.divider()
    from src.ui_domain_verify import render_domain_verify_ui
    render_domain_verify_ui(username)

    # ── White-Label Branding ───────────────────────────────────────────────
    st.divider()
    from src.ui_branding import render_branding_ui
    render_branding_ui(username)

    st.divider()
    st.markdown("### 📧 Email Templates")
    from src.ui_email_templates import render_email_templates_ui
    render_email_templates_ui()

if st.session_state.get("train_mode", "Training Tools") == "Training Tools":
    with training_tab:
        st.markdown("## 🧪 Security Training Tools")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Interactive tools to help you "
            "recognise phishing attempts and test your security awareness.</p>",
            unsafe_allow_html=True
        )
        st.divider()

        sub_tab1, sub_tab2, sub_tab3 = st.tabs(["🎣 Phishing Simulator", "📷 Screenshot Scanner", "🎓 AI Training Academy"])

        # ── Sub-tab 1: Phishing Simulation / Campaign Engine ───────────────────
        with sub_tab1:
            if is_admin:
                # ── Enterprise Campaign Engine for Admins ──────────────────────
                from src.audit_log import log_action
                from src.campaign_engine import (
                    delete_template,
                    generate_llm_template,
                    get_campaign_results,
                    launch_campaign,
                    list_templates,
                    save_template,
                )

                st.markdown("## 🎣 Enterprise Phishing Campaign Engine")
                st.markdown(
                    "<p style='color:#64748b;margin-top:-8px'>Create, launch, and monitor "
                    "corporate phishing simulation campaigns with open/click tracking.</p>",
                    unsafe_allow_html=True
                )
                st.divider()

                camp_t1, camp_t2, camp_t3 = st.tabs(["📝 Templates", "🚀 Launch Campaign", "📊 Results"])

                # ── Templates ───────────────────────────────────────────────────
                with camp_t1:
                    st.markdown("### Template Library")
                    saved_templates = list_templates()
                    if saved_templates:
                        for t in saved_templates:
                            with st.expander(f"{' 📜'} {t['name']}", expanded=False):
                                st.markdown(f"**Subject:** {t.get('subject', 'N/A')}")
                                st.markdown(f"**Body preview:** `{t.get('body', '')[:200]}...`")
                                st.markdown(f"**Category:** {t.get('category', 'General')}")
                                if st.button("🗑 Delete", key=f"del_tmpl_{t['id']}"):
                                    delete_template(t["id"])
                                    log_action(username, "campaign_delete_template", detail=f"template_id={t['id']},name={t['name']}")
                                    st.rerun()
                    else:
                        st.info("No saved templates yet. Use the builder below.")

                    st.divider()
                    st.markdown("### Build Template")
                    tmpl_name = st.text_input("Template Name", key="tmpl_name")
                    tmpl_category = st.selectbox("Category", ["Fake Invoice", "Password Reset", "Shared Document", "Voicemail", "Package Delivery"], key="tmpl_cat")
                    tmpl_sender = st.text_input("Sender Email (spoofed)", "noreply@acme-verify.com", key="tmpl_sender")
                    tmpl_subject = st.text_input("Email Subject", "Your invoice is overdue", key="tmpl_subj")
                    tmpl_body = st.text_area("Email Body (plain text)", height=200, key="tmpl_body")

                    col_t1, col_t2 = st.columns(2)
                    with col_t1:
                        if st.button("💾 Save Template", type="primary", use_container_width=True):
                            save_template(tmpl_name, tmpl_category, tmpl_sender, tmpl_subject, tmpl_body)
                            log_action(username, "campaign_save_template", detail=f"name={tmpl_name},category={tmpl_category}")
                            st.success(f"Template '{tmpl_name}' saved!")
                            st.rerun()
                    with col_t2:
                        if st.button("🤖 Generate with AI", use_container_width=True):
                            with st.spinner("Generating template via LLM..."):
                                generated = generate_llm_template(tmpl_category)
                                st.session_state["generated_template"] = generated
                            st.rerun()

                    if st.session_state.get("generated_template"):
                        gen = st.session_state["generated_template"]
                        st.markdown("### AI-Generated Preview")
                        st.markdown(f"**From:** `{gen.get('sender', '')}`")
                        st.markdown(f"**Subject:** **{gen.get('subject', '')}**")
                        st.markdown(
                            "<div style='background:#0f172a;border:1px solid #1e3a5f;"
                            "border-radius:10px;padding:16px;font-family:monospace;"
                            "font-size:13px;color:#94a3b8;max-height:300px;overflow-y:auto'>"
                            + gen.get("body", "").replace("\n", "<br>") + "</div>",
                            unsafe_allow_html=True
                        )
                        if st.button("📥 Save Generated Template", use_container_width=True):
                            save_template(
                                f"AI: {gen.get('subject', '')}",
                                tmpl_category,
                                gen.get("sender", ""),
                                gen.get("subject", ""),
                                gen.get("body", ""),
                            )
                            log_action(username, "campaign_save_ai_template", detail=f"category={tmpl_category}")
                            st.success("AI-generated template saved!")
                            st.rerun()

                # ── Launch Campaign ─────────────────────────────────────────────
                with camp_t2:
                    st.markdown("### Launch Campaign")

                    all_templates = list_templates()
                    template_options = [f"{t['id']}: {t['name']}" for t in all_templates]
                    if not template_options:
                        st.warning("Create a template first in the Templates tab.")
                        st.stop()

                    selected_template = st.selectbox("Select Template", template_options, key="camp_tmpl")

                    st.markdown("#### Target Recipients")
                    st.markdown(
                        "<p style='color:#64748b;font-size:13px'>Enter one email per line, "
                        "or paste a comma-separated list.</p>", unsafe_allow_html=True
                    )
                    target_input = st.text_area(
                        "Recipients",
                        "alice@company.com\nbob@company.com",
                        height=100, key="camp_targets"
                    )

                    targets = [t.strip() for t in target_input.replace(",", "\n").split("\n") if t.strip()]
                    st.markdown(f"**{len(targets)} recipient(s)**")

                    smtp_server = st.text_input("SMTP Server", os.getenv("SMTP_HOST", "smtp.example.com"), key="camp_smtp")
                    smtp_port = st.number_input("SMTP Port", value=int(os.getenv("SMTP_PORT", "587")), key="camp_port")
                    smtp_user = st.text_input("SMTP Username", os.getenv("SMTP_USER", ""), key="camp_user")
                    smtp_pass = st.text_input("SMTP Password", type="password", key="camp_pass")

                    if st.button("🚀 Launch Campaign", type="primary", use_container_width=True):
                        tmpl_id = int(selected_template.split(":")[0])
                        result = launch_campaign(
                            template_id=tmpl_id,
                            target_emails=targets,
                            smtp_server=smtp_server,
                            smtp_port=int(smtp_port),
                            smtp_username=smtp_user,
                            smtp_password=smtp_pass,
                        )
                        log_action(username, "campaign_launch", detail=f"template_id={tmpl_id},recipients={len(targets)}")
                        st.session_state["campaign_result"] = result
                        st.rerun()

                    if st.session_state.get("campaign_result"):
                        cres = st.session_state["campaign_result"]
                        if cres.get("status") == "launched":
                            st.success(
                                f"Campaign **{cres.get('campaign_id')}** launched! "
                                f"{cres.get('emails_sent', 0)} emails sent."
                            )
                        else:
                            st.error(f"Launch failed: {cres.get('error', 'Unknown error')}")

                # ── Results ─────────────────────────────────────────────────────
                with camp_t3:
                    st.markdown("### Campaign Results")
                    results = get_campaign_results()
                    if isinstance(results, list) and results:
                        for r in results:
                            total = r.get("total_targets", 0)
                            opened = r.get("opened_count", 0)
                            clicked = r.get("clicked_count", 0)
                            open_rate = (opened / total * 100) if total else 0
                            click_rate = (clicked / total * 100) if total else 0

                            with st.expander(
                                f"📊 Campaign #{r['id']} — {r.get('template_name', 'N/A')} "
                                f"({open_rate:.0f}% open, {click_rate:.0f}% click)",
                                expanded=False
                            ):
                                st.markdown(f"**Launched:** {r.get('launched_at', 'N/A')}")
                                st.markdown(f"**Total targets:** {total}")
                                st.markdown(f"**Opened:** {opened}")
                                st.markdown(f"**Clicked:** {clicked}")
                                st.progress(open_rate / 100, text=f"Open rate: {open_rate:.1f}%")
                                st.progress(click_rate / 100, text=f"Click rate: {click_rate:.1f}%")

                                st.markdown("---")
                                st.markdown("#### Per-Target Breakdown")
                                targets_list = r.get("targets", [])
                                if targets_list:
                                    import pandas as pd
                                    df = pd.DataFrame(targets_list)
                                    st.dataframe(
                                        df[["email", "opened", "clicked"]],
                                        use_container_width=True, hide_index=True,
                                    )
                    else:
                        st.info("No campaigns launched yet.")

            else:
                # ── Corporate Phishing Simulation Hub (WormGPT-Style) ────────────
                _sim_tier_ok = plan in ("business", "enterprise", "consultant")
                # Simulation credits counter
                if "sim_credits" not in st.session_state:
                    st.session_state["sim_credits"] = 5 if _sim_tier_ok else 0
                _sim_credits = st.session_state["sim_credits"]

                st.markdown("### 🧠 Corporate Phishing Simulation Hub")
                st.markdown(
                    "<p style='color:#64748b;margin-top:-8px'>WormGPT-style contextual "
                    "persuasion engine — generate state-actor phishing simulations "
                    "tailored to your organization's departments.</p>",
                    unsafe_allow_html=True
                )

                if not _sim_tier_ok:
                    st.markdown(
                        "<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);"
                        "border:2px solid #eab30844;border-radius:16px;padding:28px 24px;"
                        "text-align:center;margin:16px 0'>"
                        "<div style='font-size:2.5rem;margin-bottom:8px'>🧠</div>"
                        "<div style='color:#f0f6ff;font-size:1.2rem;font-weight:700;margin-bottom:6px'>"
                        "Advanced Simulation Hub Locked</div>"
                        "<div style='color:#94a3b8;font-size:0.9rem;max-width:420px;margin:0 auto 16px auto'>"
                        "Generate context-aware phishing simulations with state-actor tactical "
                        "patterns. Upgrade to Business ($99/mo) or Enterprise to unlock.</div>"
                        "<a href='#billing-tab' style='display:inline-block;"
                        "background:linear-gradient(135deg,#eab308,#f59e0b);color:#0a0f1a;"
                        "padding:10px 32px;border-radius:10px;text-decoration:none;font-weight:700;"
                        "font-size:0.95rem'>⬆ Upgrade to Business</a></div>",
                        unsafe_allow_html=True,
                    )
                else:
                    # ── Credit Meter ─────────────────────────────────────────────
                    _sc_pct = min(100, int(_sim_credits / 50 * 100))
                    _sc_color = "#22c55e" if _sim_credits > 20 else "#eab308" if _sim_credits > 5 else "#ef4444"
                    st.markdown(
                        "<div style='display:flex;gap:12px;align-items:center;"
                        "background:#111827;border:1px solid #1e3a5f;border-radius:12px;"
                        "padding:12px 18px;margin-bottom:16px'>"
                        "<div style='font-size:1.5rem'>🎯</div>"
                        "<div style='flex:1'>"
                        "<div style='display:flex;justify-content:space-between;font-size:12px;"
                        f"color:#94a3b8'><span>Simulation Credits</span>"
                        f"<span style='color:{_sc_color};font-weight:700'>{_sim_credits} remaining</span></div>"
                        "<div style='background:#1e3a5f;border-radius:4px;height:5px;margin-top:4px'>"
                        f"<div style='background:{_sc_color};border-radius:4px;height:5px;"
                        f"width:{_sc_pct}%'></div></div></div>"
                        f"<div style='font-size:11px;color:#64748b'>1 credit per simulation</div></div>",
                        unsafe_allow_html=True,
                    )

                    col_sim_dept, col_sim_vec, col_sim_tac = st.columns(3)
                    with col_sim_dept:
                        department = st.selectbox(
                            "Target Department",
                            ["Finance", "HR", "IT Support", "Executive", "Sales", "Engineering", "Legal"],
                            index=0, label_visibility="collapsed", key="sim_dept"
                        )
                    with col_sim_vec:
                        attack_vector = st.selectbox(
                            "Attack Vector",
                            ["Urgent Invoice", "Password Reset", "Fake HR Policy",
                             "Shared Document", "Voicemail", "Package Delivery",
                             "MFA Fatigue", "OAuth Consent", "Gift Card Scam"],
                            index=0, label_visibility="collapsed", key="sim_vector"
                        )
                    with col_sim_tac:
                        tactic_ref = st.selectbox(
                            "State-Actor Tactic",
                            ["Whaling (CEO Fraud)", "Business Email Compromise",
                             "Credential Harvesting", "MFA Bypass (AitM)",
                             "Pretexting / Vishing Setup", "Watering Hole Lure",
                             "WormGPT Contextual Persuasion"],
                            index=0, label_visibility="collapsed", key="sim_tactic"
                        )

                    dept_icons = {"Finance": "🏦", "HR": "📋", "IT Support": "🖥",
                                  "Executive": "👔", "Sales": "📊", "Engineering": "⚙", "Legal": "⚖"}
                    vec_icons = {"Urgent Invoice": "📄", "Password Reset": "🔑", "Fake HR Policy": "📜",
                                 "Shared Document": "📎", "Voicemail": "📞", "Package Delivery": "📦",
                                 "MFA Fatigue": "📱", "OAuth Consent": "🔐", "Gift Card Scam": "🎁"}
                    tactic_icons = {"Whaling (CEO Fraud)": "🐋", "Business Email Compromise": "💼",
                                    "Credential Harvesting": "🎣", "MFA Bypass (AitM)": "🕵️",
                                    "Pretexting / Vishing Setup": "🎭", "Watering Hole Lure": "🌊",
                                    "WormGPT Contextual Persuasion": "🧠"}

                    st.markdown(
                        f"<div style='background:#0f172a;border:1px solid #1e3a5f;"
                        f"border-radius:10px;padding:14px 18px;margin:8px 0 16px 0;"
                        f"color:#94a3b8;font-size:13px'>"
                        f"Scenario: {dept_icons.get(department, '')} <b>{department}</b> "
                        f"via {vec_icons.get(attack_vector, '')} <b>{attack_vector}</b> "
                        f"| Tactic: {tactic_icons.get(tactic_ref, '')} <b>{tactic_ref}</b></div>",
                        unsafe_allow_html=True
                    )

                    col_go, col_buy = st.columns([1, 1])
                    with col_go:
                        gen_disabled = _sim_credits <= 0
                        if st.button("🧠 WormGPT Generate", type="primary",
                                      use_container_width=True, disabled=gen_disabled):
                            with st.spinner("Generating state-actor simulation..."):
                                st.session_state["sim_credits"] = max(0, _sim_credits - 1)
                                sim = simulate_phishing(department, attack_vector)
                                # Inject tactic reference
                                sim["tactic"] = tactic_ref
                                st.session_state["simulation"] = sim
                                st.session_state["sim_reveal"] = False
                                st.rerun()
                    with col_buy:
                        if st.button("💰 Buy 1,000 Simulation Credits ($49)",
                                      use_container_width=True):
                            st.session_state["sim_credits"] = _sim_credits + 1000
                            st.success("✅ 1,000 simulation credits added!")
                            st.rerun()
                    if gen_disabled and _sim_credits <= 0:
                        st.warning("⛔ Simulation credits depleted. Purchase a bundle to continue.")

                    # Display simulation results
                    sim = st.session_state.get("simulation")
                    if sim:
                        st.divider()
                        st.markdown("### 📧 Simulated Email")
                        col_sim1, col_sim2 = st.columns([1, 3])
                        with col_sim1:
                            st.markdown("**From:**")
                            st.markdown("**Subject:**")
                            st.markdown("**Tactic:**")
                            st.markdown("**Body:**")
                        with col_sim2:
                            st.markdown(f"`{sim.get('sender', 'unknown@example.com')}`")
                            st.markdown(f"**{sim.get('subject', '(no subject)')}**")
                            st.markdown(f"<span style='color:#eab308'>{sim.get('tactic', tactic_ref)}</span>",
                                        unsafe_allow_html=True)
                            st.markdown(
                                "<div style='background:#0f172a;border:1px solid #1e3a5f;"
                                "border-radius:10px;padding:16px;font-family:monospace;"
                                "font-size:13px;color:#94a3b8;line-height:1.6;margin-top:4px;"
                                "max-height:300px;overflow-y:auto'>"
                                + sim.get("body", "").replace("\n", "<br>") +
                                "</div>", unsafe_allow_html=True
                            )

                        st.divider()
                        reveal = st.session_state.get("sim_reveal", False)
                        if not reveal:
                            if st.button("🔍 Reveal Phishing Clues", type="primary", use_container_width=True):
                                st.session_state["sim_reveal"] = True
                                st.rerun()
                        else:
                            clues = sim.get("clues", [])
                            remediation = sim.get("remediation", "")
                            st.markdown("### 🚩 Phishing Indicators")
                            for clue in clues:
                                st.markdown(
                                    "<div style='background:#2a0a0a;border:1px solid #ff444444;"
                                    "border-radius:8px;padding:10px 14px;margin:6px 0;"
                                    "color:#ff8888;font-size:13px'>🚨 " + clue + "</div>",
                                    unsafe_allow_html=True
                                )
                            st.markdown("### 🛡️ Remediation")
                            st.success(remediation)
                            col_try, col_new = st.columns(2)
                            with col_try:
                                if st.button("🔄 Try Another", use_container_width=True):
                                    st.session_state.pop("simulation", None)
                                    st.session_state.pop("sim_reveal", None)
                                    st.rerun()
                            with col_new:
                                if st.button("💰 Buy More Credits", use_container_width=True):
                                    st.session_state["sim_credits"] = _sim_credits + 1000
                                    st.success("✅ 1,000 credits added!")
                                    st.rerun()

        # ── Sub-tab 2: Screenshot OCR Scanner ────────────────────────────────────
        with sub_tab2:
            st.markdown("### 📷 Screenshot / Image Scanner")
            st.markdown(
                "<p style='color:#64748b;margin-top:-8px'>Upload a screenshot of a "
                "suspicious email, website, or message. AI vision analysis detects "
                "brand impersonation, visual spoofing, and phishing layouts.</p>",
                unsafe_allow_html=True
            )

            uploaded = st.file_uploader(
                "Choose an image", type=["png", "jpg", "jpeg", "webp"],
                label_visibility="collapsed"
            )

            if uploaded:
                st.image(uploaded, caption="Uploaded screenshot", use_container_width=True)

                if st.button("🔍 Analyze Screenshot", type="primary", use_container_width=True):
                    with st.spinner("AI vision analysis in progress..."):
                        import base64
                        bytes_data = uploaded.getvalue()
                        mime = uploaded.type or "image/png"
                        b64 = base64.b64encode(bytes_data).decode()
                        result = analyze_screenshot(b64, mime)

                    st.session_state["screenshot_result"] = result

            result = st.session_state.get("screenshot_result")
            if result:
                st.divider()
                is_phish = result.get("isPhishing", False)
                score = result.get("score", 0)
                severity = result.get("severity", "LOW")
                color = "#ff4444" if score >= 75 else "#ff8800" if score >= 50 else "#ffaa00" if score >= 25 else "#44aa44"

                st.markdown("### 📊 Scan Results")
                col_r1, col_r2 = st.columns([1, 2])
                with col_r1:
                    st.markdown(
                        "<div style='text-align:center;padding:20px;background:#111827;"
                        "border-radius:12px;border:1px solid " + color + "'>"
                        "<div style='font-size:3rem;font-weight:900;color:" + color + "'>"
                        + str(score) + "</div>"
                        "<div style='color:#64748b;font-size:0.8rem'>Risk Score</div>"
                        "<div style='color:" + color + ";font-weight:700;margin-top:4px'>"
                        + severity + "</div>"
                        + ("<div style='color:#ff4444;font-size:0.9rem;margin-top:8px'>⚠️ Phishing Risk</div>"
                           if is_phish else
                           "<div style='color:#44aa44;font-size:0.9rem;margin-top:8px'>✅ No Threats</div>")
                        + "</div>",
                        unsafe_allow_html=True
                    )

                with col_r2:
                    brand = result.get("brandTarget", "N/A")
                    st.markdown(f"**Brand Targeted:** {brand}")
                    ocr_text = result.get("detectedTextOcr", "")
                    if ocr_text and ocr_text != "N/A":
                        st.markdown("**Detected Text:**")
                        st.markdown(
                            "<div style='background:#0f172a;border:1px solid #1e3a5f;"
                            "border-radius:8px;padding:10px;font-family:monospace;"
                            "font-size:12px;color:#94a3b8;max-height:150px;overflow-y:auto'>"
                            + ocr_text[:500] + "</div>",
                            unsafe_allow_html=True
                        )

                anomalies = result.get("visualAnomalies", [])
                if anomalies and not any("unavailable" in a.lower() for a in anomalies):
                    st.markdown("### 👁️ Visual Anomalies")
                    for a in anomalies:
                        st.markdown(
                            "<div style='background:#2a1a0a;border:1px solid #ff880044;"
                            "border-radius:8px;padding:8px 12px;margin:4px 0;"
                            "color:#ffaa00;font-size:12px'>⚠ " + a + "</div>",
                            unsafe_allow_html=True
                        )

                verdict = result.get("detailedVerdict", "")
                if verdict and "unavailable" not in verdict.lower():
                    st.markdown("### 📋 Verdict")
                    st.info(verdict)

                remediation = result.get("remediation", "")
                if remediation:
                    st.markdown("### 🛡️ Recommended Actions")
                    st.success(remediation)

        # ── Sub-tab 3: AI Training Academy ─────────────────────────────────────
        with sub_tab3:
            st.markdown("### 🎓 Employee Security Awareness Academy")
            st.markdown(
                "<p style='color:#64748b;margin-top:-8px'>Test your team's phishing "
                "detection skills with AI-generated quizzes. "
                "Earn ISO-Compliance certificates for your organisation.</p>",
                unsafe_allow_html=True
            )
            st.divider()

            # Generate quiz state
            if "quiz_questions" not in st.session_state:
                import random as _rnd
                questions = [
                    {"q": "What is the safest action when you receive an unexpected email with an attachment?",
                     "options": ["Open it immediately", "Scan it with antivirus first",
                                 "Verify the sender through a separate channel, then scan",
                                 "Forward it to all colleagues"],
                     "answer": 2, "explanation": "Always verify the sender through a separate channel before opening attachments."},
                    {"q": "Which of these is a sign of a phishing email?",
                     "options": ["Personalised greeting with your name",
                                 "Urgent language demanding immediate action",
                                 "Professional company logo",
                                 "Correct grammar and spelling"],
                     "answer": 1, "explanation": "Urgency tactics like 'act now or your account will be closed' are classic phishing indicators."},
                    {"q": "What does a homograph attack do?",
                     "options": ["Encrypts your files for ransom",
                                 "Uses lookalike characters to spoof domains",
                                 "Steals your Wi-Fi password",
                                 "Cracks your email password"],
                     "answer": 1, "explanation": "Homograph attacks replace Latin letters with visually similar Cyrillic or Unicode characters."},
                    {"q": "What is the purpose of DMARC?",
                     "options": ["Encrypts email content",
                                 "Prevents email spoofing by authenticating sender domains",
                                 "Blocks all spam automatically",
                                 "Creates backups of your emails"],
                     "answer": 1, "explanation": "DMARC (Domain-based Message Authentication) prevents attackers from spoofing your domain."},
                    {"q": "You receive an SMS from 'your CEO' asking you to buy gift cards. What is this?",
                     "options": ["A legitimate request from your boss",
                                 "A CEO fraud / business email compromise (BEC) attack",
                                 "A company morale-building exercise",
                                 "An IT security test"],
                     "answer": 1, "explanation": "CEO fraud (whaling) is a targeted BEC attack where the attacker impersonates senior leadership."},
                ]
                _rnd.shuffle(questions)
                st.session_state["quiz_questions"] = questions[:4]
                st.session_state["quiz_answers"] = {}
                st.session_state["quiz_submitted"] = False

            questions = st.session_state["quiz_questions"]
            for i, q_data in enumerate(questions):
                q_key = f"quiz_q_{i}"
                st.markdown(f"**Q{i+1}:** {q_data['q']}")
                selected = st.radio(
                    "Select answer",
                    q_data["options"],
                    index=None,
                    key=q_key,
                    label_visibility="collapsed",
                )
                if selected is not None:
                    st.session_state["quiz_answers"][i] = q_data["options"].index(selected)

            col_q1, col_q2 = st.columns(2)
            with col_q1:
                if st.button("✅ Submit Quiz", type="primary", use_container_width=True):
                    st.session_state["quiz_submitted"] = True
            with col_q2:
                if st.button("🔄 New Quiz", use_container_width=True):
                    for k in list(st.session_state.keys()):
                        if k.startswith("quiz_"):
                            del st.session_state[k]
                    st.rerun()

            if st.session_state.get("quiz_submitted"):
                st.divider()
                answers = st.session_state["quiz_answers"]
                correct_count = 0
                for i, q_data in enumerate(questions):
                    user_ans = answers.get(i)
                    correct = q_data["answer"]
                    is_correct = user_ans == correct
                    if is_correct:
                        correct_count += 1
                    status_icon = "✅" if is_correct else "❌"
                    answer_text = f"Wrong. Correct answer: {q_data['options'][correct]}"
                    correct_text = "Correct!"
                    display_text = correct_text if is_correct else answer_text
                    st.markdown(
                        f"<div style='background:#111827;border:1px solid #1e3a5f;"
                        f"border-radius:10px;padding:12px 16px;margin:6px 0'>"
                        f"<div style='color:#e2e8f0;font-weight:600'>{status_icon} Q{i+1}: {q_data['q']}</div>"
                        f"<div style='color:{'#22c55e' if is_correct else '#ef4444'};font-size:13px'>"
                        f"{display_text}</div>"
                        f"<div style='color:#64748b;font-size:12px;margin-top:4px'>"
                        f"💡 {q_data['explanation']}</div></div>", unsafe_allow_html=True
                    )

                score_pct = int(correct_count / len(questions) * 100)
                st.markdown(
                    f"<div style='background:linear-gradient(135deg,#0a1a0a,#0f2a0f);"
                    f"border:2px solid #22c55e;border-radius:16px;padding:20px;"
                    f"text-align:center;margin:16px 0'>"
                    f"<div style='font-size:2rem;font-weight:800;color:#22c55e'>"
                    f"{correct_count}/{len(questions)}</div>"
                    f"<div style='color:#94a3b8'>Score: {score_pct}%</div>"
                    f"</div>", unsafe_allow_html=True
                )

                is_premium_quiz = st.session_state.get("plan") in ("enterprise", "business")
                if is_premium_quiz:
                    st.success("✅ Premium plan active — certificate generation included.")
                    st.download_button(
                        "📜 Download ISO-Compliance Certificate",
                        f"Certificate of Completion\n\nEmployee: {username}\n"
                        f"Score: {score_pct}%\nDate: {datetime.now().strftime('%Y-%m-%d')}\n"
                        f"Standard: ISO 27001 — Phishing Awareness",
                        f"phishing_awareness_cert_{username}.txt",
                        use_container_width=True,
                    )
                else:
                    st.markdown(
                        "<div style='background:linear-gradient(135deg,#1a1a0a,#2a2a0f);"
                        "border:2px solid #eab308;border-radius:16px;padding:24px 20px;"
                        "text-align:center;margin:16px 0'>"
                        "<div style='font-size:2rem;margin-bottom:6px'>🎓</div>"
                        "<div style='color:#f0f6ff;font-size:1rem;font-weight:700;"
                        "margin-bottom:4px'>Generate Official Corporate ISO-Compliance Certificate</div>"
                        "<div style='color:#94a3b8;font-size:0.85rem;margin-bottom:12px'>"
                        "$5 per employee <span style='color:#475569'>or included in "
                        "<strong>Premium Annual Plans</strong></span></div>"
                        "<div style='display:flex;gap:8px;justify-content:center'>"
                        "<span style='background:#2a2a0f;color:#eab308;padding:4px 14px;"
                        "border-radius:100px;font-size:12px'>💳 Buy 1 Certificate ($5)</span>"
                        "<span style='background:#111827;color:#94a3b8;padding:4px 14px;"
                        "border-radius:100px;font-size:12px'>📦 Included in Premium ($99/mo)</span>"
                        "</div></div>", unsafe_allow_html=True
                    )
                    if st.button("💳 Purchase Certificate — $5", use_container_width=True):
                        st.session_state["show_cert_checkout"] = True
                    if st.session_state.get("show_cert_checkout"):
                        st.info(
                            "🛒 Checkout simulation: ISO-Compliance Certificate for "
                            f"{username}. In production this would redirect to Stripe.",
                            icon="💳"
                        )

    # ═════════════════════════════════════════════════════════════════════════════
    # TAB — SECURITY CHAMPIONS LEADERBOARD
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("train_mode", "Training Tools") == "Leaderboard":
    with champions_tab:
        render_leaderboard(username)

    # ═════════════════════════════════════════════════════════════════════════════
    # LAST TAB — HISTORY
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("dash_mode", "Overview") == "History":
    with history_tab:
        from src.ui_history import render_history_tab
        render_history_tab()


    # ═════════════════════════════════════════════════════════════════════════════
    # TAB — STIX 2.1 THREAT INTELLIGENCE SHARING
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("threat_mode", "STIX Intelligence") == "STIX Intelligence":
    with tab_stix:
        st.markdown("## 🧬 STIX 2.1 Threat Intelligence Sharing")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Collective immunity via "
            "STIX 2.1 CTI bundles — broadcast confirmed threats to all tenants.</p>",
            unsafe_allow_html=True,
        )
        st.divider()

        if not _HAS_STIX:
            st.warning("⚠ STIX Intel Sharing module unavailable. Check dependencies.")
            st.stop()

        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.markdown("#### 🔬 Collective Immunity Check")
            st.caption("Check if an email hash matches any known threat indicator.")
            immunity_text = st.text_area(
                "Paste email text to check",
                height=120,
                label_visibility="collapsed",
                placeholder="Paste the full email text here to check collective immunity...",
                key="stix_immunity_input",
            )
            if st.button("🔍 Check Immunity", use_container_width=True, key="stix_check"):
                if immunity_text.strip():
                    with st.spinner("Checking collective immunity..."):
                        result = check_collective_immunity(immunity_text.strip())
                    if result.get("immunised"):
                        st.success(
                            f"✅ **IMMUNISED** — This exact threat was already "
                            f"broadcast by **{result['matched_tenant']}** "
                            f"({result['matched_severity']}, score {result['matched_score']}/100)."
                        )
                    else:
                        st.info("🟢 No collective immunity match — this appears to be a novel threat.")

        with col_s2:
            st.markdown("#### 📡 Broadcast Current Analysis")
            st.caption("Immunise the last analysis to all connected tenants.")
            if st.button("📡 Immunise Last Analysis", use_container_width=True,
                         type="primary", key="stix_immunise"):
                last_results = st.session_state.get("results")
                last_email = st.session_state.get("email_text", "")
                if last_results and last_email:
                    with st.spinner("Building STIX bundle and broadcasting..."):
                        result = immunise_from_analysis(
                            last_email, last_results,
                            sender=last_results.get("sender", ""),
                            subject=last_results.get("subject", ""),
                        )
                    if result.get("broadcast_id"):
                        st.success(
                            f"✅ STIX bundle broadcast — ID `{result['broadcast_id']}`. "
                            f"Linguistic hash: `{result.get('linguistic_hash', '')[:16]}...`"
                        )
                    else:
                        st.error(f"Broadcast failed: {result.get('error', 'Unknown')}")
                else:
                    st.warning("No analysis in session. Run an analysis first.")

        st.divider()
        st.markdown("#### 📋 Active STIX Indicators")
        indicators = get_all_active_indicators(limit=50)
        if not indicators:
            st.info("No active STIX indicators yet. Broadcast your first threat above.")
        else:
            for ind in indicators:
                stid, stix_id, ind_type, pattern, lhash, sdom, sev, score, first, last, active, bcount, created = ind
                sev_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                             "MEDIUM": "#ffaa00", "LOW": "#44aa44"}.get(sev, "#94a3b8")
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e3a5f;"
                    f"border-radius:10px;padding:12px 16px;margin:6px 0'>"
                    f"<div style='display:flex;justify-content:space-between'>"
                    f"<span style='color:{sev_color};font-weight:700'>{sev}</span>"
                    f"<span style='color:#94a3b8;font-size:12px'>Score {score}/100</span>"
                    f"<span style='color:#475569;font-size:11px'>Broadcast {bcount}x</span>"
                    f"</div>"
                    f"<div style='color:#64748b;font-size:12px;margin-top:4px'>"
                    f"{ind_type} · `{stix_id[:32]}...`</div>"
                    f"<div style='color:#475569;font-size:11px;margin-top:2px'>"
                    f"{first[:10]} → {last[:10] if last else 'ongoing'}</div>"
                    f"</div>", unsafe_allow_html=True
                )


    # ═════════════════════════════════════════════════════════════════════════════
    # TAB — SENDER PROFILER
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("threat_mode", "STIX Intelligence") == "Sender Profiler":
    with tab_sender:
        st.markdown("## 📧 Behavioral Sender Profiler")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Track sender baselines — "
            "detect tone shifts, urgency spikes, and anomalous financial requests.</p>",
            unsafe_allow_html=True,
        )
        st.divider()

        if not _HAS_SENDER_PROFILER:
            st.warning("⚠ Sender Profiler module unavailable. Check dependencies.")
            st.stop()

        col_p1, col_p2 = st.columns([1, 1])
        with col_p1:
            st.markdown("#### 🔍 Anomaly Check for Last Sender")
            last_email = st.session_state.get("email_text", "")
            if last_email:
                import re
                sender_match = re.search(r"From:\s*(\S+@\S+)", last_email)
                sender = sender_match.group(1) if sender_match else ""
                if sender:
                    st.caption(f"Last sender: `{sender}`")
                    if st.button("🧠 Detect Anomalies", use_container_width=True, key="sender_anomaly"):
                        with st.spinner("Analyzing sender behavior..."):
                            anomaly = detect_behavioural_anomaly(
                                sender, "", last_email,
                                risk_score=st.session_state.get("results", {}).get("risk_score", 0),
                            )
                        st.session_state["sender_anomaly"] = anomaly
                        st.rerun()
            else:
                st.info("Run an analysis first to check sender behavior.")

            anomaly = st.session_state.get("sender_anomaly")
            if anomaly:
                st.divider()
                st.markdown("#### 📊 Anomaly Results")
                is_anom = anomaly.get("is_anomalous", False)
                if is_anom:
                    st.error(f"🚨 **Anomalous behavior detected** — Score {anomaly['anomaly_score']:.0f}/100")
                else:
                    st.success(f"🟢 Baseline normal — Score {anomaly['anomaly_score']:.0f}/100")

                col_a1, col_a2 = st.columns(2)
                with col_a1:
                    st.metric("Urgency Spike", f"{anomaly.get('urgency_spike', 0):.1f}")
                    st.metric("Tone Shift", anomaly.get("tone_shift", "none"))
                with col_a2:
                    st.metric("Financial Request", "⚠ Yes" if anomaly.get("first_financial_request") else "No")
                    st.metric("Salutation Change", "⚠ Yes" if anomaly.get("salutation_changed") else "No")

                if anomaly.get("flags"):
                    for flag in anomaly["flags"]:
                        st.warning(f"⚠ {flag}")

        with col_p2:
            st.markdown("#### 📋 All Sender Profiles")
            profiles = get_all_profiles_summary(limit=30)
            if not profiles:
                st.info("No sender profiles yet. Run analyses to build them.")
            else:
                for prof in profiles:
                    semail, sdomain, sname, total, trust, avg_risk, last = prof[:7]
                    trust_color = "#44aa44" if trust >= 60 else "#ffaa00" if trust >= 40 else "#ff4444"
                    st.markdown(
                        f"<div style='background:#111827;border:1px solid #1e3a5f;"
                        f"border-radius:10px;padding:10px 14px;margin:4px 0'>"
                        f"<div style='display:flex;justify-content:space-between'>"
                        f"<span style='color:#e2e8f0;font-weight:500'>{sname or semail}</span>"
                        f"<span style='color:{trust_color}'>{trust:.0f} trust</span>"
                        f"</div>"
                        f"<div style='color:#475569;font-size:11px'>{total} emails · "
                        f"{avg_risk:.0f} avg risk · last {last[:10] if last else 'never'}</div>"
                        f"</div>", unsafe_allow_html=True
                    )


    # ═════════════════════════════════════════════════════════════════════════════
    # TAB — URL SANDBOX
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("threat_mode", "STIX Intelligence") == "URL Sandbox":
    with tab_sandbox:
        st.markdown("## 🔗 Headless URL Sandbox")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Isolate and analyse suspicious "
            "URLs in a headless browser — capture redirect chains, login forms, and "
            "LLM-based brand verification.</p>",
            unsafe_allow_html=True,
        )
        st.divider()

        if not _HAS_URL_SANDBOX:
            st.warning(
                "⚠ URL Sandbox requires Playwright + headless browser support. "
                "Not available on HF Spaces — run locally.",
            )
            st.stop()

        sandbox_url = st.text_input(
            "URL to analyse",
            placeholder="https://suspicious-link.example.com",
            label_visibility="collapsed",
            key="sandbox_url_input",
        )
        col_sb1, col_sb2, col_sb3 = st.columns([1, 1, 2])
        with col_sb1:
            sb_btn = st.button("🔍 Analyse URL", use_container_width=True, type="primary")
        with col_sb2:
            if st.button("📋 Load from Last Analysis", use_container_width=True):
                last_results = st.session_state.get("results", {})
                urls = last_results.get("urls_found", [])
                if urls:
                    st.session_state["sandbox_url_input"] = urls[0]
                    st.rerun()
                else:
                    st.warning("No URLs in last analysis.")

        if sb_btn and sandbox_url.strip():
            with st.spinner("Launching headless sandbox..."):
                result = analyse_url_sandbox_sync(sandbox_url.strip(), use_llm=False)
            st.session_state["sandbox_result"] = result
            st.rerun()

        sb_result = st.session_state.get("sandbox_result")
        if sb_result:
            st.divider()
            st.markdown("#### 📊 Sandbox Results")
            score_r = sb_result.get("risk_score", 0)
            verdict = sb_result.get("verdict", "unknown")
            vcolor = "#ff4444" if score_r >= 75 else "#ff8800" if score_r >= 50 else "#44aa44"
            col_r1, col_r2, col_r3 = st.columns(3)
            with col_r1:
                st.metric("Risk Score", f"{score_r}/100")
            with col_r2:
                st.metric("Verdict", verdict)
            with col_r3:
                st.metric("Redirects", len(sb_result.get("redirect_chain", [])))

            if sb_result.get("detected_login_form"):
                st.error("🚨 **Login form detected** — possible credential harvesting page.")
            if sb_result.get("detected_brand"):
                st.warning(f"⚠ Brand detected: **{sb_result['detected_brand']}**")
            if sb_result.get("final_url") and sb_result["final_url"] != sb_result.get("original_url"):
                st.markdown(
                    f"**Redirect chain:** {' → '.join(sb_result['redirect_chain'])}"
                )
            if sb_result.get("error"):
                st.error(f"Sandbox error: {sb_result['error']}")

        st.divider()
        st.markdown("#### 📋 Recent Sandbox History")
        sb_history = get_sandbox_history(limit=20)
        if not sb_history:
            st.info("No sandbox runs yet.")
        else:
            for row in sb_history:
                sid, ourl, furl, rchain, spath, title, lform, brand, lver, lconf, hhash, dsum, rscore, verd, atime, ts = row
                sc = "#ff4444" if rscore >= 75 else "#ff8800" if rscore >= 50 else "#44aa44"
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e3a5f;"
                    f"border-radius:10px;padding:10px 14px;margin:4px 0'>"
                    f"<div style='display:flex;justify-content:space-between'>"
                    f"<span style='color:#e2e8f0;font-size:13px'>{ourl[:60]}</span>"
                    f"<span style='color:{sc};font-weight:700'>{rscore}/100</span>"
                    f"</div>"
                    f"<div style='color:#475569;font-size:11px'>{verd} · {ts[:16]}</div>"
                    f"</div>", unsafe_allow_html=True
                )

        # ── Premium Domain Monitoring Hub ──────────────────────────────────────
        st.divider()
        st.markdown("### 🏢 Brand Protection — Domain Monitoring")
        st.markdown(
            "<p style='color:#64748b;font-size:13px'>Monitor your corporate domain "
            "for lookalike homograph attacks, typosquatting, and brand impersonation.</p>",
            unsafe_allow_html=True
        )
        monitored_domain = st.text_input(
            "Your Corporate Domain", placeholder="example.com",
            key="monitored_domain"
        )
        col_mon1, col_mon2 = st.columns(2)
        with col_mon1:
            if st.button("🔍 Scan for Lookalikes", type="primary", use_container_width=True, key="mon_scan"):
                if monitored_domain.strip():
                    domain = monitored_domain.strip().lower()
                    common_tlds = [".com", ".net", ".org", ".co", ".io", ".biz", ".info"]
                    homograph_subs = ["a\u0430", "e\u0435", "o\u043e", "p\u0440", "c\u0441",
                                      "i\u0456", "x\u0445", "y\u0443"]
                    lookalikes = []
                    for tld in common_tlds:
                        if not domain.endswith(tld):
                            lookalikes.append(domain.replace(".com", "") + tld)
                    for sub in homograph_subs:
                        if sub[0] in domain:
                            lookalikes.append(domain.replace(sub[0], sub[1], 1))
                    st.session_state["monitored_lookalikes"] = list(set(lookalikes))[:8]
                    st.session_state["monitored_domain"] = domain
                    st.rerun()
        with col_mon2:
            if st.button("🔄 Start Continuous Monitoring", use_container_width=True, key="mon_start"):
                st.session_state["monitoring_active"] = True
                st.rerun()
        if st.session_state.get("monitoring_active"):
            st.info("⏳ Continuous monitoring running — new lookalikes detected within 24-48h.")
        lookalikes = st.session_state.get("monitored_lookalikes")
        if lookalikes:
            st.markdown(
                f"<div style='background:#111827;border:1px solid #1e3a5f;"
                f"border-radius:12px;padding:16px;margin:12px 0'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                f"<span style='color:#e2e8f0;font-weight:600'>Found {len(lookalikes)} "
                f"potential impersonations</span>"
                f"<span style='color:#ef4444;font-size:12px;background:#2a0a0a;"
                f"padding:2px 10px;border-radius:100px'>⚠ ACTIVE</span></div>",
                unsafe_allow_html=True
            )
            for ld in lookalikes:
                risk = "HIGH" if any(c in ld for c in ["\u0430", "\u0435", "\u043e"]) else "MEDIUM"
                color = "#ef4444" if risk == "HIGH" else "#eab308"
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;"
                    f"background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;"
                    f"padding:8px 14px;margin:4px 0'>"
                    f"<span style='color:#e2e8f0;font-family:monospace'>{ld}</span>"
                    f"<span style='color:{color}'>{risk}</span></div>",
                    unsafe_allow_html=True
                )
            is_premium = plan in ("enterprise", "business")
            if not is_premium:
                st.markdown(
                    "<div style='background:linear-gradient(135deg,#1a0a0a,#2a0f0f);"
                    "border:2px solid #ef4444;border-radius:16px;padding:28px 24px;"
                    "text-align:center;margin:20px 0'>"
                    "<div style='font-size:2.5rem;margin-bottom:8px'>🔒</div>"
                    "<div style='color:#f0f6ff;font-size:1.1rem;font-weight:700;"
                    "margin-bottom:6px'>Continuous Brand Protection Active</div>"
                    "<div style='color:#ef4444;font-size:0.85rem;margin-bottom:16px;"
                    "background:#2a0a0a;display:inline-block;padding:4px 16px;"
                    "border-radius:100px'>⚠ PREVIEW MODE</div>"
                    "<div style='color:#94a3b8;font-size:0.9rem;margin-bottom:20px'>"
                    "Upgrade to <strong>Enterprise Plan ($99/mo)</strong> to enable "
                    "live automated takedown requests for malicious domains.</div>"
                    "<a href='#billing-tab' style='display:inline-block;"
                    "background:#3b82f6;color:#fff;padding:10px 32px;border-radius:10px;"
                    "text-decoration:none;font-weight:600'>⬆ Upgrade Now</a>"
                    "</div>", unsafe_allow_html=True
                )
            else:
                st.success("✅ Enterprise plan active — automated takedown requests enabled.")


    # ═════════════════════════════════════════════════════════════════════════════
    # TAB — OCR / HOMOGRAPH DETECTION
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("threat_mode", "STIX Intelligence") == "OCR Detection":
    with tab_ocr:
        st.markdown("## 👁 OCR & Homograph Detection")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Scan URLs for IDN homograph "
            "attacks (Cyrillic/Latin confusables) and decode Punycode domains.</p>",
            unsafe_allow_html=True,
        )
        st.divider()

        if not _HAS_OCR:
            st.warning(
                "⚠ OCR/Homograph module requires easyocr or tesseract. "
                "Not available on HF Spaces — run locally for image OCR.",
            )
            st.stop()

        col_o1, col_o2 = st.columns(2)
        with col_o1:
            st.markdown("#### 🔗 URL Homograph Check")
            ocr_url = st.text_input(
                "Enter a URL to check",
                placeholder="https://www.аpple.com (Cyrillic 'а')",
                label_visibility="collapsed",
                key="ocr_url_input",
            )
            if st.button("🔍 Check Homograph", use_container_width=True, key="ocr_check"):
                if ocr_url.strip():
                    with st.spinner("Analysing URL for homograph attacks..."):
                        h_result = check_url_for_homograph(ocr_url.strip())
                    st.session_state["h_result"] = h_result
                    st.rerun()

            h_result = st.session_state.get("h_result")
            if h_result:
                st.divider()
                is_homo = h_result.get("is_homograph", False)
                if is_homo:
                    st.error(
                        f"🚨 **Homograph attack detected** — "
                        f"`{h_result['decoded_punycode'] or h_result['ascii_domain']}` "
                        f"lookalike of `{h_result.get('visual_lookalike_of', 'unknown')}`"
                    )
                else:
                    st.success("🟢 No homograph detected.")

                st.markdown(
                    f"**Domain:** `{h_result.get('domain', '')}`  \n"
                    f"**ASCII:** `{h_result.get('ascii_domain', '')}`  \n"
                    f"**Punycode:** `{h_result.get('decoded_punycode', 'none')}`  \n"
                    f"**Risk score:** {h_result.get('risk_score', 0)}/100"
                )

        with col_o2:
            st.markdown("#### 📋 Recent Homograph Alerts")
            try:
                conn = get_connection()
                c = conn.cursor()
                c.execute(
                    "SELECT original_domain, homograph_type, visual_lookalike_of, "
                    "risk_score, timestamp FROM homograph_alerts ORDER BY id DESC LIMIT 20"
                )
                alerts = c.fetchall()
                conn.close()
                if alerts:
                    for ad, htype, lookalike, rscore, ts in alerts:
                        st.markdown(
                            f"<div style='background:#111827;border:1px solid #1e3a5f;"
                            f"border-radius:10px;padding:8px 12px;margin:4px 0'>"
                            f"<div style='color:#ff8888;font-size:12px'>{ad}</div>"
                            f"<div style='color:#475569;font-size:11px'>{htype} → "
                            f"{lookalike} · score {rscore}</div>"
                            f"<div style='color:#334155;font-size:10px'>{ts[:16]}</div>"
                            f"</div>", unsafe_allow_html=True
                        )
                else:
                    st.info("No homograph alerts yet.")
            except Exception:
                st.info("No homograph alerts yet.")

    # ═════════════════════════════════════════════════════════════════════════════
    # TAB — CAMPAIGNS (Phishing Simulation)
    # ═════════════════════════════════════════════════════════════════════════════
with tab_campaigns:
    st.markdown("## 🎯 Phishing Simulation Campaigns")
    st.markdown(
        "<p style='color:#64748b;margin-top:-8px'>Create and launch simulated "
        "phishing attacks to train users. Track opens, clicks, and reports.</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    col_camp1, col_camp2 = st.columns([2, 1])
    with col_camp1:
        st.markdown("### 📋 Existing Campaigns")
        campaigns = get_campaigns()
        if not campaigns:
            st.info("No campaigns yet. Create one below.")
        else:
            for c in campaigns:
                cid, cname, tname, targets, sent, opened, clicked, reported, status, created = c
                with st.expander(f"**{cname}** — {status} — {sent}/{targets} sent"):
                    st.markdown(
                        f"**Template:** {tname}  \n"
                        f"**Status:** {status}  \n"
                        f"**Sent:** {sent}/{targets}  \n"
                        f"**Opened:** {opened}  \n"
                        f"**Clicked:** {clicked}  \n"
                        f"**Reported:** {reported}  \n"
                        f"**Created:** {created[:19] if created else '—'}"
                    )
                    if status == "draft" and st.button("🚀 Launch Campaign", key=f"launch_{cid}"):
                        result = launch_campaign(cid)
                        if result.get("success"):
                            st.success(f"Campaign launched! Emails sent to {result.get('sent', 0)} recipients.")
                            st.rerun()
                        else:
                            st.error(result.get("error", "Launch failed"))
                    results = get_campaign_results(cid)
                    if results:
                        st.markdown("**Results breakdown:**")
                        for r in results[-20:]:
                            remail, rstatus, rsent, ropened, rclicked, rreported = r
                            icons = {"sent": "📤", "opened": "👁", "clicked": "🖱", "reported": "🚨"}
                            st.markdown(
                                f"<div style='background:#111827;border:1px solid #1e3a5f;"
                                f"border-radius:6px;padding:4px 8px;margin:2px 0;font-size:12px'>"
                                f"{icons.get(rstatus, '📄')} {remail} — {rstatus}</div>",
                                unsafe_allow_html=True,
                            )

    with col_camp2:
        st.markdown("### ➕ New Campaign")
        with st.form("campaign_form"):
            camp_name = st.text_input("Campaign Name", placeholder="Q1 Phishing Test")
            templates = get_templates()
            t_options = {f"{t['name']} ({t['category']}, {t['difficulty']})": t["id"] for t in templates}
            if t_options:
                selected_t = st.selectbox("Template", list(t_options.keys()))
            else:
                selected_t = None
                st.info("No templates found.")
            targets_text = st.text_area(
                "Targets (one email per line)",
                placeholder="alice@company.com\nbob@company.com",
            )
            if st.form_submit_button("🎣 Create & Launch", type="primary"):
                if camp_name and selected_t and targets_text.strip():
                    targets = [{"email": e.strip()} for e in targets_text.strip().split("\n") if e.strip()]
                    template_id = t_options[selected_t]
                    result = create_campaign(camp_name, template_id, targets, created_by=username)
                    if result.get("success"):
                        cid = result["campaign_id"]
                        st.success(f"Campaign #{cid} created!")
                        launch = launch_campaign(cid)
                        if launch.get("success"):
                            st.success(f"Launched! Sent to {launch.get('sent', 0)} recipients.")
                        st.rerun()
                    else:
                        st.error(result.get("error", "Failed to create campaign"))
                else:
                    st.warning("Fill in all fields.")

    st.divider()
    st.markdown("### 🤖 Generate Template with AI")
    with st.form("ai_template_form"):
        topic = st.text_input("Topic", "urgent invoice payment", placeholder="e.g. password reset, shared doc")
        if st.form_submit_button("✨ Generate", type="primary"):
            with st.spinner("LLM generating template..."):
                tpl = generate_llm_template(topic)
            if tpl.get("success"):
                st.code(
                    f"Subject: {tpl['subject']}\n\n{tpl['body']}",
                    language="text",
                )
                st.success("Generated! Available in templates list.")
            else:
                st.error(tpl.get("error", "Generation failed"))

# ═════════════════════════════════════════════════════════════════════════════
# TAB — API DOCS (Swagger UI)
# ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("dev_mode", "API Reference") == "API Reference":
    with tab_api_docs:
        st.markdown("## 📖 REST API Reference")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Interactive documentation "
            "for the PhishGuard REST API. Generate an API key in Settings to get started.</p>",
            unsafe_allow_html=True,
        )
        st.divider()

        api_base = ENV.APP_URL or "http://localhost:8080"
        st.markdown(
            f"**Base URL:** `{api_base}`  \n"
            f"**Auth:** `X-PhishGuard-Key` header  \n"
            f"**Spec:** `/api/v1/openapi.json`"
        )
        st.divider()

        st.components.v1.html(
            f"""<!DOCTYPE html><html lang="en"><head>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
            </head><body>
            <div id="swagger-ui"></div>
            <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
            <script>
              SwaggerUIBundle({{
                url: '{api_base}/api/v1/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [SwaggerUIBundle.presets.apis],
                layout: 'BaseLayout',
                docExpansion: 'list',
                defaultModelsExpandDepth: -1,
              }});
            </script>
            <style>
              body {{ margin:0; background:#0d1117; }}
              .swagger-ui .topbar {{ display:none; }}
              .swagger-ui .info .title {{ color:#e2e8f0; }}
              .swagger-ui .scheme-container {{ background:#111827; }}
              .swagger-ui .opblock-tag {{ color:#60a5fa; }}
              .swagger-ui .opblock-summary-path {{ font-weight:700; }}
              .swagger-ui .opblock-summary-description {{ color:#94a3b8; }}
              .swagger-ui .parameter__name, .swagger-ui label {{ color:#e2e8f0; }}
            </style>
            </body></html>""",
            height=800,
            scrolling=True,
        )
        st.info("💡 For local development, the API proxy runs on port 8080 via `python api_proxy.py`")

    # ═════════════════════════════════════════════════════════════════════════════
    # NEW TAB — AUDIT LOG
    # ═════════════════════════════════════════════════════════════════════════════
if is_admin:
    if st.session_state.get("admin_mode", "Dashboard") == "Audit":
            with tab_audit:
                from src.ui_audit_log import render_audit_log_tab
                render_audit_log_tab()

        # ═════════════════════════════════════════════════════════════════════════════
        # NEW TAB — PERFORMANCE MONITOR
        # ═════════════════════════════════════════════════════════════════════════════
if is_admin:
    if st.session_state.get("admin_mode", "Dashboard") == "Performance":
            with tab_perf:
                from src.ui_performance import render_performance_tab
                render_performance_tab()

        # ═════════════════════════════════════════════════════════════════════════════
        # TAB — M&A DILIGENCE (Acquire.com Valuation Optimizer)
        # ═════════════════════════════════════════════════════════════════════════════
    if st.session_state.get("admin_mode", "Dashboard") == "M&A":
        with tab_ma:
            st.markdown("## 📈 M&A Diligence Dashboard")
            st.markdown(
                "<p style='color:#94a3b8'>Verified transaction telemetry for acquirer due diligence. "
                "Audit-proof logs of user engagement, ARR, and SDE multiples.</p>",
                unsafe_allow_html=True,
            )
            st.divider()

            from src.database import get_valuation_logs, get_valuation_summary
            v = get_valuation_summary()

            col_v1, col_v2, col_v3, col_v4 = st.columns(4)
            col_v1.markdown(
                "<div class='stat-card'>"
                f"<div style='font-size:2rem;font-weight:900;color:#60a5fa'>{v['total_scans']}</div>"
                "<div style='color:#64748b;font-size:0.85rem'>Total Scans Logged</div></div>",
                unsafe_allow_html=True
            )
            col_v2.markdown(
                "<div class='stat-card'>"
                f"<div style='font-size:2rem;font-weight:900;color:#22c55e'>{v['unique_users']}</div>"
                "<div style='color:#64748b;font-size:0.85rem'>Active Users</div></div>",
                unsafe_allow_html=True
            )
            col_v3.markdown(
                "<div class='stat-card'>"
                f"<div style='font-size:1.5rem;font-weight:900;color:#eab308'>${v['estimated_arr']:,.0f}</div>"
                "<div style='color:#64748b;font-size:0.85rem'>Estimated ARR</div></div>",
                unsafe_allow_html=True
            )
            col_v4.markdown(
                "<div class='stat-card'>"
                f"<div style='font-size:1.5rem;font-weight:900;color:#22c55e'>${v['estimated_sde']:,.0f}</div>"
                "<div style='color:#64748b;font-size:0.85rem'>Est. SDE (2.5x)</div></div>",
                unsafe_allow_html=True
            )

            st.divider()
            col_va, col_vb = st.columns(2)
            with col_va:
                st.markdown("### 📊 Performance Metrics")
                st.metric("Avg Scan Latency", f"{v['avg_latency_ms']}ms")
                st.metric("Avg Risk Score", f"{v['avg_risk_score']}/100")
                st.metric("Unique Sessions", v["unique_sessions"])
                st.metric("Valuation Range", v["valuation_range"])
            with col_vb:
                st.markdown("### 👥 User Tier Distribution")
                if v["tier_distribution"]:
                    for tier, cnt in v["tier_distribution"].items():
                        pct = cnt / v["total_scans"] * 100 if v["total_scans"] else 0
                        st.markdown(
                            f"<div style='display:flex;justify-content:space-between;"
                            f"padding:4px 8px;background:#111827;border-radius:6px;margin:3px 0'>"
                            f"<span style='color:#94a3b8'>{tier.upper()}</span>"
                            f"<span style='color:#e2e8f0'>{cnt} scans ({pct:.1f}%)</span></div>",
                            unsafe_allow_html=True,
                        )
                else:
                    st.info("No tier data yet.")

            st.divider()
            st.markdown("### 📜 Verified Transaction Log")
            st.caption("Last 100 scan events with latency, risk, and user metadata")
            logs = get_valuation_logs(100)
            if logs:
                log_rows = ""
                for row in logs:
                    ts, sid, lat, score, sev, cat, tier, user, src = row
                    sev_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffaa00", "LOW": "#44aa44"}.get(sev, "#94a3b8")
                    log_rows += (
                        f"<tr style='border-bottom:1px solid #1e3a5f'>"
                        f"<td style='padding:4px 8px;color:#475569;font-size:11px'>{ts[:19]}</td>"
                        f"<td style='padding:4px 8px;color:#60a5fa;font-size:11px'>{sid}</td>"
                        f"<td style='padding:4px 8px;color:#94a3b8;font-size:11px'>{lat}ms</td>"
                        f"<td style='padding:4px 8px;color:{sev_color};font-size:11px'>{score}/100</td>"
                        f"<td style='padding:4px 8px;color:{sev_color};font-size:11px'>{sev}</td>"
                        f"<td style='padding:4px 8px;color:#94a3b8;font-size:11px'>{cat[:30]}</td>"
                        f"<td style='padding:4px 8px;color:#eab308;font-size:11px'>{tier}</td>"
                        f"<td style='padding:4px 8px;color:#94a3b8;font-size:11px'>{user}</td>"
                        f"<td style='padding:4px 8px;color:#94a3b8;font-size:11px'>{src}</td></tr>"
                    )
                st.markdown(
                    "<div style='overflow-x:auto;max-height:400px;overflow-y:scroll'>"
                    "<table style='width:100%;border-collapse:collapse'>"
                    "<thead style='position:sticky;top:0;background:#0a0f1a'>"
                    "<tr style='border-bottom:2px solid #1e3a5f'>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Timestamp</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Session</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Latency</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Score</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Severity</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Category</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Tier</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>User</th>"
                    "<th style='padding:8px;color:#64748b;font-size:11px;text-align:left'>Source</th></tr></thead>"
                    f"<tbody>{log_rows}</tbody></table></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.info("No scan telemetry yet. Scan an email to populate the valuation log.")

            st.divider()
            st.markdown(
                "<div style='background:#111827;border:1px solid #eab30844;border-radius:12px;padding:20px'>"
                "<div style='color:#eab308;font-weight:700;margin-bottom:8px'>💰 Pre-Revenue Valuation Estimate</div>"
                f"<p style='color:#94a3b8;font-size:13px'>Based on <strong>{v['unique_users']}</strong> active users "
                f"with <strong>{v['total_scans']}</strong> verified scan events, estimated ARR is "
                f"<strong style='color:#22c55e'>${v['estimated_arr']:,.0f}</strong> "
                f"and SDE (Seller's Discretionary Earnings) at 2.5x is "
                f"<strong style='color:#22c55e'>${v['estimated_sde']:,.0f}</strong>.</p>"
                "<p style='color:#64748b;font-size:12px'>Valuation range on Acquire.com/Microns.io: "
                f"<strong>{v['valuation_range']}</strong>. "
                "These metrics are auditable through the verified transaction log above.</p>"
                "</div>",
                unsafe_allow_html=True,
            )

        # ═════════════════════════════════════════════════════════════════════════════
        # NEW TAB — WEBHOOK TESTER
        # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("dev_mode", "API Reference") == "Webhook Tester":
    with tab_webhook:
        from src.ui_webhook_tester import render_webhook_tester_tab
        render_webhook_tester_tab()

    # ═════════════════════════════════════════════════════════════════════════════
    # NEW TAB — SOC DASHBOARD
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("dash_mode", "Overview") == "SOC":
    with tab_soc:
        from src.ui_soc_dashboard import render_soc_dashboard
        render_soc_dashboard(username)

    # ═════════════════════════════════════════════════════════════════════════════
    # NEW TAB — ACTIVITY TIMELINE
    # ═════════════════════════════════════════════════════════════════════════════
if st.session_state.get("dash_mode", "Overview") == "Timeline":
    with tab_timeline:
        from src.activity_timeline import get_activity, init_activity_timeline, record_activity
        init_activity_timeline()
        st.markdown("## 📋 Activity Timeline")
        st.caption("Your recent actions and events across the platform.")

        col_f1, col_f2 = st.columns(2)
        with col_f1:
            action_filter = st.selectbox("Filter by action", ["All", "login", "scan", "export",
                                                               "api_key_created", "settings_update",
                                                               "admin_action"], key="tl_filter")
        with col_f2:
            limit = st.selectbox("Show", [20, 50, 100], index=0, key="tl_limit")

        activities = get_activity(username, limit=limit)
        if action_filter and action_filter != "All":
            activities = [a for a in activities if a["action"] == action_filter]

        if activities:
            for a in activities:
                sev_colors = {"info": "#94a3b8", "warning": "#ff8800", "error": "#ff4444"}
                sev_color = sev_colors.get(a.get("severity", "info"), "#94a3b8")
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;padding:6px 10px;"
                    f"background:#111827;border:1px solid #1e3a5f;border-radius:6px;margin:3px 0'>"
                    f"<span style='color:#60a5fa'>{a['action']}</span>"
                    f"<span style='color:#e2e8f0;font-size:13px'>{a.get('detail', '')[:80]}</span>"
                    f"<span style='color:{sev_color};font-size:12px'>{a.get('created_at', '')[:19]}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(empty_state(
                "📋",
                "No activity recorded yet",
                "Your team's actions — analyses, logins, configuration changes — will appear here in real time.",
            ), unsafe_allow_html=True)

        record_activity(username, "view_timeline", detail="Viewed activity timeline")

    # ═════════════════════════════════════════════════════════════════════════════
    # NEW TAB — SCIM / AUDIT LOG (non-admin webhook tester only)
    # ═════════════════════════════════════════════════════════════════════════════
