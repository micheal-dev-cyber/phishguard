import os
import time
import json
import streamlit as st
import plotly.graph_objects as go
from datetime import datetime
from pathlib import Path

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡",
                   layout="wide", initial_sidebar_state="collapsed")

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
            from src.tenants import verify_tenant, create_tenant
            _username = _info["email"].split("@")[0].replace(".", "_")
            _existing = verify_tenant(_username, _info["email"])
            if not _existing or _existing.get("error") == "suspended":
                pass
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
from src.detector import analyze_email
from src.database import init_db, save_analysis, get_history
from src.report_generator import generate_pdf_report
from src.auth import check_password, logout
from src.session_manager import create_session, list_sessions, revoke_session, revoke_all_sessions, cleanup_expired
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.osint import run_osint
from src.admin import get_stats, get_all_analyses, get_recent_threats, get_daily_counts
from src.alerts import send_threat_alert, get_alert_log
from src.header_auth import analyze_auth_headers
from src.copilot import get_copilot_response, SUGGESTED_PROMPTS
from src.ai_analyzer import simulate_phishing, analyze_screenshot, generate_ai_report
from src.xai_analyzer import analyze_psychological_triggers, format_xai_report
from src.email_parser import parse_email_file
from src.brand_impersonation import run_brand_impersonation_check as _run_brand_check
from src.jury_engine import evaluate_linguistic_jury, evaluate_corporate_jury, compute_ensemble_score
from src.b2b_gateway import get_tier_config, check_feature_access, MockAPIGateway
from src.webhook_gateway import send_alert as send_webhook_alert
from src.threat_scorer import compute_combined_threat_score, format_combined_report
from src.tenants import (
    log_usage, check_quota, get_all_tenants, get_usage_all_tenants,
    create_tenant, update_tenant, delete_tenant, set_password, PLANS
)
try:
    from src.paddle_billing import (
        is_configured as paddle_configured,
        generate_checkout_url,
        verify_transaction,
        get_local_subscription,
        get_subscription,
        get_price_id,
        get_customer_portal_url,
        get_invoices,
        pause_subscription,
        cancel_subscription,
        resume_subscription,
        update_subscription_plan,
    )
except Exception:
    paddle_configured = lambda: False
    generate_checkout_url = lambda *a, **kw: None
    verify_transaction = lambda *a, **kw: None
    get_local_subscription = lambda *a, **kw: None
    get_subscription = lambda *a, **kw: None
    get_price_id = lambda *a, **kw: None
    get_customer_portal_url = lambda *a, **kw: None
    get_invoices = lambda *a, **kw: []
    pause_subscription = cancel_subscription = resume_subscription = update_subscription_plan = lambda *a, **kw: False
from src.ratelimit import check_rate_limit, get_rate_limit_remaining
from src.leaderboard import render_leaderboard, record_scan as lb_record_scan
from src.env import ENV, get_config_status, log_config_status
from src.campaign_engine import (
    get_templates, create_campaign, launch_campaign, get_campaigns,
    get_campaign_results, generate_llm_template
)
from src.weekly_report import generate_weekly_report
from src.notifications import push_notification, get_notifications, mark_read, mark_all_read, unread_count
from src.session_manager import create_session, list_sessions, revoke_session, revoke_all_sessions
from src.retention import get_retention_policy, set_retention_policy, purge_old_data
from src.ip_allowlist import add_ip_rule, remove_ip_rule, list_ip_rules
from src.custom_rules import add_rule, remove_rule, list_rules, toggle_rule
from src.workspace import (
    create_workspace, invite_member, remove_member, list_workspaces,
    get_members, get_workspace, user_role, user_workspace_id
)
from src.gdpr import export_user_data, delete_user_data, record_consent, check_consent
from src.integrations import (
    list_integrations, save_integration, remove_integration, get_available_providers, REGISTRY
)
from src.auto_responder import send_phishing_warning
from src.i18n import t, SUPPORTED_LANGUAGES

# ── RBAC permissions ────────────────────────────────────────────────────────
from src.rbac import init_rbac, check_permission
init_rbac()

# ── Structured JSON logging (opt-in via JSON_LOG=true) ──────────────────────
from src.json_logger import setup_json_logging
setup_json_logging()

# ── Enterprise component imports (with guards for optional deps) ──
try:
    from src.threat_intel_sharing import (
        check_collective_immunity, get_all_active_indicators,
        broadcast_intel, immunise_from_analysis,
    )
    _HAS_STIX = True
except Exception:
    _HAS_STIX = False

try:
    from src.sender_profiler import (
        get_or_create_profile, update_profile_after_scan,
        detect_behavioural_anomaly, get_sender_history,
        get_all_profiles_summary,
    )
    _HAS_SENDER_PROFILER = True
except Exception:
    _HAS_SENDER_PROFILER = False

try:
    from src.ocr_homograph import (
        check_url_for_homograph, decode_punycode,
        scan_ocr_text_for_threats,
    )
    _HAS_OCR = True
except Exception:
    _HAS_OCR = False

try:
    from src.url_sandbox import (
        analyse_url_sandbox_sync, get_sandbox_history,
    )
    _HAS_URL_SANDBOX = True
except Exception:
    _HAS_URL_SANDBOX = False

# ── Paddle Webhook endpoint (mounted on Streamlit's Tornado server) ───────
try:
    from src.paddle_billing import verify_webhook_signature, handle_webhook_event
    import tornado.web
    from streamlit.web.server import Server

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

    _orig_start = Server.start
    def _patched_start(self, *args, **kwargs):
        self._tornado.add_handlers(r".*", [(r"/webhook", _PaddleWebhookHandler)])
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
def _cached_stats():
    from src.admin import get_stats as _gs
    return _gs()

@st.cache_data(ttl=60)
def _cached_threats(limit: int = 10):
    from src.admin import get_recent_threats as _gt
    return _gt(limit)

@st.cache_data(ttl=60)
def _cached_daily_counts(days: int = 14):
    from src.admin import get_daily_counts as _gd
    return _gd(days)

@st.cache_data(ttl=60)
def _cached_all_analyses(limit: int = 100):
    from src.admin import get_all_analyses as _ga
    return _ga(limit)

theme = st.session_state.get("theme", "dark")
bg_main = "#0d1117" if theme == "dark" else "#ffffff"
bg_card = "#111827" if theme == "dark" else "#f3f4f6"
text_main = "#e2e8f0" if theme == "dark" else "#1f2937"
text_sec  = "#94a3b8" if theme == "dark" else "#6b7280"
border_c  = "#1e3a5f" if theme == "dark" else "#d1d5db"
from src.ui_theme import apply_theme
apply_theme(theme)
st.markdown("""
<style>
.block-container { padding-top: 1.5rem; }
.stApp { background-color: """ + bg_main + """; }
.tag {
    display: inline-block; background: #1e3a5f; color: #60a5fa;
    border-radius: 6px; padding: 3px 10px; margin: 3px;
    font-size: 13px; font-family: monospace;
}
.url-box {
    background: #1a0a0a; border: 1px solid #ff4444; border-radius: 8px;
    padding: 10px 14px; font-family: monospace; font-size: 13px;
    color: #ff8888; margin: 5px 0;
}
.safe-url-box {
    background: #0a1a0a; border: 1px solid #44aa44; border-radius: 8px;
    padding: 10px 14px; font-family: monospace; font-size: 13px;
    color: #88cc88; margin: 5px 0;
}
.section-title {
    color: #60a5fa; font-size: 1.1rem; font-weight: 700;
    margin: 18px 0 8px 0; border-left: 3px solid #60a5fa; padding-left: 10px;
}
.stat-card {
    background: #111827; border: 1px solid #1e3a5f;
    border-radius: 12px; padding: 20px; text-align: center;
}
.quota-bar-bg { background: #1e3a5f; border-radius: 6px; height: 10px; margin: 6px 0; }
.quota-bar-fill { border-radius: 6px; height: 10px; }
.quarantine-badge { display:inline-block; background:#ff4444; color:#fff; border-radius:100px;
    padding:2px 10px; font-size:10px; font-weight:700; letter-spacing:.08em; margin-left:6px; }
@media (max-width: 768px) {
    .block-container { padding: 1rem 0.5rem !important; }
    .auth-card { padding: 24px 16px !important; }
    h1 { font-size: 1.8rem !important; }
    h2 { font-size: 1.3rem !important; }
    div[data-testid="column"] { min-width: 100% !important; }
    .stTabs [data-baseweb="tab-list"] { gap: 0 !important; overflow-x: auto !important; }
    .stTabs [data-baseweb="tab"] { font-size: 11px !important; padding: 4px 8px !important; }
    .stat-card { padding: 12px 8px !important; }
}
</style>
""", unsafe_allow_html=True)

init_db()
log_config_status()

# ── Start background task queue worker ──────────────────────────────────────
try:
    from src.task_queue import start_worker
    start_worker()
except Exception as e:
    import logging
    logging.getLogger("phishguard").warning(f"Task queue worker failed: {e}")

# ── Start real-time notification poller ─────────────────────────────────────
if "notification_check" not in st.session_state:
    st.session_state["notification_check"] = 0

# ── Startup config banner (admin only) ──────────────────────────────────────
if st.session_state.get("is_admin"):
    cfg_status = get_config_status()
    missing = [k for k, v in cfg_status.items() if isinstance(v, dict) and not v["configured"]]
    if missing:
        import logging
        logger = logging.getLogger("phishguard")
        logger.warning("Missing API keys on startup: %s", ", ".join(missing))
        with st.sidebar.expander("⚠️ Configuration Status", expanded=True):
            st.caption("Set these via HF Space → Settings → Variables and secrets:")
            for key in missing:
                st.markdown(f"- `{key}`")
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

# ── Header ───────────────────────────────────────────────────────────────────
col_title, col_quota, col_user = st.columns([3, 2, 1])

with col_title:
    st.markdown(
        "<h1 style='color:#60a5fa;font-size:2rem;margin-bottom:0'>🛡 PhishGuard AI</h1>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<p style='color:#94a3b8;margin-top:2px'>AI-Powered Phishing & Threat Detection</p>",
        unsafe_allow_html=True
    )

with col_quota:
    q = check_quota(username, plan)
    plan_label = PLANS.get(plan, PLANS["trial"])["label"]
    limit_display = "∞" if plan == "enterprise" else str(q["limit"])
    bar_color = "#ff4444" if q["pct"] >= 90 else "#ffaa00" if q["pct"] >= 70 else "#60a5fa"
    bar_width = q["pct"] if plan != "enterprise" else 0
    upgrade_link = ""
    if plan != "enterprise" and paddle_configured():
        upgrade_link = "<span style='cursor:pointer;color:#3b82f6;font-size:11px' onclick=''>⬆ Upgrade</span>"
    quota_html = (
        "<div style='margin-top:10px;padding:8px 14px;background:#111827;"
        "border-radius:10px;border:1px solid #1e3a5f'>"
        "<div style='display:flex;justify-content:space-between;"
        "font-size:12px;color:#94a3b8;margin-bottom:4px'>"
        "<span>📊 " + plan_label + " plan " + upgrade_link + "</span>"
        "<span>" + str(q["usage"]) + " / " + limit_display + " analyses</span>"
        "</div>"
        "<div class='quota-bar-bg'>"
        "<div class='quota-bar-fill' style='width:" + str(bar_width) + "%;background:" + bar_color + "'></div>"
        "</div></div>"
    )
    st.markdown(quota_html, unsafe_allow_html=True)

    # ── Pay-Per-Scan Credit Counter ───────────────────────────────────────
    if "sandbox_credits" not in st.session_state:
        st.session_state["sandbox_credits"] = 3
    credits = st.session_state["sandbox_credits"]
    credit_pct = min(100, credits)  # visual meter out of 100 max
    credit_color = "#22c55e" if credits > 20 else "#eab308" if credits > 5 else "#ef4444"
    st.markdown(
        "<div style='margin-top:8px;padding:10px 14px;background:#111827;"
        "border-radius:10px;border:1px solid #1e3a5f'>"
        "<div style='display:flex;justify-content:space-between;font-size:12px;"
        "color:#94a3b8;margin-bottom:4px'>"
        "<span>🔬 Deep Sandbox Credits</span>"
        "<span style='color:" + credit_color + ";font-weight:700'>"
        + str(credits) + " / 100</span></div>"
        "<div style='background:#1e3a5f;border-radius:4px;height:5px'>"
        "<div style='background:" + credit_color + ";border-radius:4px;height:5px;"
        "width:min(" + str(credit_pct) + "%,100%)'></div></div>"
        "</div>", unsafe_allow_html=True
    )
    col_cc1, col_cc2 = st.columns(2)
    with col_cc1:
        if st.button("💰 Buy 100 Credits ($10)", key="buy_credits", use_container_width=True):
            st.session_state["show_credit_checkout"] = True
    with col_cc2:
        if st.button("🔁 Reset Demo", key="reset_credits", use_container_width=True):
            st.session_state["sandbox_credits"] = 3
            st.rerun()
    if st.session_state.get("show_credit_checkout"):
        st.info(
            "🛒 Checkout simulation: 100 Advanced Sandbox Credits for $10. "
            "In production this would redirect to Stripe/Paddle checkout.",
            icon="💳"
        )

    # ── Consumption Metering & Hard Spending Cap ───────────────────────────
    from src.database import check_scan_quota, get_spending_cap, set_spending_cap
    quota_status = check_scan_quota(username)
    cap_status = get_spending_cap(username)
    st.markdown(
        "<div style='margin-top:8px;padding:10px 14px;background:#111827;"
        "border-radius:10px;border:1px solid #1e3a5f'>"
        "<div style='display:flex;justify-content:space-between;font-size:12px;"
        "color:#94a3b8;margin-bottom:4px'>"
        "<span>📊 Monthly Scans</span>"
        "<span style='font-weight:700'>" + str(quota_status["used"]) + " / "
        + str(quota_status["limit"]) + "</span></div>"
        "<div style='background:#1e3a5f;border-radius:4px;height:5px'>"
        "<div style='background:#60a5fa;border-radius:4px;height:5px;"
        "width:min(" + str(int(quota_status["used"] / max(quota_status["limit"], 1) * 100)) + "%,100%)'></div></div>"
        "</div>", unsafe_allow_html=True
    )
    if cap_status["paused"]:
        st.warning("⛔ Spending cap reached — scanning paused. Increase your cap to continue.")
    st.markdown(
        "<div style='margin-top:6px;padding:8px 14px;background:#111827;"
        "border-radius:10px;border:1px solid #1e3a5f'>"
        "<div style='display:flex;justify-content:space-between;font-size:12px;"
        "color:#94a3b8;margin-bottom:4px'>"
        "<span>💵 Hard Spending Cap</span>"
        "<span>$" + f"{cap_status['current_spend']:.2f}" + " / $"
        + f"{cap_status['hard_cap_usd']:.0f}" + "</span></div>"
        "</div>", unsafe_allow_html=True
    )
    cap_val = st.slider(
        "Set monthly cap ($)",
        min_value=0, max_value=500, value=int(cap_status["hard_cap_usd"]),
        step=10, key="cap_slider",
        label_visibility="collapsed",
    )
    if cap_val != int(cap_status["hard_cap_usd"]):
        set_spending_cap(username, float(cap_val))
        st.rerun()

    if st.button("⬆ Upgrade Plan", key="upgrade_btn", use_container_width=True):
        st.session_state["show_upgrade"] = True
        st.rerun()

    # ── Consultant White-Label Controls ────────────────────────────────────
    tier = plan
    is_consultant_plan = tier == "consultant"
    st.markdown("<hr style='border-color:#1e3a5f;margin:12px 0'>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:13px;color:#94a3b8;margin-bottom:6px'>📄 Report Branding</div>",
                unsafe_allow_html=True)
    if is_consultant_plan:
        uploaded_logo = st.file_uploader(
            "Upload company logo for PDF reports",
            type=["png", "jpg", "jpeg", "svg"],
            key="consultant_logo_upload",
            label_visibility="collapsed",
        )
        if uploaded_logo:
            import tempfile
            _tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            _tmp.write(uploaded_logo.getvalue())
            st.session_state["consultant_logo_path"] = _tmp.name
        wl_checked = st.checkbox("Export as White-Label Report", key="whitelabel_pdf")
        if wl_checked:
            st.caption("✅ All PhishGuard/SecOpsNode branding will be stripped")
    else:
        st.file_uploader(
            "Upload company logo for PDF reports",
            type=["png", "jpg", "jpeg", "svg"],
            key="consultant_logo_locked",
            disabled=True,
            label_visibility="collapsed",
            help="Available on Consultant Tier ($149/mo)",
        )
        st.checkbox(
            "Export as White-Label Report",
            key="whitelabel_pdf_locked",
            disabled=True,
            help="Available on Consultant Tier ($149/mo)",
        )
        st.caption("🔒 <span style='color:#eab308'>Available on Consultant Tier ($149/mo)</span>",
                   unsafe_allow_html=True)

with col_user:
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Notification Center + Auto-Poll ──────────────────────────────────
    from src.notifications import unread_count, get_notifications, mark_read, mark_all_read
    n_count = unread_count(username)
    n_badge = f'<span style="background:#ff4444;color:#fff;border-radius:50%;padding:1px 6px;font-size:10px;margin-left:4px">{n_count}</span>' if n_count else ""
    st.markdown(
        f'<div style="text-align:right;font-size:13px;color:#94a3b8">'
        f'🔔{n_badge} 👤 {username}</div>',
        unsafe_allow_html=True,
    )

    # Auto-poll: rerun every 30 seconds for live notification count
    poll_interval = st.session_state.get("notification_check", 0)
    if poll_interval >= 30:
        st.session_state["notification_check"] = 0
        st.rerun()
    st.session_state["notification_check"] = poll_interval + 1
    st.caption(f"Next check in {30 - poll_interval}s")

    if n_count > 0:
        with st.expander(f"🔔 {n_count} Notification(s)", expanded=False):
            for n in get_notifications(username, limit=10):
                colors = {"critical": "#ff4444", "warning": "#ff8800", "success": "#22c55e", "info": "#60a5fa"}
                c = colors.get(n["severity"], "#60a5fa")
                read_marker = "" if not n["is_read"] else "opacity:0.5"
                st.markdown(
                    f"<div style='border-left:3px solid {c};padding:4px 8px;margin:4px 0;"
                    f"background:#111827;border-radius:6px;font-size:12px;{read_marker}'>"
                    f"<span style='color:{c};font-weight:700'>{n['severity'].upper()}</span> "
                    f"<span style='color:#e2e8f0;font-weight:600'>{n['title']}</span> "
                    f"<span style='color:#94a3b8'>{n['message'][:80]}</span>"
                    f"<span style='color:#475569;display:block;font-size:10px'>{n['created_at'][:19]}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
                if st.button("✓ Mark read", key=f"notif_read_{n['id']}", use_container_width=True):
                    mark_read(n["id"])
                    st.rerun()
            if st.button("✓ Mark All Read", key="mark_all_read", use_container_width=True):
                mark_all_read(username)
                st.rerun()

    # ── Theme Toggle ─────────────────────────────────────────────────────
    from src.ui_theme import render_theme_toggle
    render_theme_toggle()

    if st.button("Logout", use_container_width=True):
        logout()

    # ── Language Selector ─────────────────────────────────────────────────
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

        if not paddle_configured():
            st.warning(
                "⚠️ Payment processing is not configured. "
                "Contact the administrator to set up Paddle."
            )
            if st.button("← Back", key="upgrade_back_no"):
                st.session_state["show_upgrade"] = False
                st.rerun()
            st.stop()

        cols = st.columns(3)
        upgrade_plans = [
            ("starter",    "Starter",     "$29/mo",  ["100 analyses/mo", "VirusTotal scans", "OSINT investigation", "AI security reports", "Email alerts"]),
            ("business",   "Business",    "$99/mo",  ["500 analyses/mo", "Everything in Starter", "Priority support", "Team access", "Export + API access"]),
            ("consultant", "Consultant",  "$149/mo", ["2000 analyses/mo", "Everything in Business", "White-label reports", "SOC dashboard", "All integrations"]),
            ("enterprise", "Enterprise",  "Custom",  ["Unlimited analyses", "SLA guarantee", "White-label option", "Dedicated support", "Custom integrations"]),
        ]
        for i, (pkey, plabel, pprice, pfeatures) in enumerate(upgrade_plans):
            with cols[i]:
                featured = pkey == "business"
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
                    + "<div style='color:#94a3b8;font-size:0.9rem;font-weight:600;"
                       "letter-spacing:0.05em;margin-bottom:8px'>" + plabel + "</div>"
                    + "<div style='color:#f0f6ff;font-size:2.4rem;font-weight:800;"
                       "margin-bottom:4px'>" + pprice + "</div>"
                    + "<div style='color:#475569;font-size:0.75rem;margin-bottom:20px;"
                       "font-family:monospace'>per month</div>"
                    + "<ul style='list-style:none;padding:0;margin:0 0 24px;text-align:left'>"
                    + "".join("<li style='color:#94a3b8;font-size:0.8rem;padding:4px 0;"
                              "border-bottom:1px solid rgba(255,255,255,0.04)'>→ " + f + "</li>"
                              for f in pfeatures)
                    + "</ul></div>",
                    unsafe_allow_html=True
                )

                already_on = plan == pkey
                if already_on:
                    st.success("✅ Current Plan")
                elif pkey == "enterprise":
                    st.info("Contact sales")
                else:
                    if st.button("⬆ Subscribe — " + plabel, key="sub_" + pkey, use_container_width=True, type="primary"):
                        with st.spinner("Creating checkout session..."):
                            base = getattr(getattr(st, 'context', None), 'headers', {}).get("Origin", "https://phishguard.streamlit.app")
                            success_url = base + "/?checkout=completed"
                            url = generate_checkout_url(username, pkey, success_url=success_url)
                        if url:
                            st.session_state["checkout_url"] = url
                            st.session_state["checkout_plan"] = pkey
                            st.rerun()
                        else:
                            st.error("Could not create checkout. Please try again.")

        # If checkout URL is set, show proceed button + success URL guidance
        checkout_url = st.session_state.get("checkout_url")
        if checkout_url:
            cplan = st.session_state["checkout_plan"]
            st.divider()
            st.markdown(f"### 🛒 Ready to subscribe to **{PLANS[cplan]['label']}**")
            st.info(
                "You will be redirected to Paddle's secure checkout. "
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

# ── Onboarding Wizard (first-time users) ───────────────────────────────────
try:
    from src.ui_onboarding import render_onboarding_wizard
    render_onboarding_wizard(username)
except Exception:
    pass

# ── Weekly Report Check ─────────────────────────────────────────────────────
try:
    from src.weekly_report import check_and_send_weekly
    _email = st.session_state.get("email", "")
    _wr_key = f"weekly_report_{username}"
    if _email and _wr_key not in st.session_state:
        st.session_state[_wr_key] = True
        check_and_send_weekly(username, _email)
except Exception:
    pass

# ── Tabs ─────────────────────────────────────────────────────────────────────
if is_admin:
    tabs = st.tabs([
        "🔍 Analyze Email", "📥 Inbox Scanner", "📈 Analytics", "🤖 AI Copilot",
        "⚙ Admin Dashboard", "👥 Clients",
        "💳 Billing", "⚙ Settings", "🧪 Training", "🏆 Champions", "📊 History",
        "🧬 STIX Intel", "📧 Sender Profiler", "🔗 URL Sandbox", "👁 OCR/Homograph",
        "🎯 Campaigns", "📖 API Docs",
        "📋 Audit Log", "📊 Performance", "📈 M&A Diligence",
        "🔌 Webhook Tester",
        "📡 SOC Dashboard", "📋 Activity Timeline",
    ])
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11, tab12, tab13, tab14, tab15, tab16, tab17, tab_audit, tab_perf, tab_ma, tab_webhook, tab_soc, tab_timeline = tabs
    tab_stix, tab_sender, tab_sandbox, tab_ocr, tab_campaigns, tab_api_docs = tab12, tab13, tab14, tab15, tab16, tab17
else:
    tabs = st.tabs([
        "🔍 Analyze Email", "📥 Inbox Scanner", "📈 Analytics", "🤖 AI Copilot",
        "💳 Billing", "⚙ Settings", "🧪 Training", "🏆 Champions", "📊 History",
        "🧬 STIX Intel", "📧 Sender Profiler", "🔗 URL Sandbox", "👁 OCR/Homograph",
        "🎯 Campaigns", "📖 API Docs",
        "🔌 Webhook Tester",
        "📡 SOC Dashboard", "📋 Activity Timeline",
    ])
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11, tab12, tab13, tab14, tab15, tab_webhook, tab_soc, tab_timeline = tabs
    tab_stix, tab_sender, tab_sandbox, tab_ocr, tab_campaigns, tab_api_docs = tab10, tab11, tab12, tab13, tab14, tab15

# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — ANALYZER
# ═════════════════════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — INBOX SCANNER
# ═════════════════════════════════════════════════════════════════════════════
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
            imap_host = st.text_input("IMAP Server", "imap.gmail.com", key="imap_host")
        with col_imap2:
            imap_port = st.number_input("Port", 993, key="imap_port")
        with col_imap3:
            imap_ssl = st.checkbox("SSL/TLS", True, key="imap_ssl")
        col_imap4, col_imap5, col_imap6 = st.columns(3)
        with col_imap4:
            imap_user = st.text_input("Email Address", key="imap_user")
        with col_imap5:
            imap_pass = st.text_input("Password / App Password", type="password", key="imap_pass")
        with col_imap6:
            imap_folder = st.text_input("Folder", "INBOX", key="imap_folder")
        col_imap7, col_imap8 = st.columns(2)
        with col_imap7:
            imap_hours = st.slider("Look back (hours)", 1, 168, 24, key="imap_hours")
        with col_imap8:
            imap_max = st.slider("Max emails", 1, 100, 20, key="imap_max")

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
    st.stop()

# ═════════════════════════════════════════════════════════════════════════════
with tab1:
    # ── Email Verification Banner ──────────────────────────────────────────
    try:
        from src.email_verify import is_email_verified
        if not is_email_verified(username):
            st.warning(
                "📧 **Email not verified.** You must verify your email before scanning. "
                "[Resend verification email](#) — check your inbox.",
                icon="⚠️"
            )
            st.stop()
    except Exception:
        pass

    q = check_quota(username, plan)
    if q["over_limit"] and plan != "enterprise":
        limit_val = q["limit"]
        st.error(
            f"🚫 Monthly limit reached ({limit_val} analyses). "
            "Upgrade your plan to continue."
        )
        st.stop()

    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown("#### 📧 Paste Email Content")

        # Initialise session_state for email text if not set
        if "email_input" not in st.session_state:
            st.session_state["email_input"] = ""

        # ── .eml / .msg file upload (must be before text_area to update it) ─
        st.markdown("##### 📎 Or upload an email file")
        uploaded_file = st.file_uploader(
            "Upload .eml or .msg",
            type=["eml", "msg"],
            label_visibility="collapsed",
            key="email_uploader",
        )
        if uploaded_file:
            with st.spinner("Parsing email file..."):
                parsed = parse_email_file(uploaded_file.getvalue(), uploaded_file.name)
            if parsed.get("error"):
                st.error(f"Parse error: {parsed['error']}")
            else:
                combined = (
                    f"From: {parsed.get('from', '')}\n"
                    f"Subject: {parsed.get('subject', '')}\n"
                    f"To: {parsed.get('to', '')}\n\n"
                    f"{parsed.get('body', '')}"
                )
                if combined.strip() != st.session_state["email_input"].strip():
                    st.session_state["email_input"] = combined
                    st.rerun()

        # ── Batch CSV/JSON upload ──────────────────────────────────────────
        batch_file = st.file_uploader(
            "📦 Batch upload CSV/JSON (one email per row/object)",
            type=["csv", "json"],
            key="batch_uploader",
        )
        if batch_file:
            try:
                import pandas as pd
                import json as _json
                if batch_file.name.endswith(".json"):
                    batch_data = _json.load(batch_file)
                else:
                    batch_data = pd.read_csv(batch_file).to_dict("records")
                if not batch_data:
                    st.warning("Batch file is empty.")
                else:
                    st.session_state["batch_inputs"] = batch_data
                    st.success(f"Loaded {len(batch_data)} emails for batch analysis.")
            except Exception as exc:
                st.error(f"Batch file error: {exc}")

        # ── Attachment Scanner (hash + VT file reputation) ──────────────────
        st.markdown("##### 🔒 Scan Attachment")
        att_file = st.file_uploader(
            "Upload an attachment to scan (PDF, DOCX, XLSX, ZIP, etc.)",
            type=["pdf", "docx", "xlsx", "pptx", "zip", "rar", "7z",
                  "exe", "dll", "ps1", "vbs", "js", "py", "scr", "bat",
                  "doc", "xls"],
            key="attachment_scanner",
            label_visibility="collapsed",
        )
        if att_file and "att_scan_result" not in st.session_state:
            from src.attachment_scanner import scan_attachment, is_allowed_attachment
            with st.spinner(f"Hashing {att_file.name}..."):
                att_result = scan_attachment(att_file.getvalue(), att_file.name)
            st.session_state["att_scan_result"] = att_result
            st.rerun()
        if st.session_state.get("att_scan_result"):
            _att = st.session_state["att_scan_result"]
            if _att.get("error"):
                st.error(f"Scan error: {_att['error']}")
            else:
                _vt = _att.get("vt_reputation", {})
                _v = _vt.get("verdict", "unknown") if isinstance(_vt, dict) else "unknown"
                _c = {"clean": "#44aa44", "malicious": "#ff4444", "suspicious": "#ff8800", "unknown": "#94a3b8"}.get(_v, "#94a3b8")
                st.markdown(
                    f"<div style='background:#111827;border:1px solid #1e3a5f;border-radius:10px;padding:8px 14px;font-size:13px'>"
                    f"<b>📎 {_att['filename']}</b> ({_att['size']:,} bytes)<br>"
                    f"MD5: <code style='color:#60a5fa'>{_att.get('md5','')[:16]}…</code><br>"
                    f"SHA256: <code style='color:#60a5fa'>{_att.get('sha256','')[:20]}…</code><br>"
                    f"VT Verdict: <span style='color:{_c};font-weight:700'>{_v.upper()}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            if st.button("✕ Clear Attachment", key="clear_att"):
                st.session_state.pop("att_scan_result", None)
                st.rerun()

        email_text = st.text_area(
            label="email", label_visibility="collapsed",
            placeholder="Paste the full email here — subject, headers, body, links...",
            height=260,
            key="email_input",
        )

    with col_right:
        st.markdown("#### ⚙ Options")
        st.checkbox("Analyze URLs", value=True)
        st.checkbox("Keyword Detection", value=True)
        st.checkbox("Social Engineering", value=True)
        enable_vt = st.checkbox("Threat Intelligence + OSINT", value=True)
        st.markdown("")
        enable_jury = st.checkbox("🧠 Multi-LLM Jury (ensemble scoring)", value=False,
                                   help="Routes text through linguistic and corporate context juries for weighted ensemble scoring")
        st.markdown("")
        analyze_btn = st.button("🔍 Analyze Email", use_container_width=True, type="primary")
        st.markdown("")
        batch_btn = st.button("📦 Batch Analyze", use_container_width=True,
                               help="Analyze all emails from CSV/JSON upload")

        st.markdown("")
        st.info("💡 Paste any suspicious email and click Analyze.")

    if batch_btn:
        batch_inputs = st.session_state.get("batch_inputs", [])
        if not batch_inputs:
            st.warning("Upload a CSV/JSON file with email data first.")
        else:
            rl_key = f"batch_{username}"
            if not check_rate_limit(rl_key, max_requests=3, window=60):
                st.error("⏳ Rate limit reached for batch (3/min).")
                st.stop()
            batch_results = []
            text_col = "text" if batch_inputs[0].get("text") else "email" if batch_inputs[0].get("email") else list(batch_inputs[0].keys())[0]
            progress = st.progress(0, text="Batch analysis in progress...")
            for i, row in enumerate(batch_inputs):
                t = (row.get(text_col) or "").strip()
                if t:
                    r = analyze_email(t)
                    save_analysis(r, t)
                    batch_results.append({"input": t[:80], "score": r["risk_score"], "severity": r["severity"]})
                progress.progress((i + 1) / len(batch_inputs), text=f"Analyzed {i + 1}/{len(batch_inputs)}")
            st.session_state["batch_results"] = batch_results
            st.success(f"✅ Batch complete — {len(batch_results)} emails analyzed.")
            st.rerun()

    if "batch_results" in st.session_state:
        with st.expander(f"📦 Batch Results ({len(st.session_state['batch_results'])} emails)", expanded=True):
            for br in st.session_state["batch_results"][-50:]:
                c = "#ff4444" if br["severity"] in ("CRITICAL","HIGH") else "#88cc88"
                st.markdown(f"<div style='font-size:12px;padding:4px 0'><span style='color:{c}'>{br['severity']:8}</span> {br['score']:3}/100 · {br['input']}</div>", unsafe_allow_html=True)
            if st.button("Clear Batch Results", key="clear_batch"):
                st.session_state.pop("batch_results", None)
                st.rerun()

    if analyze_btn:
        if not email_text.strip():
            st.warning("⚠ Please paste an email first.")
        else:
            rl_key = f"analyze_{username}"
            if not check_rate_limit(rl_key, max_requests=15, window=60):
                remaining = get_rate_limit_remaining(rl_key, max_requests=15, window=60)
                st.error(f"⏳ Rate limit reached. Please wait before submitting another analysis. ({remaining} remaining)")
                st.stop()
            with st.spinner("Scanning for threats..."):
                # Consumption metering check
                from src.database import consume_scan, get_spending_cap as _gsc
                _scan_ok = consume_scan(username)
                _cap = _gsc(username)
                if not _scan_ok["allowed"]:
                    st.error(
                        "⛔ **Monthly scan limit reached.** "
                        f"({_scan_ok['used']}/{_scan_ok['limit']} used). "
                        "Purchase additional credits or upgrade your plan to continue."
                    )
                    st.stop()
                if _cap["paused"]:
                    st.error("⛔ **Hard spending cap reached.** Increase your cap in settings to continue.")
                    st.stop()
                import time as _tmod; _start_time = _tmod.time()
                results = analyze_email(email_text)
                save_analysis(results, email_text)
                log_usage(username, "analysis", results["risk_score"])
                lb_record_scan(
                    username,
                    severity=results["severity"],
                    score=results["risk_score"],
                )
                # Record valuation telemetry for M&A diligence
                from src.database import record_valuation_metric
                record_valuation_metric(
                    scan_latency_ms=int((_tmod.time() - _start_time) * 1000),
                    risk_score=results["risk_score"],
                    severity=results["severity"],
                    threat_category=",".join(results.get("keyword_matches", {}).keys()) or "none",
                    username=username,
                    user_tier=plan,
                    source="web",
                )
                # Send email alert if HIGH or CRITICAL
                user_email = st.session_state.get("email", "")
                if user_email and results["severity"] in ("CRITICAL", "HIGH"):
                    send_threat_alert(username, user_email, results)

                # ── Automated Incident Response ────────────────────────────
                try:
                    from src.incident_response import IncidentResponder
                    ir = IncidentResponder()
                    ir_result = ir.respond(
                        verdict=results,
                        mailbox=user_email,
                        sender_email=results.get("headers", {}).get("From", ""),
                    )
                    if ir_result["actions"]:
                        st.toast(f"🛡 IR: {' → '.join(ir_result['actions'])}", icon="🛡")
                except Exception:
                    pass

                # ── SIEM Dispatch ──────────────────────────────────────────
                try:
                    from src.siem_webhook import SIEMClient
                    siem = SIEMClient()
                    if siem.any_enabled:
                        siem.dispatch({
                            "timestamp": datetime.now().isoformat(),
                            "username": username,
                            "risk_score": results["risk_score"],
                            "severity": results["severity"],
                            "urls_found": results.get("urls_found", []),
                            "sender": results.get("headers", {}).get("From", ""),
                        })
                except Exception:
                    pass

                # ── Auto-Training Assignment ───────────────────────────────
                try:
                    from src.auto_training import assign_training
                    if results["risk_score"] >= 40:
                        assign_training(username, results["risk_score"], results["severity"])
                except Exception:
                    pass

            vt_results = []
            vt_summary = {}
            osint_data = {}

            if enable_vt and results["urls_found"]:
                with st.spinner("Checking URLs against VirusTotal..."):
                    vt_results = check_multiple_urls(results["urls_found"])
                    vt_summary = get_threat_summary(vt_results)

            if enable_vt:
                with st.spinner("Running OSINT investigation..."):
                    osint_data = run_osint(email_text)

            # ── Multi-LLM Jury ensemble ────────────────────────────────────
            jury_result = {}
            if enable_jury:
                with st.spinner("🧠 Multi-LLM Jury evaluating linguistic anomalies..."):
                    linguistic = evaluate_linguistic_jury(email_text)
                with st.spinner("🧠 Multi-LLM Jury evaluating corporate context..."):
                    corporate = evaluate_corporate_jury(email_text)
                jury_result = compute_ensemble_score(
                    linguistic, corporate,
                    heuristic_score=results.get("risk_score", 0),
                )

            # ── Email Header Authentication (SPF/DKIM/DMARC) ────────────────
            header_auth = analyze_auth_headers(email_text)

            # ── XAI Psychological Trigger Analysis ─────────────────────────
            xai_result = analyze_psychological_triggers(email_text)

            # ── Phishing DNA / Known Campaign Matching ──────────────────────
            from src.phishing_dna import flagged_as_known_phishing
            dna_known, dna_match = flagged_as_known_phishing(email_text, st.session_state)

            # ── AI-Generated Text (Perplexity) Detector ─────────────────────
            from src.perplexity_analyzer import compute_perplexity_score
            perplexity_result = compute_perplexity_score(email_text)

            # ── AitM & OTP Harvester Detector ─────────────────────────────
            from src.aitm_detector import detect_aitm_harvester
            aitm_result = detect_aitm_harvester(
                email_text=email_text,
                urls=results.get("urls_found", []),
                osint_data=osint_data,
            )

            # ── Combined Threat Score (linguistic + VT reputation) ─────────
            combined_score = compute_combined_threat_score(
                results.get("risk_score", 0),
                vt_results=vt_results,
            )

            # ── Webhook alert (threshold >= 75 OR if VT confirms threats) ──
            wh_key = f"webhook_url_{username}"
            webhook_url = st.session_state.get(wh_key, "")
            webhook_result = None
            if webhook_url and (results.get("risk_score", 0) >= 75 or
                                combined_score.get("composite_score", 0) >= 75):
                triggers = []
                if xai_result.get("triggers"):
                    triggers = [t["label"] for t in xai_result["triggers"]]
                from src.webhook_gateway import send_alert
                webhook_result = send_alert(
                    webhook_url,
                    score=results.get("risk_score", 0),
                    severity=results.get("severity", "HIGH"),
                    triggers=triggers,
                    snippet=email_text[:300],
                    action="Investigate and quarantine this email immediately.",
                    dashboard_url="https://phishguard.ai",
                )

            # ── Auto-quarantine ────────────────────────────────────────────
            q_key = f"quarantine_threshold_{username}"
            q_thresh = st.session_state.get(q_key, 70)
            severity = results["severity"]
            if results["risk_score"] >= q_thresh and severity in ("HIGH", "CRITICAL"):
                q_list_key = f"quarantined_{username}"
                if q_list_key not in st.session_state:
                    st.session_state[q_list_key] = []
                st.session_state[q_list_key].append({
                    "score": results["risk_score"],
                    "severity": severity,
                    "preview": email_text[:60],
                    "time": datetime.now().strftime("%H:%M"),
                })

            # ── In-app notification (HIGH/CRITICAL) ────────────────────────
            if severity in ("HIGH", "CRITICAL") and results["risk_score"] >= 50:
                st.session_state.setdefault("notifications", []).append({
                    "severity": severity,
                    "message": f"Threat detected — Score {results['risk_score']}/100",
                    "time": datetime.now().strftime("%H:%M"),
                })
                try:
                    push_notification(
                        username,
                        f"🚨 {severity} Threat Detected",
                        f"Score {results['risk_score']}/100 — {email_text[:60]}...",
                        severity.lower(),
                    )
                except Exception:
                    pass

            # ── Brand Impersonation Check ────────────────────────────────────
            _sender = results.get("headers", {}).get("From", "")
            _brand_result = _run_brand_check(email_text, sender=_sender)
            if _brand_result.get("impersonation_detected"):
                st.toast(f"🏷 Brand impersonation detected — risk {_brand_result['total_risk']}/100", icon="🏷")
                try:
                    from src.notification_channels import dispatch_to_channels
                    dispatch_to_channels(username, f"🏷 Brand impersonation detected: {_brand_result}", severity="high")
                except Exception:
                    pass

            st.session_state["results"]         = results
            st.session_state["email_text"]       = email_text
            st.session_state["vt_results"]       = vt_results
            st.session_state["vt_summary"]       = vt_summary
            st.session_state["osint_data"]       = osint_data
            st.session_state["jury_result"]      = jury_result
            st.session_state["xai_result"]       = xai_result
            st.session_state["combined_score"]   = combined_score
            st.session_state["webhook_result"]   = webhook_result
            st.session_state["header_auth"]      = header_auth
            st.session_state["dna_match"]        = dna_match
            st.session_state["dna_known"]        = dna_known
            st.session_state["perplexity_result"] = perplexity_result
            st.session_state["aitm_result"]      = aitm_result
            st.session_state["brand_check"]      = _brand_result
            st.session_state.pop("ai_report", None)

    if "results" in st.session_state:
        results          = st.session_state["results"]
        email_text_saved = st.session_state["email_text"]
        vt_results       = st.session_state.get("vt_results", [])
        osint_data       = st.session_state.get("osint_data", {})
        header_auth      = st.session_state.get("header_auth", {})
        aitm_result      = st.session_state.get("aitm_result", {})

        user_tier = st.session_state.get("plan", "trial")
        is_restricted = user_tier in ("free", "trial", "starter") and results.get("risk_score", 0) >= 75
        _restricted_blur = is_restricted

        st.divider()
        quarantine_badge = ""
        q_key = f"quarantine_threshold_{username}"
        q_thresh = st.session_state.get(q_key, 70)
        if results["risk_score"] >= q_thresh and results.get("severity") in ("HIGH", "CRITICAL"):
            quarantine_badge = " <span class='quarantine-badge'>🛡 QUARANTINED</span>"
        st.markdown(f"## 📊 Analysis Results{quarantine_badge}", unsafe_allow_html=True)

        score    = results["risk_score"]
        severity = results["severity"]
        color    = results["severity_color"]

        col_gauge, col_m1, col_m2, col_m3, col_m4 = st.columns([1.2, 1, 1, 1, 1])
        with col_gauge:
            lang_badges = ""
            lang_map = {"EN": {"label": "EN", "color": "#3b82f6"}, "FR": {"label": "FR", "color": "#22c55e"}, "AR": {"label": "AR", "color": "#f59e0b"}}
            for lc in results.get("languages_detected", ["EN"]):
                info = lang_map.get(lc, {"label": lc, "color": "#94a3b8"})
                lang_badges += f"<span style='background:{info['color']}20;color:{info['color']};border:1px solid {info['color']}44;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:600;margin-left:4px'>{info['label']}</span>"
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": f"<b>{severity}</b> {lang_badges}", "font": {"color": color, "size": 16}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                    "bar":  {"color": color},
                    "bgcolor": "#111827",
                    "steps": [
                        {"range": [0,  25], "color": "#0a2a0a"},
                        {"range": [25, 50], "color": "#2a2a0a"},
                        {"range": [50, 75], "color": "#2a1a0a"},
                        {"range": [75,100], "color": "#2a0a0a"},
                    ],
                    "threshold": {
                        "line": {"color": color, "width": 3},
                        "thickness": 0.75, "value": score
                    },
                },
                number={"font": {"color": color, "size": 48}}
            ))
            fig.update_layout(
                height=220, margin=dict(t=40, b=10, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0"
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_m1: st.metric("🔗 URLs Found",      results["url_count"])
        with col_m2: st.metric("🚨 Suspicious URLs", results["suspicious_url_count"])
        with col_m3: st.metric("🎯 Keyword Hits",    results["total_keyword_hits"])
        # ── AI-Author Probability (Perplexity Analyzer) ─────────────────────
        _perplex = st.session_state.get("perplexity_result", {})
        _ai_prob = _perplex.get("ai_probability", 0)
        _pcolor = "#ff4444" if _ai_prob >= 70 else "#ffaa00" if _ai_prob >= 40 else "#44aa44"
        with col_m4:
            st.markdown(
                f"<div style='background:#111827;border:1px solid #1e3a5f;border-radius:10px;"
                f"padding:12px 16px;text-align:center'>"
                f"<div style='color:#64748b;font-size:13px;margin-bottom:4px'>🤖 AI-Author</div>"
                f"<div style='font-size:1.6rem;font-weight:700;color:{_pcolor}'>{_ai_prob}%</div>"
                f"<div style='color:#475569;font-size:10px'>{_perplex.get('summary','')[:40]}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

        # ── Deep Analysis: Blur/Section-Cutoff for restricted tiers ────────
        _restricted_blur = is_restricted
        if _restricted_blur:
            st.markdown(
                "<div style='position:relative;overflow:hidden'>"
                "<div style='filter:blur(6px);pointer-events:none;user-select:none;opacity:0.3'>",
                unsafe_allow_html=True,
            )

        # ── Phishing DNA / Known Campaign Alert ─────────────────────────────
        _dna_known = st.session_state.get("dna_known", False)
        _dna_match = st.session_state.get("dna_match")
        if _dna_known and _dna_match:
            _sim_pct = round(_dna_match["similarity"] * 100, 1)
            st.markdown(
                f"<div style='background:#2a0a0a;border:1px solid #ff4444;border-radius:10px;"
                f"padding:12px 18px;margin:10px 0;display:flex;align-items:center;gap:12px'>"
                f"<span style='font-size:1.5rem'>🧬</span>"
                f"<div><strong style='color:#ff4444'>Known Phishing Campaign Variant Detected</strong><br>"
                f"<span style='color:#94a3b8;font-size:13px'>"
                f"{_sim_pct}% signature match with a previously flagged phishing campaign. "
                f"Preview: <code style='color:#60a5fa'>{_dna_match['match'].get('preview','')[:80]}</code></span></div>"
                f"</div>",
                unsafe_allow_html=True,
            )

        # ── AitM & OTP Harvester Detection ─────────────────────────────────
        if aitm_result and aitm_result.get("detected"):
            _ac = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffaa00", "LOW": "#94a3b8"}.get(
                aitm_result.get("severity", ""), "#94a3b8"
            )
            _ai = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}.get(
                aitm_result.get("severity", ""), "⚪"
            )
            st.markdown(
                f"<div style='background:#1a0a0a;border:1px solid {_ac};border-radius:10px;"
                f"padding:12px 18px;margin:10px 0'>"
                f"<div style='display:flex;align-items:center;gap:10px'>"
                f"<span style='font-size:1.3rem'>{_ai} 🕵️</span>"
                f"<div><strong style='color:{_ac}'>{aitm_result.get('label', '')}</strong>"
                f"<br><span style='color:#94a3b8;font-size:13px'>"
                f"Confidence: {aitm_result['confidence']}/100 · "
                f"URL: {aitm_result.get('url_score',0)} · "
                f"Body: {aitm_result.get('body_score',0)} · "
                f"Domain: {aitm_result.get('domain_score',0)}</span></div></div>",
                unsafe_allow_html=True,
            )
            if aitm_result.get("indicators"):
                with st.expander(f"📋 AitM Indicators ({len(aitm_result['indicators'])})"):
                    for ind in aitm_result["indicators"]:
                        st.markdown(f"- {ind}")
            st.markdown("</div>", unsafe_allow_html=True)

        # ── Email Authentication (SPF/DKIM/DMARC) ──────────────────────────
        if header_auth:
            auth_overall = header_auth.get("overall", "")
            auth_color = {"PASS": "#44aa44", "WARNING": "#ffaa00", "FAIL": "#ff4444", "UNKNOWN": "#94a3b8"}.get(auth_overall, "#94a3b8")
            auth_icon = {"PASS": "✅", "WARNING": "⚠️", "FAIL": "🔴", "UNKNOWN": "❓"}.get(auth_overall, "❓")
            st.markdown(
                f"<div class='section-title'>{auth_icon} Email Authentication — <span style='color:{auth_color}'>{auth_overall}</span>"
                f" <span style='font-size:11px;color:#475569;font-weight:400'>(+{header_auth.get('risk_contribution',0)} risk)</span></div>",
                unsafe_allow_html=True,
            )
        cols = st.columns(3)
        for col, (label, key, color_map) in zip(cols, [
                ("SPF", "spf_status", {"pass":"#44aa44","fail":"#ff4444","softfail":"#ffaa00","neutral":"#ffaa00","missing":"#94a3b8"}),
                ("DKIM", "dkim_status", {"pass":"#44aa44","fail":"#ff4444","signed":"#ffaa00","missing":"#94a3b8"}),
                ("DMARC", "dmarc_status", {"pass":"#44aa44","fail":"#ff4444","bestguesspass":"#88cc88","missing":"#94a3b8"}),
            ]):
                val = header_auth.get(key, "missing")
                c = color_map.get(val, "#94a3b8")
                dot = "🟢" if val in ("pass",) else "🔴" if val in ("fail",) else "🟡"
                with col:
                    st.markdown(
                        f"<div style='background:#111827;border:1px solid #1e3a5f;border-radius:10px;"
                        f"padding:12px;text-align:center'>"
                        f"<div style='color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.08em'>{label}</div>"
                        f"<div style='font-size:1.2rem;font-weight:700;color:{c}'>{dot} {val.upper()}</div>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )  # end with col

        st.caption(header_auth.get("details", ""))

        # ── Perplexity Analyzer (AI-written text detector) ──────────────────
        _perplex_data = st.session_state.get("perplexity_result", {})
        if _perplex_data.get("signals"):
            with st.expander(f"🤖 AI-Generated Text Analysis — {_perplex_data.get('summary','')}"):
                st.markdown(f"**AI-Author Probability:** {_perplex_data.get('ai_probability',0)}%")
                cols_perp = st.columns(4)
                cols_perp[0].metric("Burstiness", _perplex_data.get("burstiness",0), help="High = human-like variation")
                cols_perp[1].metric("Lexical Diversity", _perplex_data.get("lexical_diversity",0), help="Unique word ratio")
                cols_perp[2].metric("Avg Sentence Len", _perplex_data.get("avg_sentence_len",0))
                cols_perp[3].metric("Hedging Phrases", _perplex_data.get("hedging_count",0))
                st.caption("Signals detected: " + ", ".join(_perplex_data.get("signals", [])))

        st.divider()

        # ── Combined Threat Score ─────────────────────────────────────────────
        combined_score = st.session_state.get("combined_score")
        if combined_score and combined_score.get("has_vt_data"):
            st.markdown("<div class='section-title'>🔬 Combined Threat Intelligence Score</div>",
                        unsafe_allow_html=True)
            col_cs1, col_cs2, col_cs3 = st.columns(3)
            with col_cs1:
                st.metric("Composite Score",
                          f"{combined_score['composite_score']}/100",
                          delta=f"VT contrib: +{combined_score['vt_contribution']:.0f}")
            with col_cs2:
                st.metric("VT Malicious Detections",
                          combined_score["vt_malicious_count"])
            with col_cs3:
                st.metric("VT Suspicious Detections",
                          combined_score["vt_suspicious_count"])

        # ── Webhook alert status ─────────────────────────────────────────────
        webhook_result = st.session_state.get("webhook_result")
        if webhook_result:
            if webhook_result.get("success"):
                st.success("🚨 Webhook alert sent to your notification channel.")
            else:
                st.warning(f"Webhook delivery failed: {webhook_result.get('error', 'Unknown')}")

        # Keyword matches
        if results["keyword_matches"]:
            st.markdown("<div class='section-title'>🎯 Phishing Indicators</div>",
                        unsafe_allow_html=True)
            for category, keywords in results["keyword_matches"].items():
                with st.expander(f"**{category.upper()}** — {len(keywords)} match(es)"):
                    tags = " ".join(
                        "<span class='tag'>" + kw + "</span>" for kw in keywords
                    )
                    st.markdown(tags, unsafe_allow_html=True)

        # ── Phishing Kit Fingerprinting ──────────────────────────────────────────
        kit_data = results.get("kit_fingerprinting", {})
        if kit_data and kit_data.get("total_kits_detected", 0) > 0:
            st.markdown("<div class='section-title'>🕵️ Phishing Kit Fingerprinting</div>",
                        unsafe_allow_html=True)
            for match in kit_data["matches"]:
                icon = "🔴" if match["confidence"] >= 70 else "🟡" if match["confidence"] >= 40 else "🟢"
                sev_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffaa00"}.get(match["severity"], "#94a3b8")
                with st.expander(f"{icon} **{match['name']}** — {match['confidence']}% match", expanded=match["confidence"] >= 50):
                    st.caption(f"Severity: <span style='color:{sev_color}'>{match['severity']}</span> — {match['description']}",
                               unsafe_allow_html=True)
                    mp = match["matched_patterns"]
                    cols = st.columns(6)
                    labels = ["HTML", "CSS", "Form Fields", "JS", "File Paths", "Headers"]
                    for i, (key, label) in enumerate(zip(["html","css","form_fields","js","file_paths","headers"], labels)):
                        cols[i].metric(label, mp.get(key, 0))

        # ── XAI Psychological Trigger Breakdown ─────────────────────────────────
        xai_result = st.session_state.get("xai_result")
        if xai_result and xai_result.get("triggers"):
            st.markdown("<div class='section-title'>🧠 Psychological Manipulation Analysis</div>",
                        unsafe_allow_html=True)

            xai_score = xai_result["total_manipulation_score"]
            xai_color = xai_result["overall_color"]
            col_x1, col_x2 = st.columns([1, 2])

            with col_x1:
                fig_xai = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=xai_score,
                    domain={"x": [0, 1], "y": [0, 1]},
                    title={"text": f"<b>Manipulation Score</b>", "font": {"color": xai_color, "size": 14}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                        "bar": {"color": xai_color},
                        "bgcolor": "#111827",
                        "steps": [
                            {"range": [0, 25], "color": "#0a2a0a"},
                            {"range": [25, 50], "color": "#2a2a0a"},
                            {"range": [50, 75], "color": "#2a1a0a"},
                            {"range": [75, 100], "color": "#2a0a0a"},
                        ],
                        "threshold": {
                            "line": {"color": xai_color, "width": 3},
                            "thickness": 0.75, "value": xai_score,
                        },
                    },
                    number={"font": {"color": xai_color, "size": 40}},
                ))
                fig_xai.update_layout(
                    height=200, margin=dict(t=30, b=0, l=10, r=10),
                    paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                )
                st.plotly_chart(fig_xai, use_container_width=True)

            with col_x2:
                triggers = xai_result["triggers"]
                categories = [t["label"] for t in triggers]
                raw_scores = [t["raw_score"] for t in triggers]
                fig_radar = go.Figure()
                fig_radar.add_trace(go.Scatterpolar(
                    r=raw_scores + [raw_scores[0]],
                    theta=categories + [categories[0]],
                    fill="toself",
                    name="Trigger Intensity",
                    line_color="#3b82f6",
                    fillcolor="rgba(59, 130, 246, 0.15)",
                ))
                fig_radar.update_layout(
                    polar=dict(
                        radialaxis=dict(visible=True, range=[0, 100],
                                        tickcolor="#475569", gridcolor="#1e3a5f"),
                        bgcolor="rgba(0,0,0,0)",
                    ),
                    height=200, margin=dict(t=10, b=10, l=30, r=30),
                    paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                    showlegend=False,
                )
                st.plotly_chart(fig_radar, use_container_width=True)

            st.markdown(
                f"<p style='color:{xai_color};font-size:0.9rem;margin-bottom:12px'>"
                f"{xai_result['trigger_count']} manipulation tactic(s) detected — "
                f"{xai_result['overall_severity']} social engineering risk.</p>",
                unsafe_allow_html=True
            )

            for t in triggers:
                with st.expander(
                    f"{t['icon']} {t['label']} — Score {t['raw_score']}/100 "
                    f"(<span style='color:{t['severity_color']}'>{t['severity']}</span>)",
                    expanded=t["raw_score"] >= 50
                ):
                    st.markdown(f"*{t['description']}*")
                    if t.get("key_phrases"):
                        st.markdown(
                            "**Detected patterns:** " + ", ".join(
                                f"`{p}`" for p in t["key_phrases"][:6]
                            )
                        )
                    if t.get("evidence"):
                        st.markdown("**Why this was flagged:**")
                        for ev in t["evidence"][:4]:
                            st.markdown(f"- {ev['explanation']}")

            # Show XAI markdown report as downloadable context
            st.markdown(
                f"<details><summary style='color:#60a5fa;font-size:0.85rem;cursor:pointer'>"
                f"📋 View full XAI explanation</summary>"
                f"<div style='background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;"
                f"padding:16px;font-family:monospace;font-size:12px;color:#94a3b8;"
                f"margin-top:8px;white-space:pre-wrap'>{format_xai_report(xai_result)}</div>"
                f"</details>",
                unsafe_allow_html=True
            )

        # URL results
        if results["suspicious_urls"]:
            st.markdown("<div class='section-title'>🔗 Suspicious URLs Detected</div>",
                        unsafe_allow_html=True)
            for item in results["suspicious_urls"]:
                url_val = item["url"]
                st.markdown(
                    "<div class='url-box'>🚨 " + url_val + "</div>",
                    unsafe_allow_html=True
                )
        elif results["urls_found"]:
            st.markdown("<div class='section-title'>🔗 URLs Found (no pattern threats)</div>",
                        unsafe_allow_html=True)
            for url in results["urls_found"]:
                st.markdown(
                    "<div class='safe-url-box'>🔗 " + url + "</div>",
                    unsafe_allow_html=True
                )

        # VirusTotal
        if vt_results:
            st.markdown(
                "<div class='section-title'>🌐 Threat Intelligence (VirusTotal)</div>",
                unsafe_allow_html=True
            )
            for vt in vt_results:
                status  = vt.get("status", "error")
                url     = vt.get("url", "")
                mal     = vt.get("malicious", 0)
                sus     = vt.get("suspicious", 0)
                total   = vt.get("total_vendors", 0)
                threats = vt.get("threat_names", [])
                vt_link = vt.get("vt_link", "")

                if status == "malicious":
                    threat_str = ", ".join(threats) if threats else ""
                    st.markdown(
                        "<div class='url-box'>🔴 <b>MALICIOUS</b> — " + url[:70] +
                        "<br><span style='font-size:12px'>" +
                        str(mal) + "/" + str(total) + " vendors flagged " + threat_str +
                        "</span></div>",
                        unsafe_allow_html=True
                    )
                elif status == "suspicious":
                    st.markdown(
                        "<div style='background:#2a1a0a;border:1px solid #ff8800;"
                        "border-radius:8px;padding:10px 14px;margin:4px 0'>"
                        "🟠 <b>SUSPICIOUS</b> — " + url[:70] + "</div>",
                        unsafe_allow_html=True
                    )
                elif status == "clean":
                    st.markdown(
                        "<div class='safe-url-box'>🟢 <b>CLEAN</b> — " + url[:70] +
                        "<br><span style='font-size:12px'>No threats from " +
                        str(total) + " vendors</span></div>",
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        "<div style='background:#111827;border:1px solid #1e3a5f;"
                        "border-radius:8px;padding:10px 14px;margin:4px 0;"
                        "font-size:12px;color:#64748b'>⚪ Could not check: " +
                        url[:70] + "</div>",
                        unsafe_allow_html=True
                    )
                if vt_link and status != "error":
                    st.markdown(
                        "<a href='" + vt_link + "' target='_blank' "
                        "style='font-size:11px;color:#60a5fa'>View on VirusTotal →</a>",
                        unsafe_allow_html=True
                    )

        # OSINT
        if osint_data and osint_data.get("domain_results"):
            st.markdown("<div class='section-title'>🔎 OSINT Investigation</div>",
                        unsafe_allow_html=True)
            sender_val = osint_data.get("sender", "")
            if sender_val:
                st.markdown("**Sender:** `" + sender_val + "`")
            osint_risk = osint_data.get("osint_risk_score", 0)
            if osint_risk >= 75:
                st.error(f"🔴 OSINT Risk Score: {osint_risk}/100 — High confidence threat infrastructure")
            elif osint_risk >= 50:
                st.warning(f"🟠 OSINT Risk Score: {osint_risk}/100 — Suspicious infrastructure")
            elif osint_risk >= 25:
                st.warning(f"🟡 OSINT Risk Score: {osint_risk}/100 — Some suspicious indicators")
            else:
                st.success(f"🟢 OSINT Risk Score: {osint_risk}/100 — No major concerns")

            for dr in osint_data["domain_results"]:
                domain_name  = dr["domain"]
                domain_score = dr["risk_score"]
                with st.expander(f"🌐 **{domain_name}** — Risk: {domain_score}/100"):
                    dc1, dc2, dc3 = st.columns(3)
                    dc1.metric("Risk Score", str(domain_score) + "/100")
                    dc2.metric("Country", dr.get("country", "Unknown"))
                    age_val = dr.get("domain_age_days")
                    dc3.metric("Domain Age",
                               str(age_val) + " days" if age_val else "Unknown")
                    for ind in dr.get("risk_indicators", []):
                        st.markdown("- " + ind)

        # Attachment / Header / Language
        if results["has_attachments"]:
            st.warning("📎 **Attachment detected** — Do NOT open files from unverified senders.")

        header = results.get("header_analysis", {})
        if header.get("findings"):
            st.markdown("<div class='section-title'>📨 Email Header Analysis</div>",
                        unsafe_allow_html=True)
            for finding in header["findings"]:
                st.error("🚨 " + finding)

        attach = results.get("attachment_analysis", {})
        if attach.get("findings"):
            st.markdown("<div class='section-title'>📎 Attachment Analysis</div>",
                        unsafe_allow_html=True)
            for finding in attach["findings"]:
                st.error("🚨 " + finding)

        lang = results.get("language_analysis", {})
        if lang.get("findings"):
            st.markdown(
                "<div class='section-title'>🧠 Language & Manipulation Analysis</div>",
                unsafe_allow_html=True
            )
            for finding in lang["findings"]:
                st.warning("⚠ " + finding)

        # Verdict
        st.divider()
        st.markdown("<div class='section-title'>📋 Security Verdict</div>",
                    unsafe_allow_html=True)
        if score >= 75:
            st.error("🔴 **CRITICAL THREAT** — Strong phishing indicators detected. Do not click any links.")
        elif score >= 50:
            st.error("🟠 **HIGH RISK** — Multiple phishing indicators found. Treat with extreme caution.")
        elif score >= 25:
            st.warning("🟡 **MEDIUM RISK** — Suspicious elements detected. Verify before acting.")
        else:
            st.success("🟢 **LOW RISK** — No major phishing indicators found. Stay vigilant.")

        # ── Multi-LLM Jury Ensemble ──────────────────────────────────────────
        jury_result = st.session_state.get("jury_result")
        if jury_result and "final_score" in jury_result:
            jr = jury_result
            st.markdown("<div class='section-title'>🧠 Multi-LLM Jury Consensus</div>",
                        unsafe_allow_html=True)
            col_j1, col_j2, col_j3 = st.columns(3)
            with col_j1:
                delta_j = jr.get("final_score", 0) - score
                st.metric("⚖️ Ensemble Score", f"{jr['final_score']:.0f}/100",
                          delta=f"{delta_j:+.0f} vs heuristic")
            with col_j2:
                st.metric("🔤 Linguistic Jury",
                          f"{jr.get('linguistic_score', 0):.0f}/100")
            with col_j3:
                st.metric("🏢 Corporate Jury",
                          f"{jr.get('corporate_score', 0):.0f}/100")

            if jr.get("final_score", 0) > score + 15:
                st.warning(
                    "⚠️ The jury ensemble rates this email **significantly higher** "
                    "than the heuristic scan. Consider it a priority threat."
                )
            elif jr.get("final_score", 0) < score - 15:
                st.info(
                    "ℹ️ The jury ensemble rates this email **lower** than the heuristic scan. "
                    "Heuristic flags may be false positives."
                )

        # ── Phishing Reverse Honeypot (Counter-Measure) ─────────────────────
        if score >= 50:
            st.divider()
            st.markdown("<div class='section-title'>🪤 Counter-Measure Deployment</div>",
                        unsafe_allow_html=True)
            if st.button("⚔️ Deploy Deception Payload", use_container_width=True,
                         type="secondary", key="honeypot_btn"):
                from src.honeypot_generator import generate_honeypot
                with st.spinner("Generating deceptive payload..."):
                    honeypot = generate_honeypot(email_text_saved)
                st.session_state["honeypot"] = honeypot
                st.success("✅ Deception payload generated. You may copy and send it to the attacker.")
                st.rerun()
            _hp = st.session_state.get("honeypot")
            if _hp:
                st.markdown(
                    f"<div style='background:#0a1a0a;border:1px solid #44aa44;border-radius:10px;"
                    f"padding:14px 18px;margin:8px 0'>"
                    f"<div style='color:#44aa44;font-weight:700;margin-bottom:6px'>"
                    f"📨 {_hp.get('subject','')}</div>"
                    f"<div style='color:#94a3b8;font-size:12px'>"
                    f"From: {_hp.get('sender_name','')} ({_hp.get('sender_email','')})<br>"
                    f"Payload: {_hp.get('payload_type','')}</div>"
                    f"<div style='background:#000;border-radius:8px;padding:12px;margin:8px 0;"
                    f"font-size:12px;color:#e2e8f0;white-space:pre-wrap;font-family:monospace'>"
                    f"{_hp.get('body','')}</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
                import json as _json
                _pd = _hp.get("payload_data", "{}")
                if isinstance(_pd, str):
                    try:
                        _pd = _json.loads(_pd)
                    except Exception:
                        pass
                with st.expander("📦 Extracted Payload Data (for tracking)"):
                    st.json(_pd)
                if st.button("✕ Clear Payload", key="clear_hp"):
                    st.session_state.pop("honeypot", None)
                    st.rerun()

        # ── Close blur overlay for restricted tiers ────────────────────────
        if _restricted_blur:
            st.markdown("</div></div>", unsafe_allow_html=True)

        # ── Abrupt Visibility Cutoff Paywall Gate ──────────────────────────
        is_restricted = _restricted_blur

        if is_restricted:
            st.divider()
            st.markdown(
                "<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);"
                "border:3px solid #eab308;border-radius:20px;padding:32px 28px;"
                "text-align:center;margin:12px 0 24px 0;position:relative;overflow:hidden'>"
                # Blur overlay background effect
                "<div style='position:absolute;top:0;left:0;right:0;bottom:0;"
                "background:rgba(10,15,26,0.85);backdrop-filter:blur(4px);z-index:0'></div>"
                # Content on top
                "<div style='position:relative;z-index:1'>"
                "<div style='font-size:3rem;margin-bottom:8px'>🔒</div>"
                "<div style='color:#f0f6ff;font-size:1.5rem;font-weight:800;"
                "margin-bottom:4px'>Premium Analysis Restricted</div>"
                "<div style='color:#94a3b8;font-size:0.9rem;margin-bottom:20px'>"
                "AI Security Audit, Threat Links, and PDF Reports are locked on your current plan.</div>"
                # Breach Cost ROI Calculator
                "<div style='background:rgba(234,179,8,0.08);border:1px solid rgba(234,179,8,0.3);"
                "border-radius:14px;padding:20px;margin:0 auto 20px auto;max-width:400px'>"
                "<div style='color:#eab308;font-weight:700;font-size:1.1rem;margin-bottom:12px'>"
                "💰 Breach Cost ROI Calculator</div>"
                "<div style='color:#94a3b8;font-size:12px;margin-bottom:8px'>"
                "Your company size:</div>"
                + "<div style='margin:0 auto;max-width:300px'>__BREACH_SLIDER__</div>"
                + "<div style='color:#e2e8f0;font-size:0.9rem;margin-top:12px'>"
                "Estimated cost of a single successful BEC breach at your firm:</div>"
                "<div style='color:#ef4444;font-size:2rem;font-weight:800;margin:8px 0'>"
                "__BREACH_COST__</div>"
                "<div style='color:#64748b;font-size:0.8rem'>"
                "Protect your company today for just <strong>$99/mo</strong>.</div>"
                "</div>"
                "<a href='#billing-tab' style='display:inline-block;"
                "background:linear-gradient(135deg,#eab308,#f59e0b);color:#0a0f1a;"
                "padding:12px 40px;border-radius:12px;text-decoration:none;font-weight:700;"
                "font-size:1rem'>⬆ Upgrade to Business Tier</a>"
                "</div></div>",
                unsafe_allow_html=False  # we build it below
            )
            # Build breach cost slider + result dynamically
            breach_employees = st.slider("Employees", 10, 500, 50, key="breach_slider",
                                         label_visibility="collapsed")
            breach_cost = breach_employees * 900
            st.markdown(
                f"<div style='text-align:center;margin:-20px 0 20px 0;"
                f"background:#111827;border:1px solid #1e3a5f;border-radius:12px;"
                f"padding:16px;max-width:400px;margin-left:auto;margin-right:auto'>"
                f"<div style='color:#94a3b8;font-size:13px'>Estimated cost of a single "
                f"successful BEC breach at your firm:</div>"
                f"<div style='color:#ef4444;font-size:2.2rem;font-weight:800'>"
                f"${breach_cost:,}</div>"
                f"<div style='color:#64748b;font-size:11px;margin-top:4px'>"
                f"Based on {breach_employees} employees × $900 avg cost per employee</div>"
                f"</div>",
                unsafe_allow_html=True
            )
        else:
            # Export — full access
            st.divider()
            st.markdown("<div class='section-title'>📄 Export & AI Analysis</div>",
                        unsafe_allow_html=True)
            col_ai, col_pdf, col_stix = st.columns(3)

            with col_ai:
                if st.button("🤖 Generate AI Security Report",
                             use_container_width=True, type="secondary"):
                    try:
                        with st.spinner("AI is writing your security report..."):
                            ai_report = generate_ai_report(email_text_saved, results)
                        st.session_state["ai_report"] = ai_report
                        save_analysis(results, email_text_saved, ai_report)
                    except Exception as e:
                        st.error(f"AI analysis failed: {e}")

            with col_pdf:
                ai_report_text = st.session_state.get("ai_report", "")
                # Check for consultant white-label
                is_consultant = user_tier == "consultant"
                wl_flag = st.session_state.get("whitelabel_pdf", False) and is_consultant
                wl_logo = st.session_state.get("consultant_logo_path") if is_consultant else None
                pdf_bytes = generate_pdf_report(results, email_text_saved, ai_report_text,
                                                white_label=wl_flag, custom_logo_path=wl_logo)
                sev_lower = results["severity"].lower()
                st.download_button(
                    label="📥 Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"phishguard_report_{sev_lower}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    type="primary"
                )

            with col_stix:
                import json as _json_stix
                from src.stix_exporter import build_enterprise_stix_bundle
                _att_result = st.session_state.get("att_scan_result")
                _sender_anom = st.session_state.get("sender_anomaly")
                _perplex = st.session_state.get("perplexity_result")
                stix_bundle = build_enterprise_stix_bundle(
                    email_text=email_text_saved,
                    results=results,
                    osint_data=osint_data,
                    vt_results=vt_results,
                    attachment_result=_att_result,
                    sender_anomaly=_sender_anom,
                    perplexity_result=_perplex,
                )
                stix_json = _json_stix.dumps(stix_bundle, indent=2)
                st.download_button(
                    label="📤 Export STIX 2.1 Threat Intel",
                    data=stix_json,
                    file_name=f"phishguard_stix_{sev_lower}.json",
                    mime="application/json",
                    use_container_width=True,
                    type="secondary",
                )

            if "ai_report" in st.session_state:
                st.markdown("<div class='section-title'>🤖 AI Security Analysis</div>",
                            unsafe_allow_html=True)
            st.markdown(st.session_state["ai_report"])


# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 — ENTERPRISE ANALYTICS DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
with tab3:
    from src.ui_analytics import render_analytics_tab
    render_analytics_tab()
    st.divider()

    history = _cached_history(500)
    if not history:
        st.info("No scan data yet. Go to Analyze and scan your first email.")
    else:
        scores = [row[1] for row in history]
        severities = [row[2] for row in history]
        timestamps = [row[0] for row in history]

        if lookback_days != "All Time":
            limit = 30 if "30" in lookback_days else 7
            cutoff = (datetime.now() - __import__("datetime").timedelta(days=limit)).strftime("%Y-%m-%d")
            filtered = [(ts, sc, sev) for ts, sc, sev, *_ in history if ts[:10] >= cutoff]
            if filtered:
                scores = [r[1] for r in filtered]
                severities = [r[2] for r in filtered]
                timestamps = [r[0] for r in filtered]

        total_scans = len(history)
        filtered_count = len(scores)
        avg_score = round(sum(scores) / filtered_count, 1) if filtered_count else 0
        critical_count = sum(1 for s in severities if s == "CRITICAL")
        high_count = sum(1 for s in severities if s == "HIGH")
        medium_count = sum(1 for s in severities if s == "MEDIUM")
        safe_count = sum(1 for s in severities if s == "LOW")
        threats_neutralized = critical_count + high_count

        # ── SOC KPI cards ──────────────────────────────────────────────────
        st.markdown("#### 🎯 Key SOC Metrics")
        col_k1, col_k2, col_k3, col_k4, col_k5 = st.columns(5)
        col_k1.metric("Total Scans", filtered_count, delta=total_scans - filtered_count if filtered_count != total_scans else None)
        col_k2.metric("Avg Risk Score", f"{avg_score}/100")
        col_k3.metric("Threats Neutralized", threats_neutralized, delta_color="inverse")
        col_k4.metric("Critical", critical_count, delta_color="inverse")
        col_k5.metric("Safe %", f"{round(safe_count / filtered_count * 100, 1) if filtered_count else 0}%")
        st.divider()

        # ── Row: Donut (threat distribution) + Bar (threat level breakdown) ─
        col_d1, col_d2 = st.columns([1, 1])
        with col_d1:
            st.markdown("#### 🛡 Threat Level Distribution")
            fig_donut = go.Figure(go.Pie(
                labels=["Safe (LOW)", "Medium", "High", "Critical"],
                values=[safe_count, medium_count, high_count, critical_count],
                hole=0.5,
                marker_colors=["#44aa44", "#ffaa00", "#ff8800", "#ff4444"],
                textinfo="label+percent",
                textfont=dict(size=11, color="#e2e8f0"),
                rotation=90,
                pull=[0, 0, 0.05, 0.08],
            ))
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                height=290, margin=dict(t=10, b=10, l=10, r=10),
                showlegend=False,
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        with col_d2:
            st.markdown("#### 📊 Threat Severity Counts")
            fig_bar_sev = go.Figure(go.Bar(
                x=["Safe", "Medium", "High", "Critical"],
                y=[safe_count, medium_count, high_count, critical_count],
                marker_color=["#44aa44", "#ffaa00", "#ff8800", "#ff4444"],
                text=[str(safe_count), str(medium_count), str(high_count), str(critical_count)],
                textposition="outside",
                textfont=dict(color="#e2e8f0", size=13),
            ))
            fig_bar_sev.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=290,
                margin=dict(t=10, b=10, l=10, r=10),
                xaxis=dict(gridcolor="#1e3a5f"),
                yaxis=dict(gridcolor="#1e3a5f", title="Count"),
                showlegend=False,
            )
            st.plotly_chart(fig_bar_sev, use_container_width=True)

        st.divider()

        # ── Timeline chart: phishing trends ────────────────────────────────
        st.markdown("#### 📅 Phishing Trend Timeline")
        from collections import Counter
        daily_counts = Counter()
        daily_critical = Counter()
        daily_high = Counter()
        for ts, sev in zip(timestamps, severities):
            day = ts[:10]
            daily_counts[day] += 1
            if sev == "CRITICAL":
                daily_critical[day] += 1
            elif sev == "HIGH":
                daily_high[day] += 1

        if daily_counts:
            days_sorted = sorted(daily_counts.keys())
            total_vals = [daily_counts[d] for d in days_sorted]
            crit_vals  = [daily_critical.get(d, 0) for d in days_sorted]
            high_vals  = [daily_high.get(d, 0) for d in days_sorted]

            col_t1, col_t2 = st.columns([3, 1])
            with col_t1:
                fig_line = go.Figure()
                fig_line.add_trace(go.Scatter(
                    x=days_sorted, y=total_vals, mode="lines+markers",
                    name="Total Scans", line=dict(color="#60a5fa", width=2),
                    fill="tozeroy", fillcolor="rgba(96, 165, 250, 0.08)"
                ))
                fig_line.add_trace(go.Scatter(
                    x=days_sorted, y=crit_vals, mode="lines+markers",
                    name="Critical", line=dict(color="#ff4444", width=2)
                ))
                fig_line.add_trace(go.Scatter(
                    x=days_sorted, y=high_vals, mode="lines+markers",
                    name="High", line=dict(color="#ff8800", width=2)
                ))
                fig_line.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e2e8f0", height=320,
                    margin=dict(t=10, b=20, l=20, r=20),
                    legend=dict(orientation="h", y=1.1),
                    xaxis=dict(gridcolor="#1e3a5f", tickangle=-45),
                    yaxis=dict(gridcolor="#1e3a5f", title="Count"),
                    hovermode="x unified",
                )
                st.plotly_chart(fig_line, use_container_width=True)

            with col_t2:
                st.markdown("##### 📊 Summary")
                st.metric("Total Threats", threats_neutralized)
                today_str = datetime.now().strftime("%Y-%m-%d")
                today_threats = sum(1 for ts, sev in zip(timestamps, severities) if ts[:10] == today_str and sev in ("CRITICAL", "HIGH"))
                st.metric("Today's Threats", today_threats)
                highest_risk = max(scores) if scores else 0
                st.metric("Highest Risk", f"{highest_risk}/100")
                recent_avg = round(sum(scores[-20:]) / min(len(scores), 20), 1) if scores else 0
                st.metric("Last 20 Avg", f"{recent_avg}/100")

        st.divider()

        # ── Bottom row: XAI triggers + AI authorship trend ─────────────────
        col_b1, col_b2 = st.columns(2)
        with col_b1:
            st.markdown("#### 🧠 Psychological Triggers (Last Scan)")
            from src.xai_analyzer import TRIGGER_DEFINITIONS
            last_xai = st.session_state.get("xai_result", {})
            if last_xai and last_xai.get("triggers"):
                trig_labels = [t["label"] for t in last_xai["triggers"]]
                trig_scores = [t["raw_score"] for t in last_xai["triggers"]]
                trig_colors = [t["severity_color"] for t in last_xai["triggers"]]

                fig_bar = go.Figure(go.Bar(
                    x=trig_scores[::-1],
                    y=trig_labels[::-1],
                    orientation="h",
                    marker_color=trig_colors[::-1],
                    text=[f"{s}/100" for s in trig_scores[::-1]],
                    textposition="outside",
                ))
                fig_bar.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e2e8f0", height=280,
                    margin=dict(t=10, b=10, l=10, r=60),
                    xaxis=dict(range=[0, 105], gridcolor="#1e3a5f", title="Score"),
                    yaxis=dict(gridcolor="#1e3a5f"),
                )
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("Run an analysis with XAI enabled to see trigger data.")

        with col_b2:
            st.markdown("#### 🤖 AI-Generated Text Trend")
            st.caption("Probability that scanned emails were AI-written (last 20 scans).")
            _perplex_hist = []
            for row in history[:20]:
                _p = st.session_state.get(f"_perplex_{row[0]}", None)
                _perplex_hist.append(_p)
            if any(v is not None for v in _perplex_hist):
                valid = [(i, v) for i, v in enumerate(_perplex_hist) if v is not None]
                if len(valid) >= 2:
                    xs, ys = zip(*valid)
                    fig_ai = go.Figure(go.Scatter(
                        x=list(xs), y=list(ys), mode="lines+markers",
                        line=dict(color="#aa44ff", width=2),
                        fill="tozeroy", fillcolor="rgba(170, 68, 255, 0.08)",
                    ))
                    fig_ai.add_hline(y=50, line_dash="dash", line_color="#ff8800",
                                     annotation_text="Threshold")
                    fig_ai.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e2e8f0", height=280,
                        margin=dict(t=10, b=10, l=10, r=10),
                        xaxis=dict(gridcolor="#1e3a5f", title="Scan #"),
                        yaxis=dict(gridcolor="#1e3a5f", title="AI Probability", range=[0, 100]),
                        showlegend=False,
                    )
                    st.plotly_chart(fig_ai, use_container_width=True)
                else:
                    st.info("More AI-text data needed.")
            else:
                st.info("Run analyses to populate AI authorship trend.")

        st.divider()

        # ── Recent threats table ────────────────────────────────────────────
        with st.expander(f"📋 Threat Log — Recent {min(filtered_count, 50)} Scans"):
            _sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            for row in history[:50]:
                ts, sc, sev, kw, su, preview = row
                emoji = _sev_emoji.get(sev, "⚪")
                st.markdown(
                    f"{emoji} **{sev}** | Score {sc}/100 | {ts[:16]} | "
                    f"KW: {kw} | URLs: {su} | `{preview[:50]}`"
                )

        # ── Weekly Digest ───────────────────────────────────────────────────
        st.divider()
        st.markdown("#### 📬 Weekly Digest (Last 7 Days)")
        st.caption("Summary of the last 7 days.")
        weekly_scores = [row[1] for row in history if (datetime.now() - datetime.strptime(row[0][:10], "%Y-%m-%d")).days < 7] if history else []
        if weekly_scores:
            w_total = len(weekly_scores)
            w_crit = sum(1 for row in history if row[2] == "CRITICAL" and (datetime.now() - datetime.strptime(row[0][:10], "%Y-%m-%d")).days < 7)
            w_high = sum(1 for row in history if row[2] == "HIGH" and (datetime.now() - datetime.strptime(row[0][:10], "%Y-%m-%d")).days < 7)
            w_avg = round(sum(weekly_scores) / w_total, 1)
            w_col1, w_col2, w_col3, w_col4 = st.columns(4)
            w_col1.metric("7-Day Scans", w_total)
            w_col2.metric("Avg Score", f"{w_avg}/100")
            w_col3.metric("Critical", w_crit, delta_color="inverse")
            w_col4.metric("High", w_high, delta_color="inverse")
        else:
            st.info("No scans in the last 7 days.")

        # ── Export options ──────────────────────────────────────────────────
        st.divider()
        st.markdown("#### 📥 Export Data")
        col_ex1, col_ex2, col_ex3 = st.columns(3)
        with col_ex1:
            if history:
                import csv, io
                out = io.StringIO()
                w = csv.writer(out)
                w.writerow(["Timestamp", "Risk Score", "Severity",
                             "Keyword Hits", "Suspicious URLs", "Preview"])
                w.writerows(history)
                st.download_button(
                    "📥 Export CSV (All History)", out.getvalue(),
                    "phishguard_analytics.csv", "text/csv",
                    use_container_width=True,
                )
        with col_ex2:
            if history:
                import json
                json_data = json.dumps(
                    [{"timestamp": r[0], "risk_score": r[1], "severity": r[2],
                      "keyword_hits": r[3], "suspicious_urls": r[4], "preview": r[5]}
                     for r in history], indent=2
                )
                st.download_button(
                    "📥 Export JSON (All History)", json_data,
                    "phishguard_analytics.json", "application/json",
                    use_container_width=True,
                )
        with col_ex3:
            last_results = st.session_state.get("results")
            if last_results:
                import json
                result_json = json.dumps(last_results, indent=2, default=str)
                st.download_button(
                    "📥 Export Last Analysis JSON", result_json,
                    "phishguard_last_analysis.json", "application/json",
                    use_container_width=True,
                )

    # ── Compliance Reports ────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📋 Compliance Reports")
    st.markdown(
        "<p style='color:#64748b;font-size:13px'>Generate SOC 2, GDPR, or HIPAA "
        "PDF reports summarizing your phishing defense posture.</p>",
        unsafe_allow_html=True
    )

    col_cr1, col_cr2 = st.columns(2)
    with col_cr1:
        cr_standard = st.selectbox(
            "Standard", ["soc2", "gdpr", "hipaa"],
            format_func=lambda x: x.upper(),
            key="cr_standard"
        )
    with col_cr2:
        cr_days = st.slider("Report period (days)", 7, 365, 90, key="cr_days")

    # ── White-Label Toggle ─────────────────────────────────────────────────
    whitelabel_enabled = st.checkbox(
        "🔏 Enable White-Label (Remove PhishGuard Branding)",
        key="whitelabel_toggle",
        help="Generate reports without PhishGuard watermarks for client delivery.",
    )
    if whitelabel_enabled:
        is_consultant = st.session_state.get("plan") in ("enterprise", "business")
        if not is_consultant:
            st.markdown(
                "<div style='background:linear-gradient(135deg,#1a0a1a,#2a0f2a);"
                "border:2px solid #a855f7;border-radius:16px;padding:24px 20px;"
                "text-align:center;margin:12px 0'>"
                "<div style='font-size:2rem;margin-bottom:6px'>💼</div>"
                "<div style='color:#f0f6ff;font-size:1rem;font-weight:700;"
                "margin-bottom:4px'>Consultant License Required</div>"
                "<div style='color:#94a3b8;font-size:0.85rem'>White-label reports "
                "are exclusive to the <strong>Consultant License ($149/mo)</strong>. "
                "Rebrand threat intelligence reports with your own company logo "
                "for commercial client delivery.</div>"
                "</div>", unsafe_allow_html=True
            )

    if st.button("📄 Generate Compliance Report", type="primary", use_container_width=True):
        from src.compliance_reports import ComplianceReport
        with st.spinner(f"Generating {cr_standard.upper()} report..."):
            report = ComplianceReport(standard=cr_standard, org_name=username,
                                      date_range_days=cr_days)
            pdf_bytes = report.generate()
        st.session_state["compliance_report"] = pdf_bytes
        st.session_state["compliance_standard"] = cr_standard
        st.rerun()

    if st.session_state.get("compliance_report"):
        label = "🕊 Download White-Label Report" if whitelabel_enabled else "📥 Download PDF Report"
        st.success(f"{st.session_state['compliance_standard'].upper()} report ready!")
        st.download_button(
            label,
            st.session_state["compliance_report"],
            f"phishguard_{st.session_state['compliance_standard']}_{datetime.now().strftime('%Y%m%d')}.pdf",
            "application/pdf",
            use_container_width=True,
        )


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
    with tab5:
        st.markdown("## ⚙ Admin Dashboard")
        st.markdown(
            "<p style='color:#94a3b8'>Only visible to admin account</p>",
            unsafe_allow_html=True
        )
        if st.button("🔄 Refresh", key="refresh_admin"):
            _cached_stats.clear()
            _cached_threats.clear()
            _cached_daily_counts.clear()
            st.rerun()
        st.divider()

        stats = _cached_stats()
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(
            "<div class='stat-card'>"
            "<div style='font-size:2rem;font-weight:900;color:#60a5fa'>" +
            str(stats["total_analyses"]) +
            "</div><div style='color:#64748b;font-size:0.85rem'>Total Analyses</div></div>",
            unsafe_allow_html=True
        )
        c2.markdown(
            "<div class='stat-card'>"
            "<div style='font-size:2rem;font-weight:900;color:#22c55e'>" +
            str(stats["today_analyses"]) +
            "</div><div style='color:#64748b;font-size:0.85rem'>Today</div></div>",
            unsafe_allow_html=True
        )
        c3.markdown(
            "<div class='stat-card'>"
            "<div style='font-size:2rem;font-weight:900;color:#ff4444'>" +
            str(stats["critical_count"]) +
            "</div><div style='color:#64748b;font-size:0.85rem'>Critical Threats</div></div>",
            unsafe_allow_html=True
        )
        c4.markdown(
            "<div class='stat-card'>"
            "<div style='font-size:2rem;font-weight:900;color:#ffaa00'>" +
            str(stats["avg_risk_score"]) +
            "</div><div style='color:#64748b;font-size:0.85rem'>Avg Risk Score</div></div>",
            unsafe_allow_html=True
        )

        st.markdown("<br>", unsafe_allow_html=True)

        col_ch1, col_ch2 = st.columns(2)
        with col_ch1:
            daily  = _cached_daily_counts(14)
            dates  = [d["date"] for d in daily]
            counts = [d["count"] for d in daily]
            fig3 = go.Figure(go.Bar(
                x=dates, y=counts, marker_color="#2563eb",
                text=counts, textposition="outside"
            ))
            fig3.update_layout(
                title="Analyses per Day (Last 14 Days)",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=300, margin=dict(t=40, b=20, l=20, r=20)
            )
            fig3.update_xaxes(showgrid=False, tickangle=45)
            fig3.update_yaxes(gridcolor="#1e3a5f")
            st.plotly_chart(fig3, use_container_width=True)

        with col_ch2:
            sev_data = stats["severity_counts"]
            if sev_data:
                sev_colors = {
                    "CRITICAL": "#ff4444", "HIGH": "#ff8800",
                    "MEDIUM": "#ffaa00",   "LOW":  "#44aa44"
                }
                fig4 = go.Figure(go.Pie(
                    labels=list(sev_data.keys()),
                    values=list(sev_data.values()),
                    marker_colors=[sev_colors.get(k, "#60a5fa") for k in sev_data],
                    hole=0.4
                ))
                fig4.update_layout(
                    title="Severity Distribution",
                    paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                    height=300, margin=dict(t=40, b=20, l=20, r=20)
                )
                st.plotly_chart(fig4, use_container_width=True)

        # ── Risk Trend Chart (last 100 analyses) ────────────────────────────
        st.markdown("### 📈 Risk Score Trend")
        try:
            import sqlite3
            from pathlib import Path
            _adb = Path(__file__).parent / "data" / "phishguard.db"
            _aconn = sqlite3.connect(str(_adb))
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
                _aconn2 = sqlite3.connect(str(_adb))
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
                _aconn3 = sqlite3.connect(str(_adb))
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
                    _bar_c = [_colors.get(l, "#60a5fa") for l in _labels]
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
                import csv, io
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

    from src.feedback import mark_feedback, get_feedback_stats, get_feedback_history

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

    # ── A/B Testing ─────────────────────────────────────────────────────
    if is_admin:
        st.divider()
        with st.expander("🔬 A/B Testing", expanded=False):
            st.caption("Run side-by-side detection rule comparisons.")
            from src.ab_testing import ABTest, list_active_tests, stop_test, promote_variant
            col_ab1, col_ab2 = st.columns(2)
            with col_ab1:
                ab_name = st.text_input("Test name", placeholder="keyword_boost_v2", key="ab_name")
            with col_ab2:
                if st.button("➕ Create Test", use_container_width=True) and ab_name:
                    ABTest(ab_name, owner=username, description="Manual A/B test")
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
                            st.success(f"Winner promoted for '{t['test_name']}'")
                            st.rerun()
                    with col_t4:
                        if st.button("⏹ Stop", key=f"ab_stop_{t['id']}", use_container_width=True):
                            stop_test(t['test_name'])
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
            import sqlite3
            from pathlib import Path
            _db = Path(__file__).parent / "data" / "phishguard.db"
            try:
                _conn = sqlite3.connect(str(_db))
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
                                            st.rerun()
                            with st.form(f"invite_{ws['id']}"):
                                invite_user = st.text_input("Username to invite",
                                                              placeholder="johndoe")
                                invite_role = st.selectbox("Role", ["viewer", "analyst", "admin"])
                                if st.form_submit_button("📨 Invite", type="primary"):
                                    if invite_user:
                                        r = invite_member(ws["id"], invite_user, invite_role, username)
                                        if r["success"]:
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
                                from src.email_verify import create_verification, send_verification_email
                                base = st.secrets.get("base_url", "http://localhost:8501")
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
billing_tab = tab7 if is_admin else tab5

with billing_tab:
    st.markdown("## 💳 Billing & Subscription")
    st.divider()

    plan_info = PLANS.get(plan, PLANS["trial"])
    q = check_quota(username, plan)

    # ── Current Plan + Subscription Status Card ───────────────────────────
    sub = get_local_subscription(username)
    paddle_avail = paddle_configured()

    status_tag = ""
    status_color = "#22c55e"
    if sub:
        s = sub.get("status", "")
        if s == "active":
            status_tag = "🟢 Active"
        elif s == "paused":
            status_tag = "⏸ Paused"
            status_color = "#f59e0b"
        elif s == "cancelled":
            status_tag = "⏹ Cancelled"
            status_color = "#ef4444"
        elif s == "past_due":
            status_tag = "🔴 Past Due"
            status_color = "#ef4444"
        else:
            status_tag = s.capitalize()

    st.markdown(
        f"<div style='background:#111827;border:1px solid #1e3a5f;"
        f"border-radius:16px;padding:28px 32px;margin-bottom:24px'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center'>"
        f"<div>"
        f"<div style='color:#64748b;font-size:0.8rem;text-transform:uppercase;"
        f"letter-spacing:0.08em;margin-bottom:4px'>Current Plan</div>"
        f"<div style='color:#f0f6ff;font-size:1.8rem;font-weight:800'>"
        + plan_info["label"] + f"</div>"
        f"<div style='color:#475569;font-size:0.85rem;margin-top:4px'>"
        + plan_info["price"] + f"</div>"
        f"</div>"
        f"<div style='text-align:right'>"
        + (f"<div style='color:{status_color};font-size:0.9rem;font-weight:600'>{status_tag}</div>"
           if status_tag else "")
        + f"<div style='color:#94a3b8;font-size:0.9rem;margin-top:4px'>"
        + str(q["usage"]) + " / " + str(q["limit"]) + " analyses used</div>"
        f"<div style='background:#1e3a5f;border-radius:4px;height:6px;width:120px;margin:6px 0 0 auto'>"
        f"<div style='background:#60a5fa;border-radius:4px;height:6px;width:"
        + str(q["pct"]) + f"%'></div></div></div></div>"
        + (f"<div style='color:#64748b;font-size:0.8rem;margin-top:12px;border-top:1px solid #1e3a5f;padding-top:12px'>"
           f"Subscription ID: <code>{sub['subscription_id']}</code>"
           + (f" | Next billing: <strong>{sub.get('next_billed_at', 'N/A')}</strong>" if sub.get('next_billed_at') else "")
           + f"</div>" if sub and sub.get('subscription_id') else "")
        + f"</div>",
        unsafe_allow_html=True
    )

    # ── Subscription Management Actions ───────────────────────────────────
    if sub and sub.get("subscription_id") and sub["subscription_id"].startswith("sub_"):
        sub_id = sub["subscription_id"]
        sub_status = sub.get("status", "")
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
                    inv_total = int(inv["total"]) / 100 if inv["total"].isdigit() else inv["total"]
                    st.markdown(
                        f"<div style='background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;"
                        f"padding:10px 16px;margin:4px 0;font-size:13px;display:flex;justify-content:space-between'>"
                        f"<span style='color:#94a3b8'>{inv.get('number', inv['id'][:12])}</span>"
                        f"<span style='color:#22c55e;font-weight:600'>{inv_total} {inv['currency']}</span>"
                        f"<span style='color:#475569'>{inv.get('paid_at', '')[:10]}</span>"
                        + (f"<a href='{inv['invoice_url']}' target='_blank' style='color:#60a5fa'>PDF</a>"
                           if inv.get('invoice_url') else "")
                        + f"</div>",
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
        upgrade_options = [
            ("starter", "Starter", "$29/mo", ["100 analyses/mo", "VirusTotal + OSINT", "AI security reports", "Email alerts"]),
            ("business", "Business", "$99/mo", ["500 analyses/mo", "Priority support", "Team access", "All features"]),
            ("consultant", "Consultant", "$149/mo", ["2000 analyses/mo", "White-label", "SOC dashboard", "All features"]),
            ("enterprise", "Enterprise", "Custom", ["Unlimited analyses", "SLA guarantee", "White-label", "Dedicated support"]),
        ]
        upgrade_cols = st.columns(len(upgrade_options))
        for i, (pkey, plabel, pprice, pfeatures) in enumerate(upgrade_options):
            with upgrade_cols[i]:
                featured = pkey == "business"
                bg = "linear-gradient(160deg, #040f24, #071530)" if featured else "#0f172a"
                already_on = plan == pkey
                st.markdown(
                    "<div style='background:" + bg + ";border:" + border + ";"
                    "border-radius:16px;padding:24px 16px;text-align:center;"
                    "height:280px;position:relative'>"
                    + ("<div style='position:absolute;top:-10px;left:50%;transform:translateX(-50%);"
                       "background:#3b82f6;color:#020818;font-size:9px;font-weight:700;"
                       "padding:3px 14px;border-radius:100px'>POPULAR</div>" if featured else "")
                    + "<div style='color:#94a3b8;font-weight:600;margin-bottom:6px'>" + plabel + "</div>"
                    + "<div style='color:#f0f6ff;font-size:2rem;font-weight:800;margin-bottom:2px'>" + pprice + "</div>"
                    + "<div style='color:#475569;font-size:0.7rem;margin-bottom:16px'>/ month</div>"
                    + "".join("<div style='color:#94a3b8;font-size:0.75rem;padding:3px 0'>→ " + f + "</div>" for f in pfeatures)
                    + "</div>",
                    unsafe_allow_html=True
                )
                if already_on:
                    st.success("✅ Current Plan")
                elif pkey == "enterprise":
                    st.info("Contact sales for Enterprise")
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

    from src.api_keys import generate_api_key, delete_api_key, init_api_keys_table
    import sqlite3
    from pathlib import Path
    api_db = Path(__file__).parent / "data" / "phishguard.db"
    init_api_keys_table()
    conn = sqlite3.connect(str(api_db))
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
                conn2 = sqlite3.connect(str(api_db))
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
settings_tab = tab8 if is_admin else tab6

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
            from src.email_verify import is_email_verified, create_verification, send_verification_email
            if not is_email_verified(username):
                if current_email:
                    st.warning("📧 Email not verified. Some features are restricted.")
                    if st.button("📨 Resend Verification Email", use_container_width=True):
                        base = st.secrets.get("base_url", "http://localhost:8501")
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
            from src.mfa import setup_mfa, enable_mfa, disable_mfa, is_mfa_enabled
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
                    from urllib.parse import quote
                    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={quote(uri)}"
                    st.markdown(
                        f"<div style='text-align:center'><img src='{qr_url}' "
                        f"width='180' alt='QR Code'></div>",
                        unsafe_allow_html=True
                    )
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
            if webhook_url and not webhook_url.startswith(("https://hooks.slack.com/", "https://outlook.office.com/webhook/")):
                st.error("Invalid webhook URL. Must be a Slack or Teams incoming webhook URL.")
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
            quarantine_host, disable_ad_account, broadcast_slack_channel, get_soar_status,
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
            from src.alerting import send_webhook, build_alert
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

training_tab = tab9 if is_admin else tab7

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
            from src.campaign_engine import (
                CAMPAIGN_TEMPLATES, generate_llm_template,
                launch_campaign, get_campaign_results,
                save_template, list_templates, delete_template,
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
                            if st.button(f"🗑 Delete", key=f"del_tmpl_{t['id']}"):
                                delete_template(t["id"])
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
champions_tab = tab9 if is_admin else tab7

with champions_tab:
    render_leaderboard(username)

# ═════════════════════════════════════════════════════════════════════════════
# LAST TAB — HISTORY
# ═════════════════════════════════════════════════════════════════════════════
history_tab = tab10 if is_admin else tab8

with history_tab:
    from src.ui_history import render_history_tab
    render_history_tab()


# ═════════════════════════════════════════════════════════════════════════════
# TAB — STIX 2.1 THREAT INTELLIGENCE SHARING
# ═════════════════════════════════════════════════════════════════════════════
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
            import sqlite3
            from pathlib import Path
            db_path = Path(__file__).parent / "data" / "phishguard.db"
            conn = sqlite3.connect(db_path)
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
    with tab_audit:
        from src.ui_audit_log import render_audit_log_tab
        render_audit_log_tab()

# ═════════════════════════════════════════════════════════════════════════════
# NEW TAB — PERFORMANCE MONITOR
# ═════════════════════════════════════════════════════════════════════════════
if is_admin:
    with tab_perf:
        from src.ui_performance import render_performance_tab
        render_performance_tab()

# ═════════════════════════════════════════════════════════════════════════════
# TAB — M&A DILIGENCE (Acquire.com Valuation Optimizer)
# ═════════════════════════════════════════════════════════════════════════════
with tab_ma:
    st.markdown("## 📈 M&A Diligence Dashboard")
    st.markdown(
        "<p style='color:#94a3b8'>Verified transaction telemetry for acquirer due diligence. "
        "Audit-proof logs of user engagement, ARR, and SDE multiples.</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    from src.database import get_valuation_summary, get_valuation_logs
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
with tab_webhook:
    from src.ui_webhook_tester import render_webhook_tester_tab
    render_webhook_tester_tab()

# ═════════════════════════════════════════════════════════════════════════════
# NEW TAB — SOC DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
with tab_soc:
    from src.ui_soc_dashboard import render_soc_dashboard
    render_soc_dashboard(username)

# ═════════════════════════════════════════════════════════════════════════════
# NEW TAB — ACTIVITY TIMELINE
# ═════════════════════════════════════════════════════════════════════════════
with tab_timeline:
    from src.activity_timeline import init_activity_timeline, record_activity, get_activity
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
        st.info("No activity recorded yet. Actions will appear here as you use the platform.")

    record_activity(username, "view_timeline", detail="Viewed activity timeline")

# ═════════════════════════════════════════════════════════════════════════════
# NEW TAB — SCIM / AUDIT LOG (non-admin webhook tester only)
# ═════════════════════════════════════════════════════════════════════════════