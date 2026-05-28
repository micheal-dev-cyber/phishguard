import os
import streamlit as st
import plotly.graph_objects as go
from datetime import datetime

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡",
                   layout="wide", initial_sidebar_state="collapsed")

# ── All src.* imports go AFTER set_page_config to avoid Streamlit init issues ──
from src.detector import analyze_email
from src.database import init_db, save_analysis, get_history
from src.report_generator import generate_pdf_report
from src.auth import check_password, logout
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.osint import run_osint
from src.admin import get_stats, get_all_analyses, get_recent_threats, get_daily_counts
from src.alerts import send_threat_alert, get_alert_log
from src.header_auth import analyze_auth_headers
from src.copilot import get_copilot_response, SUGGESTED_PROMPTS
from src.ai_analyzer import simulate_phishing, analyze_screenshot, generate_ai_report
from src.xai_analyzer import analyze_psychological_triggers, format_xai_report
from src.email_parser import parse_email_file
from src.jury_engine import evaluate_linguistic_jury, evaluate_corporate_jury, compute_ensemble_score
from src.b2b_gateway import get_tier_config, check_feature_access, MockAPIGateway
from src.webhook_gateway import send_alert as send_webhook_alert
from src.threat_scorer import compute_combined_threat_score, format_combined_report
from src.tenants import (
    log_usage, check_quota, get_all_tenants, get_usage_all_tenants,
    create_tenant, update_tenant, delete_tenant, set_password, PLANS
)
from src.paddle_billing import (
    is_configured as paddle_configured,
    generate_checkout_url,
    verify_transaction,
)
from src.ratelimit import check_rate_limit, get_rate_limit_remaining
from src.leaderboard import render_leaderboard, record_scan as lb_record_scan
from src.env import ENV, get_config_status, log_config_status

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
</style>
""", unsafe_allow_html=True)

init_db()
log_config_status()

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
    if st.button("⬆ Upgrade Plan", key="upgrade_btn", use_container_width=True):
        st.session_state["show_upgrade"] = True
        st.rerun()

with col_user:
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Notification Bell ────────────────────────────────────────────────
    if "notifications" not in st.session_state:
        st.session_state["notifications"] = []
    n_count = len(st.session_state["notifications"])
    n_badge = f'<span style="background:#ff4444;color:#fff;border-radius:50%;padding:1px 6px;font-size:10px;margin-left:4px">{n_count}</span>' if n_count else ""
    st.markdown(
        f'<div style="text-align:right;font-size:13px;color:#94a3b8">'
        f'🔔{n_badge} 👤 {username}</div>',
        unsafe_allow_html=True,
    )
    if n_count > 0:
        with st.expander(f"🔔 {n_count} Alert(s)", expanded=False):
            for n in st.session_state["notifications"][-5:]:
                c = "#ff4444" if n["severity"] == "CRITICAL" else "#ff8800"
                st.markdown(
                    f"<div style='border-left:3px solid {c};padding:4px 8px;margin:4px 0;"
                    f"background:#111827;border-radius:6px;font-size:12px'>"
                    f"<span style='color:{c};font-weight:700'>{n['severity']}</span> "
                    f"<span style='color:#94a3b8'>{n['message'][:60]}</span>"
                    f"<span style='color:#475569;display:block;font-size:10px'>{n.get('time','')}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            if st.button("Clear All", key="clear_notif", use_container_width=True):
                st.session_state["notifications"] = []
                st.rerun()

    # ── Theme Toggle ─────────────────────────────────────────────────────
    if "theme" not in st.session_state:
        st.session_state["theme"] = "dark"
    theme_toggle = st.toggle("☀️", value=(st.session_state["theme"] == "light"),
                              key="theme_toggle", help="Toggle light/dark theme")
    new_theme = "light" if theme_toggle else "dark"
    if new_theme != st.session_state["theme"]:
        st.session_state["theme"] = new_theme
        st.rerun()
    st.markdown(
        f"<p style='color:#94a3b8;text-align:right;font-size:11px'>{'☀️ Light' if theme_toggle else '🌙 Dark'}</p>",
        unsafe_allow_html=True,
    )

    if st.button("Logout", use_container_width=True):
        logout()

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
            ("starter",  "Starter",   "$29/mo", ["100 analyses/mo", "VirusTotal scans", "OSINT investigation", "AI security reports", "Email alerts"]),
            ("business", "Business",  "$99/mo", ["500 analyses/mo", "Everything in Starter", "Priority support", "Team access", "Export + API access"]),
            ("enterprise", "Enterprise", "Custom", ["Unlimited analyses", "SLA guarantee", "White-label option", "Dedicated support", "Custom integrations"]),
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
                            base = st.context.headers.get("Origin", "https://phishguard.streamlit.app")
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

# ── Tabs ─────────────────────────────────────────────────────────────────────
# Positions (both):     1        2         3
# Admin:                4        5         6     7      8      9       10      11       12       13      14
# Non-admin:            4        5         6     7      8
# Enterprise (both):    9/11    10/12     11/13  12/14
if is_admin:
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11, tab12, tab13, tab14 = st.tabs([
        "🔍 Analyze Email", "📈 Analytics", "🤖 AI Copilot",
        "⚙ Admin Dashboard", "👥 Clients",
        "💳 Billing", "⚙ Settings", "🧪 Training", "🏆 Champions", "📊 History",
        "🧬 STIX Intel", "📧 Sender Profiler", "🔗 URL Sandbox", "👁 OCR/Homograph",
    ])
    tab_stix, tab_sender, tab_sandbox, tab_ocr = tab11, tab12, tab13, tab14
else:
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11, tab12 = st.tabs([
        "🔍 Analyze Email", "📈 Analytics", "🤖 AI Copilot",
        "💳 Billing", "⚙ Settings", "🧪 Training", "🏆 Champions", "📊 History",
        "🧬 STIX Intel", "📧 Sender Profiler", "🔗 URL Sandbox", "👁 OCR/Homograph",
    ])
    tab_stix, tab_sender, tab_sandbox, tab_ocr = tab9, tab10, tab11, tab12

# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — ANALYZER
# ═════════════════════════════════════════════════════════════════════════════
with tab1:
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
                results = analyze_email(email_text)
                save_analysis(results, email_text)
                log_usage(username, "analysis", results["risk_score"])
                lb_record_scan(
                    username,
                    severity=results["severity"],
                    score=results["risk_score"],
                )
                # Send email alert if HIGH or CRITICAL
                user_email = st.session_state.get("email", "")
                if user_email and results["severity"] in ("CRITICAL", "HIGH"):
                    send_threat_alert(username, user_email, results)

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
            st.session_state.pop("ai_report", None)

    if "results" in st.session_state:
        results          = st.session_state["results"]
        email_text_saved = st.session_state["email_text"]
        vt_results       = st.session_state.get("vt_results", [])
        osint_data       = st.session_state.get("osint_data", {})
        header_auth      = st.session_state.get("header_auth", {})

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
            fig = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": f"<b>{severity}</b>", "font": {"color": color, "size": 16}},
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
                    )
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

        # Export
        st.divider()
        st.markdown("<div class='section-title'>📄 Export & AI Analysis</div>",
                    unsafe_allow_html=True)
        col_ai, col_pdf = st.columns(2)

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
            pdf_bytes = generate_pdf_report(results, email_text_saved, ai_report_text)
            sev_lower = results["severity"].lower()
            st.download_button(
                label="📥 Download PDF Report",
                data=pdf_bytes,
                file_name=f"phishguard_report_{sev_lower}.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary"
            )

        if "ai_report" in st.session_state:
            st.markdown("<div class='section-title'>🤖 AI Security Analysis</div>",
                        unsafe_allow_html=True)
            st.markdown(st.session_state["ai_report"])


# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — ENTERPRISE ANALYTICS DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("## 📈 Enterprise Analytics")
    st.caption("Real-time threat intelligence and scanning metrics.")
    if st.button("🔄 Refresh Data", key="refresh_analytics"):
        _cached_history.clear()
        st.rerun()
    st.divider()

    history = _cached_history(500)
    if not history:
        st.info("No scan data yet. Go to Analyze and scan your first email.")
    else:
        # ── Compute metrics ────────────────────────────────────────────────
        scores = [row[1] for row in history]
        severities = [row[2] for row in history]
        timestamps = [row[0] for row in history]

        total_scans = len(history)
        avg_score = round(sum(scores) / total_scans, 1) if total_scans else 0
        critical_count = sum(1 for s in severities if s == "CRITICAL")
        high_count = sum(1 for s in severities if s == "HIGH")
        safe_count = sum(1 for s in severities if s == "LOW")

        # ── KPI cards ──────────────────────────────────────────────────────
        col_k1, col_k2, col_k3, col_k4 = st.columns(4)
        col_k1.metric("Total Scans", total_scans)
        col_k2.metric("Avg Risk Score", f"{avg_score}/100")
        col_k3.metric("Critical Threats", critical_count)
        col_k4.metric("Safe Emails", safe_count)
        st.divider()

        # ── Line chart: daily scan volumes and threat distribution ─────────
        st.markdown("#### 📅 Daily Scan Volume & Threat Distribution")
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
                font_color="#e2e8f0", height=300,
                margin=dict(t=20, b=20, l=20, r=20),
                legend=dict(orientation="h", y=1.1),
                xaxis=dict(gridcolor="#1e3a5f", tickangle=-45),
                yaxis=dict(gridcolor="#1e3a5f", title="Count"),
            )
            st.plotly_chart(fig_line, use_container_width=True)

        st.divider()

        # ── Pie: Safe vs Phishing ──────────────────────────────────────────
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            st.markdown("#### 🛡 Safe vs Phishing Encounters")
            phish_count = critical_count + high_count
            medium_count = sum(1 for s in severities if s == "MEDIUM")
            fig_pie = go.Figure(go.Pie(
                labels=["Safe (LOW)", "Medium Risk", "High Risk", "Critical"],
                values=[safe_count, medium_count, high_count, critical_count],
                hole=0.45,
                marker_colors=["#44aa44", "#ffaa00", "#ff8800", "#ff4444"],
                textinfo="label+percent",
                textfont=dict(size=11, color="#e2e8f0"),
            ))
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=280,
                margin=dict(t=10, b=10, l=10, r=10),
                showlegend=False,
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        # ── Horizontal bar: psychological triggers ─────────────────────────
        with col_p2:
            st.markdown("#### 🧠 Most Frequent Psychological Triggers")
            # Compute trigger frequencies from xai_analyzer
            st.info(
                "Trigger frequency data recorded per scan. "
                "Run analyses with XAI enabled to populate this chart."
            )

        st.divider()

        # ── Trigger breakdown bar chart (computed from stored session) ─────
        st.markdown("#### 📊 Trigger Category Breakdown (Last Analysis)")
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
                title="Psychological Trigger Intensity (from XAI engine)",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=300,
                margin=dict(t=30, b=10, l=10, r=60),
                xaxis=dict(range=[0, 105], gridcolor="#1e3a5f", title="Score"),
                yaxis=dict(gridcolor="#1e3a5f"),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        st.divider()

        # ── Threat trend mini-table ────────────────────────────────────────
        with st.expander("📋 Recent Threat Summary (Last 20 Scans)"):
            for row in history[:20]:
                ts, sc, sev, kw, su, preview = row
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
                st.markdown(
                    f"{emoji} **{sev}** | Score {sc}/100 | {ts[:16]} | "
                    f"Keywords: {kw} | URLs: {su}"
                )

        # ── Weekly Digest ───────────────────────────────────────────────────
        st.divider()
        st.markdown("#### 📬 Weekly Digest")
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


# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 — AI COPILOT
# ═════════════════════════════════════════════════════════════════════════════
with tab3:
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
            st.markdown(
                "<div style='display:flex;justify-content:flex-end;margin:8px 0'>"
                "<div style='background:#1e3a5f;border-radius:14px 14px 2px 14px;"
                "padding:12px 18px;max-width:75%;color:#e2e8f0;font-size:14px'>"
                + content +
                "</div></div>",
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                "<div style='display:flex;justify-content:flex-start;margin:8px 0'>"
                "<div style='background:#111827;border:1px solid #1e3a5f;"
                "border-radius:14px 14px 14px 2px;padding:14px 18px;"
                "max-width:80%;color:#e2e8f0;font-size:14px;line-height:1.6'>"
                + content.replace("\n", "<br>") +
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
    with tab4:
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


# ═════════════════════════════════════════════════════════════════════════════
# TAB 4 — CLIENT MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════
if is_admin:
    with tab5:
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
                        update_tenant(uname, plan=new_plan_val)
                        st.success(f'Plan updated to {PLANS[new_plan_val]["label"]}')
                        st.rerun()

                    new_pw = st.text_input(
                        "New password", type="password",
                        key="pw_" + uname
                    )
                    if st.button("🔑 Reset Password", key="rpw_" + uname):
                        if new_pw:
                            set_password(uname, new_pw)
                            st.success("Password updated.")
                        else:
                            st.warning("Enter a new password first.")

                b1, b2, b3 = st.columns(3)
                if uactive:
                    if b1.button("⏸ Suspend", key="sus_" + uname):
                        update_tenant(uname, is_active=0)
                        st.warning(f"{uname} suspended.")
                        st.rerun()
                else:
                    if b1.button("▶ Reactivate", key="act_" + uname):
                        update_tenant(uname, is_active=1)
                        st.success(f"{uname} reactivated.")
                        st.rerun()
                if b3.button("🗑 Delete", key="del_" + uname):
                    delete_tenant(uname)
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
billing_tab = tab6 if is_admin else tab4

with billing_tab:
    st.markdown("## 💳 Billing & Subscription")
    st.divider()

    plan_info = PLANS.get(plan, PLANS["trial"])
    q = check_quota(username, plan)

    # Current plan card
    st.markdown(
        "<div style='background:#111827;border:1px solid #1e3a5f;"
        "border-radius:16px;padding:28px 32px;margin-bottom:24px'>"
        "<div style='display:flex;justify-content:space-between;align-items:center'>"
        "<div>"
        "<div style='color:#64748b;font-size:0.8rem;text-transform:uppercase;"
        "letter-spacing:0.08em;margin-bottom:4px'>Current Plan</div>"
        "<div style='color:#f0f6ff;font-size:1.8rem;font-weight:800'>"
        + plan_info["label"] + "</div>"
        "<div style='color:#475569;font-size:0.85rem;margin-top:4px'>"
        + plan_info["price"] + "</div>"
        "</div>"
        "<div style='text-align:right'>"
        "<div style='color:#94a3b8;font-size:0.9rem'>"
        + str(q["usage"]) + " / " + str(q["limit"]) + " analyses used</div>"
        "<div style='background:#1e3a5f;border-radius:4px;height:6px;width:120px;margin:6px 0 0 auto'>"
        "<div style='background:#60a5fa;border-radius:4px;height:6px;width:"
        + str(q["pct"]) + "%'></div></div></div></div></div>",
        unsafe_allow_html=True
    )

    if plan == "enterprise":
        st.success("🌟 You are on the **Enterprise** plan — unlimited analyses, all features enabled.")
    else:
        col1, col2, col3 = st.columns(3)
        upgrade_options = [
            ("starter", "Starter", "$29/mo", ["100 analyses/mo", "VirusTotal + OSINT", "AI security reports", "Email alerts"]),
            ("business", "Business", "$99/mo", ["500 analyses/mo", "Priority support", "Team access", "All features"]),
            ("enterprise", "Enterprise", "Custom", ["Unlimited analyses", "SLA guarantee", "White-label", "Dedicated support"]),
        ]
        for i, (pkey, plabel, pprice, pfeatures) in enumerate(upgrade_options):
            with [col1, col2, col3][i]:
                featured = pkey == "business"
                border = "2px solid #3b82f6" if featured else "1px solid rgba(255,255,255,0.1)"
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
settings_tab = tab7 if is_admin else tab5

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

# ═════════════════════════════════════════════════════════════════════════════
# TAB 8/6 — TRAINING (Simulator + Screenshot Scanner)
# ═════════════════════════════════════════════════════════════════════════════
training_tab = tab8 if is_admin else tab6

with training_tab:
    st.markdown("## 🧪 Security Training Tools")
    st.markdown(
        "<p style='color:#64748b;margin-top:-8px'>Interactive tools to help you "
        "recognise phishing attempts and test your security awareness.</p>",
        unsafe_allow_html=True
    )
    st.divider()

    sub_tab1, sub_tab2 = st.tabs(["🎣 Phishing Simulator", "📷 Screenshot Scanner"])

    # ── Sub-tab 1: Phishing Simulator ────────────────────────────────────────
    with sub_tab1:
        st.markdown("### 🎣 Phishing Simulation Generator")
        st.markdown(
            "<p style='color:#64748b;margin-top:-8px'>Generate context-specific "
            "phishing simulations targeting real corporate departments. "
            "Use these to test and train your team.</p>",
            unsafe_allow_html=True
        )

        col_sim_dept, col_sim_vec = st.columns(2)
        with col_sim_dept:
            department = st.selectbox(
                "Target Department",
                options=["Finance", "HR", "IT Support"],
                index=0,
                label_visibility="collapsed",
                key="sim_dept"
            )
        with col_sim_vec:
            attack_vector = st.selectbox(
                "Attack Vector",
                options=["Urgent Invoice", "Password Reset", "Fake HR Policy"],
                index=0,
                label_visibility="collapsed",
                key="sim_vector"
            )

        dept_icons = {"Finance": "🏦", "HR": "📋", "IT Support": "🖥"}
        vec_icons = {"Urgent Invoice": "📄", "Password Reset": "🔑", "Fake HR Policy": "📜"}

        st.markdown(
            f"<div style='background:#0f172a;border:1px solid #1e3a5f;"
            f"border-radius:10px;padding:14px 18px;margin:8px 0 16px 0;"
            f"color:#94a3b8;font-size:13px'>"
            f"Scenario: {dept_icons.get(department, '')} <b>{department}</b> "
            f"via {vec_icons.get(attack_vector, '')} <b>{attack_vector}</b></div>",
            unsafe_allow_html=True
        )

        if st.button("🎲 Generate Simulation", type="primary", use_container_width=True):
            with st.spinner("Generating context-specific phishing simulation..."):
                sim = simulate_phishing(department, attack_vector)
            st.session_state["simulation"] = sim
            st.session_state["sim_reveal"] = False

        sim = st.session_state.get("simulation")
        if sim:
            st.divider()
            st.markdown("### 📧 Simulated Email")

            col_sim1, col_sim2 = st.columns([1, 3])
            with col_sim1:
                st.markdown("**From:**")
                st.markdown("**Subject:**")
                st.markdown("**Body:**")
            with col_sim2:
                st.markdown(f"`{sim.get('sender', 'unknown@example.com')}`")
                st.markdown(f"**{sim.get('subject', '(no subject)')}**")
                st.markdown(
                    "<div style='background:#0f172a;border:1px solid #1e3a5f;"
                    "border-radius:10px;padding:16px;font-family:monospace;"
                    "font-size:13px;color:#94a3b8;line-height:1.6;margin-top:4px;"
                    "max-height:300px;overflow-y:auto'>"
                    + sim.get("body", "").replace("\n", "<br>") +
                    "</div>",
                    unsafe_allow_html=True
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

                st.divider()
                st.markdown("### 📊 What to Look For")
                st.markdown(
                    "- **Urgency tactics** — phrases like 'act now', 'limited time', "
                    "'suspended' are red flags\n"
                    "- **Spoofed domains** — check the sender domain carefully, "
                    "phishers use similar-looking addresses\n"
                    "- **Generic greetings** — real companies use your name\n"
                    "- **Suspicious links** — hover before clicking, check the real URL\n"
                    "- **Requests for credentials** — legitimate companies never ask "
                    "for passwords or personal info\n"
                    "- **Poor grammar/spelling** — many phishing emails originate "
                    "from non-native speakers"
                )

                if st.button("🔄 Try Another Scenario", use_container_width=True):
                    st.session_state.pop("simulation", None)
                    st.session_state.pop("sim_reveal", None)
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
    st.markdown("#### 📊 Recent Analyses")
    history = get_history(20)
    if not history:
        st.info("No analyses yet. Go to Analyze and scan your first email.")
    else:
        scores     = [row[1] for row in history]
        labels     = [f"#{i+1}" for i in range(len(history))]
        colors_bar = [
            "#ff4444" if s >= 75 else
            "#ff8800" if s >= 50 else
            "#ffaa00" if s >= 25 else
            "#44aa44"
            for s in scores
        ]
        fig2 = go.Figure(go.Bar(
            x=labels, y=scores, marker_color=colors_bar,
            text=scores, textposition="outside"
        ))
        fig2.update_layout(
            title="Risk Scores — Last 20 Analyses", yaxis_range=[0, 110],
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0", height=300, margin=dict(t=40, b=20, l=20, r=20)
        )
        fig2.update_xaxes(showgrid=False)
        fig2.update_yaxes(gridcolor="#1e3a5f")
        st.plotly_chart(fig2, use_container_width=True)

        st.divider()
        for row in history:
            timestamp, score, severity, kw_hits, susp_urls, preview = row
            with st.expander(
                f"**{severity}** — Score {score}/100 — {timestamp[:16]}"
            ):
                ca, cb, cc = st.columns(3)
                ca.metric("Risk Score", score)
                cb.metric("Keyword Hits", kw_hits)
                cc.metric("Suspicious URLs", susp_urls)
                st.markdown(
                    "<div class='url-box' style='color:#94a3b8'>📧 " +
                    preview + "...</div>",
                    unsafe_allow_html=True
                )


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