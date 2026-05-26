import streamlit as st
import plotly.graph_objects as go
from src.detector import analyze_email
from src.database import init_db, save_analysis, get_history
from src.report_generator import generate_pdf_report
from src.auth import check_password, logout
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.osint import run_osint
from src.admin import get_stats, get_all_analyses, get_recent_threats, get_daily_counts
from src.tenants import (
    log_usage, check_quota, get_all_tenants, get_usage_all_tenants,
    create_tenant, update_tenant, delete_tenant, set_password, PLANS
)

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡",
                   layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
.block-container { padding-top: 1.5rem; }
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
</style>
""", unsafe_allow_html=True)

if not check_password():
    st.stop()

init_db()

username = st.session_state.get("username", "user")
plan     = st.session_state.get("plan", "trial")
is_admin = st.session_state.get("is_admin", False)

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
    quota_html = (
        "<div style='margin-top:10px;padding:8px 14px;background:#111827;"
        "border-radius:10px;border:1px solid #1e3a5f'>"
        "<div style='display:flex;justify-content:space-between;"
        "font-size:12px;color:#94a3b8;margin-bottom:4px'>"
        "<span>📊 " + plan_label + " plan</span>"
        "<span>" + str(q["usage"]) + " / " + limit_display + " analyses</span>"
        "</div>"
        "<div class='quota-bar-bg'>"
        "<div class='quota-bar-fill' style='width:" + str(bar_width) + "%;background:" + bar_color + "'></div>"
        "</div></div>"
    )
    st.markdown(quota_html, unsafe_allow_html=True)

with col_user:
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        "<p style='color:#94a3b8;text-align:right'>👤 " + username + "</p>",
        unsafe_allow_html=True
    )
    if st.button("Logout", use_container_width=True):
        logout()

st.divider()

# ── Tabs ─────────────────────────────────────────────────────────────────────
if is_admin:
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Analyze Email", "📊 History", "⚙ Admin Dashboard", "👥 Clients"
    ])
else:
    tab1, tab2 = st.tabs(["🔍 Analyze Email", "📊 History"])

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
        email_text = st.text_area(
            label="email", label_visibility="collapsed",
            placeholder="Paste the full email here — subject, headers, body, links...",
            height=260
        )

    with col_right:
        st.markdown("#### ⚙ Options")
        st.checkbox("Analyze URLs", value=True)
        st.checkbox("Keyword Detection", value=True)
        st.checkbox("Social Engineering", value=True)
        enable_vt = st.checkbox("Threat Intelligence + OSINT", value=True)
        st.markdown("")
        analyze_btn = st.button("🔍 Analyze Email", use_container_width=True, type="primary")
        st.markdown("")
        st.info("💡 Paste any suspicious email and click Analyze.")

    if analyze_btn:
        if not email_text.strip():
            st.warning("⚠ Please paste an email first.")
        else:
            with st.spinner("Scanning for threats..."):
                results = analyze_email(email_text)
                save_analysis(results, email_text)
                log_usage(username, "analysis", results["risk_score"])

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

            st.session_state["results"]    = results
            st.session_state["email_text"] = email_text
            st.session_state["vt_results"] = vt_results
            st.session_state["vt_summary"] = vt_summary
            st.session_state["osint_data"] = osint_data
            st.session_state.pop("ai_report", None)

    if "results" in st.session_state:
        results          = st.session_state["results"]
        email_text_saved = st.session_state["email_text"]
        vt_results       = st.session_state.get("vt_results", [])
        osint_data       = st.session_state.get("osint_data", {})

        st.divider()
        st.markdown("## 📊 Analysis Results")

        score    = results["risk_score"]
        severity = results["severity"]
        color    = results["severity_color"]

        col_gauge, col_m1, col_m2, col_m3 = st.columns([1.2, 1, 1, 1])
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

        st.divider()

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

        # Export
        st.divider()
        st.markdown("<div class='section-title'>📄 Export & AI Analysis</div>",
                    unsafe_allow_html=True)
        col_ai, col_pdf = st.columns(2)

        with col_ai:
            if st.button("🤖 Generate AI Security Report",
                         use_container_width=True, type="secondary"):
                try:
                    from src.ai_analyzer import ai_analyze_email
                    with st.spinner("AI is writing your security report..."):
                        ai_report = ai_analyze_email(email_text_saved, results)
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
# TAB 2 — HISTORY
# ═════════════════════════════════════════════════════════════════════════════
with tab2:
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
# TAB 3 — ADMIN DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
if is_admin:
    with tab3:
        st.markdown("## ⚙ Admin Dashboard")
        st.markdown(
            "<p style='color:#94a3b8'>Only visible to admin account</p>",
            unsafe_allow_html=True
        )
        st.divider()

        stats = get_stats()
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
            daily  = get_daily_counts(14)
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
        threats = get_recent_threats(10)
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
            all_a = get_all_analyses(100)
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


# ═════════════════════════════════════════════════════════════════════════════
# TAB 4 — CLIENT MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════
if is_admin:
    with tab4:
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