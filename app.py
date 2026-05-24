import streamlit as st
from src.osint import run_osint
import plotly.graph_objects as go
import plotly.express as px
from src.detector import analyze_email
from src.database import init_db, save_analysis, get_history
from src.report_generator import generate_pdf_report
from src.auth import check_password, logout
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.admin import get_stats, get_all_analyses, get_recent_threats, get_daily_counts, get_severity_trend

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; }
    .tag {
        display: inline-block;
        background: #1e3a5f;
        color: #60a5fa;
        border-radius: 6px;
        padding: 3px 10px;
        margin: 3px;
        font-size: 13px;
        font-family: monospace;
    }
    .url-box {
        background: #1a0a0a;
        border: 1px solid #ff4444;
        border-radius: 8px;
        padding: 10px 14px;
        font-family: monospace;
        font-size: 13px;
        color: #ff8888;
        margin: 5px 0;
    }
    .safe-url-box {
        background: #0a1a0a;
        border: 1px solid #44aa44;
        border-radius: 8px;
        padding: 10px 14px;
        font-family: monospace;
        font-size: 13px;
        color: #88cc88;
        margin: 5px 0;
    }
    .section-title {
        color: #60a5fa;
        font-size: 1.1rem;
        font-weight: 700;
        margin: 18px 0 8px 0;
        border-left: 3px solid #60a5fa;
        padding-left: 10px;
    }
    .stat-card {
        background: #111827;
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

if not check_password():
    st.stop()

init_db()

col_title, col_user = st.columns([4, 1])
with col_title:
    st.markdown("<h1 style='color:#60a5fa; font-size:2rem; margin-bottom:0'>🛡️ PhishGuard AI</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#94a3b8; margin-top:2px'>AI-Powered Phishing & Threat Detection Platform</p>", unsafe_allow_html=True)
with col_user:
    st.markdown("<br>", unsafe_allow_html=True)
    username = st.session_state.get("username", "user")
    st.markdown(f"<p style='color:#94a3b8; text-align:right'>👤 {username}</p>", unsafe_allow_html=True)
    if st.button("Logout", use_container_width=True):
        logout()

st.divider()

is_admin = username == "admin"

if is_admin:
    tab1, tab2, tab3 = st.tabs(["🔍 Analyze Email", "📊 History", "⚙️ Admin Dashboard"])
else:
    tab1, tab2 = st.tabs(["🔍 Analyze Email", "📊 History"])

with tab1:
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown("#### 📧 Paste Email Content")
        email_text = st.text_area(
            label="email",
            label_visibility="collapsed",
            placeholder="Paste the full email here — subject, headers, body, links...",
            height=260
        )

    with col_right:
        st.markdown("#### ⚙️ Options")
        st.checkbox("Analyze URLs", value=True)
        st.checkbox("Keyword Detection", value=True)
        st.checkbox("Social Engineering", value=True)
        enable_vt = st.checkbox("Threat Intelligence (VirusTotal)", value=True)
        st.markdown("")
        analyze_btn = st.button("🔍 Analyze Email", use_container_width=True, type="primary")
        st.markdown("")
        st.info("💡 Paste any suspicious email and click Analyze.")

    if analyze_btn:
        if not email_text.strip():
            st.warning("⚠️ Please paste an email first.")
        else:
            with st.spinner("Scanning for threats..."):
                results = analyze_email(email_text)
                save_analysis(results, email_text)

            vt_results  = []
            vt_summary  = {}
            osint_data  = {}

            if enable_vt and results["urls_found"]:
                with st.spinner("Checking URLs against VirusTotal..."):
                    vt_results = check_multiple_urls(results["urls_found"])
                    vt_summary = get_threat_summary(vt_results)

            if enable_vt:
                with st.spinner("Running OSINT investigation on sender and domains..."):
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

        st.divider()
        st.markdown("## 📊 Analysis Results")

        score    = results["risk_score"]
        severity = results["severity"]
        color    = results["severity_color"]

        col_gauge, col_m1, col_m2, col_m3 = st.columns([1.2, 1, 1, 1])

        with col_gauge:
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": f"<b>{severity}</b>", "font": {"color": color, "size": 16}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                    "bar": {"color": color},
                    "bgcolor": "#111827",
                    "steps": [
                        {"range": [0, 25], "color": "#0a2a0a"},
                        {"range": [25, 50], "color": "#2a2a0a"},
                        {"range": [50, 75], "color": "#2a1a0a"},
                        {"range": [75, 100], "color": "#2a0a0a"},
                    ],
                    "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.75, "value": score}
                },
                number={"font": {"color": color, "size": 48}}
            ))
            fig.update_layout(
                height=220,
                margin=dict(t=40, b=10, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0"
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_m1:
            st.metric("🔗 URLs Found", results["url_count"])
        with col_m2:
            st.metric("🚨 Suspicious URLs", results["suspicious_url_count"])
        with col_m3:
            st.metric("🎯 Keyword Hits", results["total_keyword_hits"])

        st.divider()

        if results["keyword_matches"]:
            st.markdown("<div class='section-title'>🎯 Phishing Indicators</div>", unsafe_allow_html=True)
            for category, keywords in results["keyword_matches"].items():
                with st.expander(f"**{category.upper()}** — {len(keywords)} match(es)"):
                    tags = " ".join([f"<span class='tag'>{kw}</span>" for kw in keywords])
                    st.markdown(tags, unsafe_allow_html=True)

        if results["suspicious_urls"]:
            st.markdown("<div class='section-title'>🔗 Suspicious URLs Detected</div>", unsafe_allow_html=True)
            for item in results["suspicious_urls"]:
                st.markdown(f"<div class='url-box'>🚨 {item['url']}</div>", unsafe_allow_html=True)
        elif results["urls_found"]:
            st.markdown("<div class='section-title'>🔗 URLs Found (no pattern threats)</div>", unsafe_allow_html=True)
            for url in results["urls_found"]:
                st.markdown(f"<div class='safe-url-box'>🔗 {url}</div>", unsafe_allow_html=True)

        if vt_results:
            st.markdown("<div class='section-title'>🌐 Threat Intelligence (VirusTotal)</div>", unsafe_allow_html=True)
            for vt in vt_results:
                status  = vt.get("status", "error")
                url     = vt.get("url", "")
                mal     = vt.get("malicious", 0)
                sus     = vt.get("suspicious", 0)
                total   = vt.get("total_vendors", 0)
                threats = vt.get("threat_names", [])
                vt_link = vt.get("vt_link", "")

                if status == "malicious":
                    st.markdown(f"<div class='url-box'>🔴 <b>MALICIOUS</b> — {url[:70]}<br><span style='font-size:12px'>{mal} of {total} vendors flagged{f' | {chr(44).join(threats)}' if threats else ''}</span></div>", unsafe_allow_html=True)
                elif status == "suspicious":
                    st.markdown(f"<div style='background:#2a1a0a;border:1px solid #ff8800;border-radius:8px;padding:10px 14px;margin:4px 0'>🟠 <b>SUSPICIOUS</b> — {url[:70]}<br><span style='font-size:12px;color:#ff8800'>{mal} malicious, {sus} suspicious of {total} vendors</span></div>", unsafe_allow_html=True)
                elif status == "clean":
                    st.markdown(f"<div class='safe-url-box'>🟢 <b>CLEAN</b> — {url[:70]}<br><span style='font-size:12px'>No threats from {total} vendors</span></div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div style='background:#111827;border:1px solid #1e3a5f;border-radius:8px;padding:10px 14px;margin:4px 0;font-size:12px;color:#64748b'>⚪ Could not check: {url[:70]}</div>", unsafe_allow_html=True)

                if vt_link and status != "error":
                    st.markdown(f"<a href='{vt_link}' target='_blank' style='font-size:11px;color:#60a5fa'>View on VirusTotal →</a>", unsafe_allow_html=True)
        
                    osint_data = st.session_state.get("osint_data", {})
        if osint_data and osint_data.get("domain_results"):
            st.markdown("<div class='section-title'>🔎 OSINT Investigation</div>", unsafe_allow_html=True)

            if osint_data.get("sender"):
                st.markdown(f"**Sender:** `{osint_data['sender']}`")

            osint_risk = osint_data.get("osint_risk_score", 0)
            if osint_risk >= 75:
                st.error(f"🔴 OSINT Risk Score: {osint_risk}/100 — High confidence threat")
            elif osint_risk >= 50:
                st.warning(f"🟠 OSINT Risk Score: {osint_risk}/100 — Suspicious infrastructure")
            elif osint_risk >= 25:
                st.warning(f"🟡 OSINT Risk Score: {osint_risk}/100 — Some suspicious indicators")
            else:
                st.success(f"🟢 OSINT Risk Score: {osint_risk}/100 — No major concerns")

            for domain_result in osint_data["domain_results"]:
                domain    = domain_result["domain"]
                d_score   = domain_result["risk_score"]
                country   = domain_result.get("country", "Unknown")
                org       = domain_result.get("org", "Unknown")
                age       = domain_result.get("domain_age_days")
                created   = domain_result.get("creation_date", "Unknown")
                ip        = domain_result.get("ip", "Unknown")
                indicators = domain_result.get("risk_indicators", [])

                color = "#ff4444" if d_score >= 75 else "#ff8800" if d_score >= 50 else "#ffaa00" if d_score >= 25 else "#44aa44"

                with st.expander(f"🌐 **{domain}** — Risk: {d_score}/100"):
                    col_d1, col_d2, col_d3 = st.columns(3)
                    col_d1.metric("Risk Score", f"{d_score}/100")
                    col_d2.metric("Country", country)
                    col_d3.metric("Domain Age", f"{age} days" if age else "Unknown")

                    st.markdown(f"""
                    <div style='background:#111827;border:1px solid #1e3a5f;
                        border-radius:8px;padding:12px;margin:8px 0;
                        font-size:13px'>
                        <b style='color:#94a3b8'>IP Address:</b>
                        <span style='color:#e2e8f0'> {ip}</span><br>
                        <b style='color:#94a3b8'>Organization:</b>
                        <span style='color:#e2e8f0'> {org}</span><br>
                        <b style='color:#94a3b8'>Created:</b>
                        <span style='color:#e2e8f0'> {created}</span>
                    </div>
                    """, unsafe_allow_html=True)

                    if indicators:
                        st.markdown("**⚠️ Risk Indicators:**")
                        for ind in indicators:
                            st.markdown(f"- {ind}")

            if osint_data.get("ip_results"):
                st.markdown("**🖥️ IP Investigation:**")
                for ip_result in osint_data["ip_results"]:
                    ip      = ip_result["ip"]
                    country = ip_result.get("country", "Unknown")
                    org     = ip_result.get("org", "Unknown")
                    ip_inds = ip_result.get("risk_indicators", [])
                    ip_score = ip_result.get("risk_score", 0)

                    st.markdown(f"""
                    <div style='background:#111827;border:1px solid #1e3a5f;
                        border-radius:8px;padding:12px;margin:4px 0;
                        font-size:13px'>
                        🖥️ <b>{ip}</b> — {country} — {org}
                        {f"<br>⚠️ " + "<br>⚠️ ".join(ip_inds) if ip_inds else ""}
                    </div>
                    """, unsafe_allow_html=True)

        if results["has_attachments"]:
        if results["has_attachments"]:
            st.warning("📎 **Attachment detected** — Do NOT open files from unverified senders.")

        header = results.get("header_analysis", {})
        if header.get("findings"):
            st.markdown("<div class='section-title'>📨 Email Header Analysis</div>", unsafe_allow_html=True)
            for finding in header["findings"]:
                st.error(f"🚨 {finding}")

        attach = results.get("attachment_analysis", {})
        if attach.get("findings"):
            st.markdown("<div class='section-title'>📎 Attachment Analysis</div>", unsafe_allow_html=True)
            for finding in attach["findings"]:
                st.error(f"🚨 {finding}")

        lang = results.get("language_analysis", {})
        if lang.get("findings"):
            st.markdown("<div class='section-title'>🧠 Language & Manipulation Analysis</div>", unsafe_allow_html=True)
            for finding in lang["findings"]:
                st.warning(f"⚠️ {finding}")

        st.divider()
        st.markdown("<div class='section-title'>📋 Security Verdict</div>", unsafe_allow_html=True)

        if score >= 75:
            st.error("🔴 **CRITICAL THREAT** — Strong phishing indicators detected. Do not click any links, do not reply. Report to your IT security team immediately.")
        elif score >= 50:
            st.error("🟠 **HIGH RISK** — Multiple phishing indicators found. Treat with extreme caution.")
        elif score >= 25:
            st.warning("🟡 **MEDIUM RISK** — Suspicious elements detected. Verify before acting.")
        else:
            st.success("🟢 **LOW RISK** — No major phishing indicators found. Stay vigilant.")

        st.divider()
        st.markdown("<div class='section-title'>📄 Export & AI Analysis</div>", unsafe_allow_html=True)

        col_ai, col_pdf = st.columns(2)
        with col_ai:
            if st.button("🤖 Generate AI Security Report", use_container_width=True, type="secondary"):
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
            st.download_button(
                label="📥 Download PDF Report",
                data=pdf_bytes,
                file_name=f"phishguard_report_{results['severity'].lower()}.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary"
            )

        if "ai_report" in st.session_state:
            st.markdown("<div class='section-title'>🤖 AI Security Analysis</div>", unsafe_allow_html=True)
            st.markdown(st.session_state["ai_report"])

with tab2:
    st.markdown("#### 📊 Recent Analyses")
    history = get_history(20)

    if not history:
        st.info("No analyses yet. Go to the Analyze tab and scan your first email.")
    else:
        scores     = [row[1] for row in history]
        labels     = [f"#{i+1}" for i in range(len(history))]
        colors_bar = ["#ff4444" if s >= 75 else "#ff8800" if s >= 50 else "#ffaa00" if s >= 25 else "#44aa44" for s in scores]

        fig2 = go.Figure(go.Bar(
            x=labels, y=scores, marker_color=colors_bar,
            text=scores, textposition="outside"
        ))
        fig2.update_layout(
            title="Risk Scores - Last 20 Analyses",
            yaxis_range=[0, 110],
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            height=300,
            margin=dict(t=40, b=20, l=20, r=20)
        )
        fig2.update_xaxes(showgrid=False)
        fig2.update_yaxes(gridcolor="#1e3a5f")
        st.plotly_chart(fig2, use_container_width=True)
        st.divider()

        for i, row in enumerate(history):
            timestamp, score, severity, kw_hits, susp_urls, preview = row
            with st.expander(f"**{severity}** - Score {score}/100 - {timestamp[:16]}"):
                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Risk Score", score)
                col_b.metric("Keyword Hits", kw_hits)
                col_c.metric("Suspicious URLs", susp_urls)
                st.markdown(f"<div class='url-box' style='color:#94a3b8'>📧 {preview}...</div>", unsafe_allow_html=True)

if is_admin:
    with tab3:
        st.markdown("## ⚙️ Admin Dashboard")
        st.markdown("<p style='color:#94a3b8'>Only visible to admin account</p>", unsafe_allow_html=True)
        st.divider()

        stats = get_stats()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f"""
            <div class='stat-card'>
                <div style='font-size:2rem;font-weight:900;color:#60a5fa'>{stats["total_analyses"]}</div>
                <div style='color:#64748b;font-size:0.85rem'>Total Analyses</div>
            </div>""", unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class='stat-card'>
                <div style='font-size:2rem;font-weight:900;color:#22c55e'>{stats["today_analyses"]}</div>
                <div style='color:#64748b;font-size:0.85rem'>Today</div>
            </div>""", unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class='stat-card'>
                <div style='font-size:2rem;font-weight:900;color:#ff4444'>{stats["critical_count"]}</div>
                <div style='color:#64748b;font-size:0.85rem'>Critical Threats</div>
            </div>""", unsafe_allow_html=True)
        with col4:
            st.markdown(f"""
            <div class='stat-card'>
                <div style='font-size:2rem;font-weight:900;color:#ffaa00'>{stats["avg_risk_score"]}</div>
                <div style='color:#64748b;font-size:0.85rem'>Avg Risk Score</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            daily = get_daily_counts(14)
            dates  = [d["date"] for d in daily]
            counts = [d["count"] for d in daily]

            fig3 = go.Figure(go.Bar(
                x=dates, y=counts,
                marker_color="#2563eb",
                text=counts, textposition="outside"
            ))
            fig3.update_layout(
                title="Analyses per Day (Last 14 Days)",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0",
                height=300,
                margin=dict(t=40, b=20, l=20, r=20)
            )
            fig3.update_xaxes(showgrid=False, tickangle=45)
            fig3.update_yaxes(gridcolor="#1e3a5f")
            st.plotly_chart(fig3, use_container_width=True)

        with col_chart2:
            severity_data = stats["severity_counts"]
            if severity_data:
                sev_colors = {
                    "CRITICAL": "#ff4444",
                    "HIGH":     "#ff8800",
                    "MEDIUM":   "#ffaa00",
                    "LOW":      "#44aa44"
                }
                fig4 = go.Figure(go.Pie(
                    labels=list(severity_data.keys()),
                    values=list(severity_data.values()),
                    marker_colors=[sev_colors.get(k, "#60a5fa") for k in severity_data.keys()],
                    hole=0.4
                ))
                fig4.update_layout(
                    title="Severity Distribution",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="#e2e8f0",
                    height=300,
                    margin=dict(t=40, b=20, l=20, r=20)
                )
                st.plotly_chart(fig4, use_container_width=True)

        st.divider()
        st.markdown("### 🚨 Recent Critical & High Threats")
        threats = get_recent_threats(10)

        if not threats:
            st.info("No critical or high threats detected yet.")
        else:
            for row in threats:
                timestamp, score, severity, kw_hits, susp_urls, preview = row
                color = "#ff4444" if severity == "CRITICAL" else "#ff8800"
                with st.expander(f"**{severity}** — Score {score}/100 — {timestamp[:16]}"):
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Risk Score", score)
                    col_b.metric("Keyword Hits", kw_hits)
                    col_c.metric("Suspicious URLs", susp_urls)
                    st.markdown(f"<div class='url-box' style='color:#94a3b8'>📧 {preview}...</div>", unsafe_allow_html=True)

        st.divider()
        st.markdown("### 👥 Client Management")
        st.info("To add or remove clients, update the passwords section in Streamlit Cloud secrets.")
        st.code("""
[passwords]
admin    = "your_admin_password"
client1  = "client1_password"
client2  = "client2_password"
        """, language="toml")

        col_refresh, col_export = st.columns(2)
        with col_refresh:
            if st.button("🔄 Refresh Dashboard", use_container_width=True):
                st.rerun()
        with col_export:
            all_analyses = get_all_analyses(100)
            if all_analyses:
                import csv, io
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["ID", "Timestamp", "Risk Score", "Severity", "Keyword Hits", "Suspicious URLs", "Email Preview"])
                writer.writerows(all_analyses)
                st.download_button(
                    label="📥 Export All Data (CSV)",
                    data=output.getvalue(),
                    file_name="phishguard_all_analyses.csv",
                    mime="text/csv",
                    use_container_width=True
                )
