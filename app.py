import streamlit as st
import plotly.graph_objects as go
from src.detector import analyze_email
from src.database import init_db, save_analysis, get_history

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
</style>
""", unsafe_allow_html=True)

init_db()

st.markdown("<h1 style='color:#60a5fa; font-size:2rem; margin-bottom:0'>🛡️ PhishGuard AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='color:#94a3b8; margin-top:2px'>AI-Powered Phishing & Threat Detection Platform</p>", unsafe_allow_html=True)
st.divider()

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

            st.divider()
            st.markdown("## 📊 Analysis Results")

            score = results["risk_score"]
            severity = results["severity"]
            color = results["severity_color"]

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
                st.markdown("<div class='section-title'>🔗 URLs Found (no threats)</div>", unsafe_allow_html=True)
                for url in results["urls_found"]:
                    st.markdown(f"<div class='safe-url-box'>🔗 {url}</div>", unsafe_allow_html=True)

            if results["has_attachments"]:
                st.warning("📎 **Attachment detected** — Do NOT open files from unverified senders.")

            st.divider()
            st.markdown("<div class='section-title'>📋 Security Verdict</div>", unsafe_allow_html=True)

            if score >= 75:
                st.error("🔴 **CRITICAL THREAT** — Strong phishing indicators detected. Do not click any links, do not reply. Report to your IT security team immediately.")
            elif score >= 50:
                st.error("🟠 **HIGH RISK** — Multiple phishing indicators found. Treat this email with extreme caution.")
            elif score >= 25:
                st.warning("🟡 **MEDIUM RISK** — Suspicious elements detected. Verify the sender before taking any action.")
            else:
                st.success("🟢 **LOW RISK** — No major phishing indicators found. Stay vigilant.")

            st.divider()
            if st.button("🤖 Generate AI Security Report", type="secondary"):
                try:
                    from src.ai_analyzer import ai_analyze_email
                    with st.spinner("AI is writing your security report..."):
                        ai_report = ai_analyze_email(email_text, results)
                    st.markdown("<div class='section-title'>🤖 AI Security Analysis</div>", unsafe_allow_html=True)
                    st.markdown(ai_report)
                    save_analysis(results, email_text, ai_report)
                except Exception as e:
                    st.error(f"AI analysis failed: {e}")

with tab2:
    st.markdown("#### 📊 Recent Analyses")
    history = get_history(20)

    if not history:
        st.info("No analyses yet. Go to the Analyze tab and scan your first email.")
    else:
        scores = [row[1] for row in history]
        labels = [f"#{i+1}" for i in range(len(history))]
        colors_bar = ["#ff4444" if s >= 75 else "#ff8800" if s >= 50 else "#ffaa00" if s >= 25 else "#44aa44" for s in scores]

        fig2 = go.Figure(go.Bar(
            x=labels, y=scores, marker_color=colors_bar,
            text=scores, textposition="outside"
        ))
        fig2.update_layout(
            title="Risk Scores — Last 20 Analyses",
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
            with st.expander(f"**{severity}** — Score {score}/100 — {timestamp[:16]}"):
                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Risk Score", score)
                col_b.metric("Keyword Hits", kw_hits)
                col_c.metric("Suspicious URLs", susp_urls)
                st.markdown(f"<div class='url-box' style='color:#94a3b8'>📧 {preview}...</div>", unsafe_allow_html=True)
