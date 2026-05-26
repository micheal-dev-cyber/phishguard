# app.py
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px  # Added to prevent missing name map errors
import pandas as pd
import csv
import io

# Import project modules safely
from src.database import init_db, save_analysis, get_history
from src.detector import analyze_email as static_analyze_email
from src.ai_analyzer import analyze_email, analyze_url, copilot_chat, simulate_phishing, analyze_screenshot, generate_ai_report
from src.report_generator import generate_pdf_report
from src.auth import check_password, logout
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.osint import run_osint
from src.admin import get_stats, get_all_analyses, get_recent_threats, get_daily_counts
from src.header_parser import parse_email_headers

# --- Design Injection (Obsidian Sentinel) ---
def apply_design():
    st.markdown(f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700&family=JetBrains+Mono:wght@400;700&display=swap');
        
        .stApp {{ background-color: #131313; font-family: 'Inter', sans-serif; color: #e5e2e1; }}
        
        /* Obsidian Sentinel Palette */
        .glass-card {{
            background: #1c1b1b;
            border: 1px solid #2a2a2a;
            border-radius: 1rem;
            padding: 1.5rem;
            backdrop-filter: blur(20px);
            margin-bottom: 1rem;
        }}
        
        .threat-card {{
            border-left: 4px solid #FF4444;
        }}
        
        /* Buttons */
        .stButton > button {{
            background: transparent;
            border: 1px solid #39FF14;
            color: #39FF14;
            border-radius: 0.5rem;
            font-family: 'JetBrains Mono', monospace;
            transition: all 0.3s ease;
        }}
        .stButton > button:hover {{
            box-shadow: 0 0 15px rgba(57, 255, 20, 0.3);
            background: rgba(57, 255, 20, 0.05);
        }}
        
        /* Typography */
        h1, h2, h3 {{ font-family: 'Inter', sans-serif; color: #efffe3 !important; }}
        code {{ font-family: 'JetBrains Mono', monospace; background: #0e0e0e; color: #39FF14; }}
    </style>
    """, unsafe_allow_html=True)

# Helper for the UI
def glass_card(title=None, is_threat=False):
    css_class = "glass-card" + (" threat-card" if is_threat else "")
    container = st.container()
    container.markdown(f'<div class="{css_class}">', unsafe_allow_html=True)
    if title:
        container.markdown(f"### {title}")
    return container

# Call this immediately after set_page_config
apply_design()

# Initialize Database
init_db()

# --- Page Configuration ---
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS ---
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
        border-radius: 6px;
        padding: 10px;
        margin: 5px 0;
    }
    .ai-container {
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 20px;
        margin-top: 15px;
    }
    .stat-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# --- Authentication Gate ---
if not check_password():
    st.stop()

# --- Sidebar ---
with st.sidebar:
    st.markdown(f"### 👤 {st.session_state.get('username', 'User')}")
    st.markdown(f"**Role:** {st.session_state.get('role', 'Client').capitalize()}")
    if st.button("🚪 Logout", use_container_width=True):
        logout()
    
    st.divider()
    st.markdown("### 🛡️ System Status")
    st.success("API: Online")
    st.success("Database: Connected")
    st.success("AI Engine: Active")

# --- Main App Title ---
st.title("🛡️ PhishGuard AI")
st.markdown("Commercial Threat Intelligence & Header Analysis Platform")

# --- Define the 7 Main Tabs ---
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "🔍 Analyze", 
    "📨 Header Parser", 
    "🤖 AI Copilot", 
    "🎯 Phishing Simulator",
    "🖼️ Screenshot Scanner",
    "📊 History", 
    "⚙️ Admin"
])

# ==========================================
# TAB 1: ANALYZE EMAIL
# ==========================================
with tab1:
    st.markdown("### 🔍 Scan Suspicious Content")
    email_text = st.text_area("Paste the email content or suspicious URLs here:", height=200)
    
    if st.button("🚀 Run AI Analysis", type="primary", use_container_width=True):
        if not email_text.strip():
            st.warning("Please paste some text to analyze.")
        else:
            with st.spinner("Analyzing threat vectors..."):
                result = static_analyze_email(email_text)
                findings = result.get("findings", [])
                urls = result.get("urls", [])

            with st.spinner("🤖 Consulting Threat Engine..."):
                ai_report_markdown = generate_ai_report(email_text, rule_findings=findings)
                
            save_analysis(
                risk_score=result.get("risk_score", 0),
                severity=result.get("severity", "Low"),
                keyword_hits=len(findings),
                suspicious_urls=len(urls),
                email_preview=email_text[:100] + "...",
                ai_report=ai_report_markdown
            )
            
            st.success("Complete System Analysis Generated!")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Risk Score", f"{result.get('risk_score', 0)}/100")
            col2.metric("Severity", result.get('severity', 'Low'))
            col3.metric("Flags Detected", len(findings))
            
            layout_left, layout_right = st.columns([1, 2])
            with layout_left:
                if urls:
                    st.markdown("#### 🔗 Extracted Links")
                    for url in urls:
                        st.markdown(f"<div class='url-box'>{url}</div>", unsafe_allow_html=True)
                if findings:
                    st.markdown("#### ⚠️ Heuristic Detections")
                    for finding in findings:
                        st.markdown(f"- {finding}")
                        
            with layout_right:
                st.markdown("#### 🤖 Deep Learning SecOps Report")
                st.markdown(f"<div class='ai-container'>{ai_report_markdown}</div>", unsafe_allow_html=True)

    st.divider()
    
    # --- Deep URL Scan Section (Properly Nested in Tab 1) ---
    st.markdown("### 🔗 Deep URL Intelligence")
    url_input = st.text_input("Enter URL to scan:", placeholder="https://example.com", key="unique_url_input_tab1")

    if st.button("🚀 Deep URL Scan", key="unique_scan_btn_tab1"):
        if not url_input:
            st.warning("Please enter a URL first.")
        else:
            with st.spinner("Analyzing reputation and redirects..."):
                from src.url_intel import analyze_url_safety
                from src.threat_intel import get_url_reputation
                
                # 1. Get Redirect Analysis
                analysis = analyze_url_safety(url_input)
                
                # 2. Get Threat Intelligence
                reputation = get_url_reputation(url_input)
                
                # 3. Display Results
                st.subheader("Deep Scan Results")
                
                # Visual reputation meter
                if reputation and "error" not in reputation:
                    malicious = reputation.get('malicious', 0)
                    st.metric("Malicious Flags", f"{malicious} / 70 vendors", 
                              delta_color="inverse" if malicious > 0 else "normal")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Final Domain:** {analysis.get('domain')}")
                    st.write(f"**Redirects:** {analysis.get('chain_length')}")
                with col2:
                    st.write(f"**Shortened:** {'Yes' if analysis.get('is_shortened') else 'No'}")
                
                st.markdown("### 🔗 Full Redirect Chain")
                for i, hop in enumerate(analysis.get('chain', [])):
                    st.text(f"{i+1}: {hop}")


# ==========================================
# TAB 2: EMAIL HEADER ANALYZER
# ==========================================
with tab2:
    st.markdown("### 📨 Email Header Analyzer")
    st.markdown("Paste the full raw headers from any suspicious email to perform deep authentication analysis.")
    
    st.info("""
    **How to get raw headers:**
    • **Gmail:** Open email → 3 dots menu → Show original → Copy all
    • **Outlook:** File → Properties → Internet headers → Copy all
    """)
    
    raw_headers = st.text_area("Paste raw email headers here:", height=250, key="headers_area")
    
    if st.button("Analyze Headers", type="primary", use_container_width=True):
        if not raw_headers.strip():
            st.warning("Please paste email headers first.")
        else:
            with st.spinner("Parsing routing hops and verifying signatures..."):
                headers_result = parse_email_headers(raw_headers)
                
                st.markdown("### 🛡️ Authentication Summary")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Risk Score", f"{headers_result['risk_score']}/100")
                
                auth_cols = [c2, c3, c4]
                for idx, auth in enumerate(headers_result["auth_summary"]):
                    if idx < len(auth_cols):
                        auth_cols[idx].metric(auth["protocol"], f"{auth['icon']} {auth['result']}")
                
                if headers_result["findings"]:
                    st.markdown("### ⚠️ Security Findings")
                    for f in headers_result["findings"]:
                        st.markdown(f"- {f}")
                
                with st.expander("🌐 View Network Routing Hops", expanded=False):
                    if not headers_result["received_hops"]:
                        st.info("No clear routing hops detected.")
                    else:
                        for idx, hop in enumerate(headers_result["received_hops"]):
                            st.markdown(f"**Hop {idx + 1}:** `{hop['ip']}`")
                            st.code(hop['raw'], language="text")

# ── TAB 3: AI COPILOT ──────────────────────────────────────────
with tab3:
    st.markdown("## 🤖 PhishGuard AI Copilot")
    st.markdown("<p style='color:#94a3b8'>Ask anything about phishing, email headers, typosquatting, or threat remediation.</p>", unsafe_allow_html=True)

    if "copilot_messages" not in st.session_state:
        st.session_state.copilot_messages = []

    for msg in st.session_state.copilot_messages:
        with st.chat_message(msg["role"]):
            st.markdown(f"{msg['content']}")

    user_input = st.chat_input("Ask PhishGuard Copilot...")
    if user_input:
        st.session_state.copilot_messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                reply = copilot_chat(st.session_state.copilot_messages)
            st.markdown(reply)
        st.session_state.copilot_messages.append({"role": "assistant", "content": reply})

# ── TAB 4: PHISHING SIMULATOR ──────────────────────────────────
with tab4:
    st.markdown("## 🎯 Phishing Simulator — Training Mode")
    st.markdown("<p style='color:#94a3b8'>Generate realistic phishing emails for employee awareness training.</p>", unsafe_allow_html=True)

    st.markdown("""
    <div style='background:#0f172a;border:1px solid #f59e0b;border-radius:8px;padding:12px;margin-bottom:16px;font-size:13px;color:#94a3b8'>
    ⚠️ <b style='color:#f59e0b'>For training purposes only.</b> These are simulated phishing emails to help users recognize threats.
    </div>
    """, unsafe_allow_html=True)

    scenario = st.selectbox("Choose a phishing scenario:", [
        "bank-scam", "crypto-scam", "fake-hr", "fake-delivery"
    ], format_func=lambda x: {
        "bank-scam": "🏦 Bank / Credit Card Scam",
        "crypto-scam": "₿ Crypto / Web3 Wallet Scam",
        "fake-hr": "👔 Fake HR / Salary Email",
        "fake-delivery": "📦 Fake Delivery / DHL Scam"
    }[x])

    if st.button("🎯 Generate Phishing Simulation", type="primary", use_container_width=True):
        with st.spinner("Generating realistic phishing email..."):
            sim = simulate_phishing(scenario)

        st.markdown("### 📧 Simulated Phishing Email")
        st.markdown(f"""
        <div style='background:#1e0a0a;border:1px solid #dc2626;border-radius:10px;padding:20px;font-family:monospace;font-size:13px'>
            <div style='margin-bottom:8px'><b style='color:#94a3b8'>From:</b> <span style='color:#fca5a5'>{sim.get('sender','')}</span></div>
            <div style='margin-bottom:8px'><b style='color:#94a3b8'>Subject:</b> <span style='color:#fbbf24'>{sim.get('subject','')}</span></div>
            <hr style='border-color:#374151;margin:12px 0'>
            <pre style='white-space:pre-wrap;color:#e2e8f0;font-size:13px'>{sim.get('body','')}</pre>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("### 🔍 Red Flags — Can You Spot Them?")
        clues = sim.get("clues", [])
        for i, clue in enumerate(clues):
            with st.expander(f"🚩 Clue {i+1} — Click to reveal"):
                st.markdown(f"**{clue}**")

        st.divider()
        st.markdown("### ✅ Remediation")
        st.success(sim.get("remediation", ""))

# ── TAB 5: SCREENSHOT SCANNER ──────────────────────────────────
with tab5:
    st.markdown("## 🖼️ Screenshot Phishing Scanner")
    st.markdown("<p style='color:#94a3b8'>Upload a screenshot of a suspicious login page or alert.</p>", unsafe_allow_html=True)

    uploaded_img = st.file_uploader("Upload screenshot (PNG, JPG, WEBP)", type=["png", "jpg", "jpeg", "webp"], key="screenshot_uploader")

    if uploaded_img:
        import base64
        st.image(uploaded_img, caption="Uploaded screenshot", use_container_width=True)
        mime_type = uploaded_img.type or "image/png"
        img_bytes = uploaded_img.read()
        img_b64 = base64.b64encode(img_bytes).decode("utf-8")

        if st.button("🔍 Scan Screenshot for Phishing", type="primary", use_container_width=True):
            with st.spinner("Running AI vision analysis..."):
                result = analyze_screenshot(img_b64, mime_type)

            vscore = result.get("score", 0)
            if vscore >= 75: st.error(f"🔴 **Visual Risk Score: {vscore}/100 — CRITICAL THREAT**")
            elif vscore >= 50: st.error(f"🟠 **Visual Risk Score: {vscore}/100 — HIGH RISK**")
            elif vscore >= 25: st.warning(f"🟡 **Visual Risk Score: {vscore}/100 — SUSPICIOUS**")
            else: st.success(f"🟢 **Visual Risk Score: {vscore}/100 — CLEAN**")

            st.divider()
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Severity:** `{result.get('severity','N/A')}`")
                st.markdown(f"**Brand Target:** `{result.get('brandTarget','N/A')}`")
            with col2:
                st.markdown(f"**Phishing:** `{'YES ⚠️' if result.get('isPhishing') else 'NO ✅'}`")

            if result.get("detectedTextOcr"):
                st.divider()
                st.markdown("### 📄 OCR — Detected Text")
                st.code(result["detectedTextOcr"], language=None)

            if result.get("visualAnomalies"):
                st.divider()
                st.markdown("### 🚨 Visual Anomalies Detected")
                for anomaly in result["visualAnomalies"]:
                    st.markdown(f"- {anomaly}")

            if result.get("detailedVerdict"):
                st.divider()
                st.markdown("### 🧠 AI Verdict")
                st.info(result["detailedVerdict"])

# ==========================================
# TAB 6: HISTORY
# ==========================================
with tab6:
    st.markdown("### 📊 Recent Analyses")
    recent = get_recent_threats(10)
    
    if not recent:
        st.info("No analyses yet. Go to the Analyze tab and scan your first email.")
    else:
        for row in recent:
            if len(row) >= 3:
                timestamp, severity, preview = row[0], row[1], row[2]
            else:
                timestamp, severity, preview = "Unknown time", "Unknown", "No content preview"
            color = "red" if severity in ["High", "Critical", "CRITICAL", "HIGH"] else "orange" if severity in ["Medium", "MEDIUM"] else "green"
            st.markdown(
                f"<div style='border-left: 4px solid {color}; padding-left: 10px; margin-bottom: 10px;'>"
                f"<small>{timestamp} | <b>{severity}</b></small><br/>"
                f"<span style='color:#94a3b8'>📧 {preview}...</span></div>", 
                unsafe_allow_html=True
            )

# ==========================================
# TAB 7: ADMIN DASHBOARD
# ==========================================
with tab7:
    st.markdown("## ⚙️ Advanced SOC Dashboard")
    st.markdown("<p style='color:#94a3b8'>Global Threat Telemetry & Client Management</p>", unsafe_allow_html=True)
    st.divider()
    
    stats = get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"<div class='stat-card'><div style='font-size:2rem;font-weight:900;color:#60a5fa'>{stats.get('total_analyses', 0)}</div><div style='color:#64748b;font-size:0.85rem'>Total Analyses</div></div>", unsafe_allow_html=True)
    with col2:
        st.markdown(f"<div class='stat-card'><div style='font-size:2rem;font-weight:900;color:#22c55e'>{stats.get('today_analyses', 0)}</div><div style='color:#64748b;font-size:0.85rem'>Scans Today</div></div>", unsafe_allow_html=True)
    with col3:
        st.markdown(f"<div class='stat-card'><div style='font-size:2rem;font-weight:900;color:#ff4444'>{stats.get('critical_count', 0)}</div><div style='color:#64748b;font-size:0.85rem'>Critical Threats</div></div>", unsafe_allow_html=True)
    with col4:
        st.markdown(f"<div class='stat-card'><div style='font-size:2rem;font-weight:900;color:#ffaa00'>{stats.get('avg_risk_score', 0)}</div><div style='color:#64748b;font-size:0.85rem'>Avg Risk Score</div></div>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    col_map, col_radar = st.columns([2, 1])
    with col_map:
        st.markdown("### 🌍 Live Global Threat Map")
        from src.admin import get_threat_map_data, get_attack_vectors
        map_data = get_threat_map_data()
        df_map = pd.DataFrame(map_data)
        
        if not df_map.empty:
            fig_map = px.scatter_geo(
                df_map, lat="lat", lon="lon", size="threats", color="threats",
                hover_name="city", hover_data=["country"],
                color_continuous_scale="Reds", size_max=25, projection="natural earth"
            )
        # REMOVED bordercolor from here as it caused the ValueError
        fig_map.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            geo=dict(bgcolor='rgba(0,0,0,0)', lakecolor='#0f172a', landcolor='#1e293b', showcountries=True),
            margin=dict(l=0, r=0, t=0, b=0), height=350
        )
        st.plotly_chart(fig_map, use_container_width=True)

    with col_radar:
        st.markdown("### 🎯 Attack Vectors")
        vectors = get_attack_vectors()
        fig_radar = go.Figure(data=go.Scatterpolar(
            r=list(vectors.values()), theta=list(vectors.keys()), fill='toself',
            line_color='#ef4444', fillcolor='rgba(239, 68, 68, 0.2)'
        ))
        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=False, range=[0, 100]), bgcolor='rgba(0,0,0,0)'),
            paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
            margin=dict(l=20, r=20, t=20, b=20), height=350
        )
        st.plotly_chart(fig_radar, use_container_width=True)
        
    st.divider()
    
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        daily = get_daily_counts()
        
        # Fix: Convert DataFrame to list of dicts if needed
        if isinstance(daily, pd.DataFrame):
            daily_data = daily.to_dict('records')
        else:
            daily_data = daily or [] # Fallback to empty list if None
            
        fig3 = go.Figure(go.Bar(
            x=[d.get("date", "") for d in daily_data], 
            y=[d.get("count", 0) for d in daily_data],
            marker_color="#2563eb", 
            text=[d.get("count", 0) for d in daily_data], 
            textposition="outside"
        ))
        fig3.update_layout(
            title="Analyses per Day (Last 14 Days)", 
            paper_bgcolor="rgba(0,0,0,0)", 
            plot_bgcolor="rgba(0,0,0,0)", 
            font_color="#e2e8f0", 
            height=300
        )
        st.plotly_chart(fig3, use_container_width=True)
        
    with col_chart2:
        severity_data = stats.get("severity_counts", {})
        if severity_data:
            sev_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffaa00", "LOW": "#44aa44"}
            fig4 = go.Figure(go.Pie(
                labels=list(severity_data.keys()), values=list(severity_data.values()),
                marker_colors=[sev_colors.get(k, "#60a5fa") for k in severity_data.keys()], hole=0.4
            ))
            fig4.update_layout(title="Severity Distribution", paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0", height=300)
            st.plotly_chart(fig4, use_container_width=True)
            
    st.divider()
    
    col_feed, col_clients = st.columns(2)
    with col_feed:
        st.markdown("### 🚨 Live Incident Feed")
        threats = get_recent_threats(5)
        if not threats:
            st.info("No critical threats detected recently.")
        else:
            for row in threats:
                if len(row) == 6:
                    timestamp, score, severity, kw_hits, susp_urls, preview = row
                    st.error(f"**{severity}** ({score}/100) — {timestamp[:16]}\n\n*URLs: {susp_urls} | Flags: {kw_hits}*\n\n`{preview[:60]}...`")
                
    with col_clients:
        st.markdown("### 👥 Client Management")
        st.info("Update `st.secrets` on Streamlit Cloud to manage access:")
        st.code("[passwords]\nadmin = \"your_admin_password\"\nclient1 = \"client1_password\"", language="toml")
        
        all_analyses = get_all_analyses(100)
        if all_analyses:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Timestamp", "Risk Score", "Severity", "Keywords", "URLs", "Preview"])
            writer.writerows(all_analyses)
            st.download_button("📥 Export All Telemetry (CSV)", data=output.getvalue(), file_name="phishguard_telemetry.csv", mime="text/csv", use_container_width=True)
            
        if st.button("🔄 Refresh Dashboard", use_container_width=True):
            st.rerun()