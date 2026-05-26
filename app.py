# app.py
import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import csv
import io

# Import project modules
from src.database import init_db, save_analysis, get_history
from src.detector import analyze_email
from src.ai_analyzer import generate_ai_report
from src.report_generator import generate_pdf_report
from src.auth import check_password, logout
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.osint import run_osint
from src.admin import get_stats, get_all_analyses, get_recent_threats, get_daily_counts
from src.header_parser import parse_email_headers

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

# --- Define the 4 Main Tabs ---
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "🔍 Analyze", 
    "📨 Header Parser", 
    "🤖 AI Copilot", 
    "🎯 Phishing Simulator",
    "🖼️ Screenshot Scanner",
    "📊 History", 
    "⚙️ Admin"
])

# ── TAB 3: AI COPILOT ──────────────────────────────────────────
with tab3:
    st.markdown("## 🤖 PhishGuard AI Copilot")
    st.markdown("<p style='color:#94a3b8'>Ask anything about phishing, email headers, typosquatting, or threat remediation.</p>", unsafe_allow_html=True)

    if "copilot_messages" not in st.session_state:
        st.session_state.copilot_messages = []

    for msg in st.session_state.copilot_messages:
        role_icon = "🧑" if msg["role"] == "user" else "🤖"
        with st.chat_message(msg["role"]):
            st.markdown(f"{msg['content']}")

    user_input = st.chat_input("Ask PhishGuard Copilot...")
    if user_input:
        st.session_state.copilot_messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                from src.ai_analyzer import copilot_chat
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
        "bank-scam",
        "crypto-scam", 
        "fake-hr",
        "fake-delivery"
    ], format_func=lambda x: {
        "bank-scam": "🏦 Bank / Credit Card Scam",
        "crypto-scam": "₿ Crypto / Web3 Wallet Scam",
        "fake-hr": "👔 Fake HR / Salary Email",
        "fake-delivery": "📦 Fake Delivery / DHL Scam"
    }[x])

    if st.button("🎯 Generate Phishing Simulation", type="primary", use_container_width=True):
        with st.spinner("Generating realistic phishing email..."):
            from src.ai_analyzer import simulate_phishing
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
    st.markdown("<p style='color:#94a3b8'>Upload a screenshot of a suspicious login page, email, or alert. AI will analyze it for phishing indicators.</p>", unsafe_allow_html=True)

    uploaded_img = st.file_uploader(
        "Upload screenshot (PNG, JPG, WEBP)",
        type=["png", "jpg", "jpeg", "webp"],
        key="screenshot_uploader"
    )

    if uploaded_img:
        import base64
        st.image(uploaded_img, caption="Uploaded screenshot", use_container_width=True)
        mime_type = uploaded_img.type or "image/png"
        img_bytes = uploaded_img.read()
        img_b64 = base64.b64encode(img_bytes).decode("utf-8")

        if st.button("🔍 Scan Screenshot for Phishing", type="primary", use_container_width=True):
            with st.spinner("Running AI vision analysis..."):
                from src.ai_analyzer import analyze_screenshot
                result = analyze_screenshot(img_b64, mime_type)

            vscore = result.get("score", 0)
            if vscore >= 75:
                st.error(f"🔴 **Visual Risk Score: {vscore}/100 — CRITICAL THREAT**")
            elif vscore >= 50:
                st.error(f"🟠 **Visual Risk Score: {vscore}/100 — HIGH RISK**")
            elif vscore >= 25:
                st.warning(f"🟡 **Visual Risk Score: {vscore}/100 — SUSPICIOUS**")
            else:
                st.success(f"🟢 **Visual Risk Score: {vscore}/100 — CLEAN**")

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

            if result.get("remediation"):
                st.divider()
                st.markdown("### ✅ Remediation")
                st.success(result["remediation"])

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
            # Step A: Run structural static analysis
            with st.spinner("Analyzing threat vectors..."):
                result = analyze_email(email_text)
                findings = result.get("findings", [])
                urls = result.get("urls", [])

            # Step B: Trigger the Mistral LLM Brain 🧠
            with st.spinner("🤖 Consulting Mistral Threat Engine..."):
                ai_report_markdown = generate_ai_report(email_text, rule_findings=findings)
                
            # Step C: Save to database
            # Step C: Save to database
            save_analysis(
                risk_score=result.get("risk_score", 0),
                severity=result.get("severity", "Low"),
                keyword_hits=len(findings),
                suspicious_urls=len(urls),
                email_preview=email_text[:100] + "...",
                ai_report=ai_report_markdown  # <--- WE MISSED THIS LINE!
            )
            
            st.success("Complete System Analysis Generated!")
            
            # Metrics UI Layout
            col1, col2, col3 = st.columns(3)
            col1.metric("Risk Score", f"{result.get('risk_score', 0)}/100")
            col2.metric("Severity", result.get('severity', 'Low'))
            col3.metric("Flags Detected", len(findings))
            
            # Left/Right Layout for Findings vs AI Report
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


# ==========================================
# TAB 4: EMAIL HEADER ANALYZER
# ==========================================
with tab4:
    st.markdown("### 📨 Email Header Analyzer")
    st.markdown("Paste the full raw headers from any suspicious email to perform deep authentication analysis.")
    
    st.info("""
    **How to get raw headers:**
    • **Gmail:** Open email → 3 dots menu → Show original → Copy all
    • **Outlook:** File → Properties → Internet headers → Copy all
    • **Apple Mail:** View → Message → All Headers → Copy
    """)
    
    raw_headers = st.text_area("Paste raw email headers here:", height=250)
    
    if st.button("Analyze Headers", type="primary", use_container_width=True):
        if not raw_headers.strip():
            st.warning("Please paste email headers first.")
        else:
            with st.spinner("Parsing routing hops and verifying signatures..."):
                headers_result = parse_email_headers(raw_headers)
                
                # Summary Metrics
                st.markdown("### 🛡️ Authentication Summary")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Risk Score", f"{headers_result['risk_score']}/100")
                
                auth_cols = [c2, c3, c4]
                for idx, auth in enumerate(headers_result["auth_summary"]):
                    auth_cols[idx].metric(
                        auth["protocol"], 
                        f"{auth['icon']} {auth['result']}"
                    )
                
                # Key Findings
                if headers_result["findings"]:
                    st.markdown("### ⚠️ Security Findings")
                    for f in headers_result["findings"]:
                        st.markdown(f"- {f}")
                
                # Routing Hops
                with st.expander("🌐 View Network Routing Hops", expanded=False):
                    if not headers_result["received_hops"]:
                        st.info("No clear routing hops detected.")
                    else:
                        for idx, hop in enumerate(headers_result["received_hops"]):
                            st.markdown(f"**Hop {idx + 1}:** `{hop['ip']}`")
                            st.code(hop['raw'], language="text")

# ==========================================
# TAB 2: HISTORY
# ==========================================
with tab2:
    st.markdown("### 📊 Recent Analyses")
    recent = get_recent_threats(10)
    
    if not recent:
        st.info("No analyses yet. Go to the Analyze tab and scan your first email.")
    else:
        for row in recent:
            timestamp, severity, preview = row
            color = "red" if severity in ["High", "Critical"] else "orange" if severity == "Medium" else "green"
            st.markdown(
                f"<div style='border-left: 4px solid {color}; padding-left: 10px; margin-bottom: 10px;'>"
                f"<small>{timestamp} | <b>{severity}</b></small><br/>"
                f"<span style='color:#94a3b8'>📧 {preview}...</span></div>", 
                unsafe_allow_html=True
            )

# ==========================================
# TAB 3: ADMIN DASHBOARD
# ==========================================
with tab3:
    if st.session_state.get("role") != "admin":
        st.error("🚫 Access Denied: Administrator privileges required to view telemetry.")
    else:
        st.markdown("### ⚙️ System Metrics")
        
        stats = get_stats()
        colA, colB = st.columns(2)
        colA.metric("Total Scans Processed", stats.get("total_scans", 0))
        colB.metric("Critical Threats Blocked", stats.get("threats_blocked", 0))
        
        st.divider()
        st.markdown("### 👥 Client Data Management")
        
        col_refresh, col_export = st.columns(2)
        with col_refresh:
            if st.button("🔄 Refresh Dashboard", use_container_width=True):
                st.rerun()
                
        with col_export:
            all_analyses = get_all_analyses(100)
            if all_analyses:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["ID", "Timestamp", "Risk Score", "Severity", "Keyword Hits", "Suspicious URLs", "Email Preview"])
                writer.writerows(all_analyses)
                st.download_button(
                    label="📥 Export All Data (CSV)",
                    data=output.getvalue(),
                    file_name="phishguard_export.csv",
                    mime="text/csv",
                    use_container_width=True
                )
