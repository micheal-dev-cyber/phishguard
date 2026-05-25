# src/ai_analyzer.py
from config import GOOGLE_API_KEY
import google.generativeai as genai

import sys
import os
from pathlib import Path

# Explicitly add the project root to the system path
sys.path.append(str(Path(__file__).parent))

# Now you can safely import from your src folder
from src.ai_analyzer import generate_ai_report

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import csv
import io

# 1. Initialize Database (Must happen before other imports use it)
from src.database import init_db, save_analysis, get_history
init_db() 

# 2. Import modules
from src.detector import analyze_email
from src.report_generator import generate_pdf_report
from src.auth import check_password, logout
from src.threat_intel import check_multiple_urls, get_threat_summary
from src.osint import run_osint
from src.admin import get_stats, get_all_analyses, get_recent_threats, get_daily_counts
from src.header_parser import parse_email_headers
from src.ai_analyzer import generate_ai_report  # <-- Dynamic AI Import

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
tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Analyze Email", 
    "📊 History", 
    "⚙️ Admin Dashboard", 
    "📨 Email Header Analyzer"
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