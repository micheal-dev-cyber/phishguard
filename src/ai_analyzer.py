# src/ai_analyzer.py
import streamlit as st
import google.generativeai as genai

def generate_ai_report(email_text, rule_findings=None):
    """Generates an incident response report using Google Gemini."""
    
    # Securely fetch key from Streamlit Secrets
    api_key = st.secrets.get("GOOGLE_API_KEY")
    
    if not api_key:
        return "❌ AI Error: GOOGLE_API_KEY is not configured in Streamlit Secrets."
    
    genai.configure(api_key=api_key)
    
    # Using the current stable model
    model = genai.GenerativeModel('gemini-2.0-flash')
    
    context_injection = f"Our local static analyzer already flagged these vulnerabilities: {', '.join(rule_findings)}.\n" if rule_findings else ""
    
    prompt = f"""
    You are an expert SecOps Incident Responder. Analyze this email:
    {context_injection}
    ---
    {email_text}
    ---
    Generate an analytical investigation profile structured exactly with:
    ### 🔍 EXECUTIVE RISK BREAKDOWN
    ### ⚠️ PSYCHOLOGICAL & TECHNICAL TACTICS
    ### 🛡️ SECURE MITIGATION ACTIONS
    """

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"❌ Gemini API Error: {str(e)}"