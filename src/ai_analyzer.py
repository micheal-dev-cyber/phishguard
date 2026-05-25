import google.generativeai as genai
import os
from config import GOOGLE_API_KEY # Ensure you add this key to your .env/secrets

def generate_ai_report(email_text, rule_findings=None):
    """Generates an incident response report using Google Gemini."""
    
    # Configure the client
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    
    # Use Gemini Flash (fast and perfect for this)
    model = genai.GenerativeModel('gemini-1.5-flash')
    
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