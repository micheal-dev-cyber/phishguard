import streamlit as st
import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"

DEFAULT_TEMPLATES = {
    "alert_high": {
        "subject": "🔴 PhishGuard Alert: CRITICAL Threat Detected",
        "body_html": """<h2 style="color:#ef4444">⚠️ Phishing Threat Detected</h2>
<p>A {severity} threat was detected in a scanned email.</p>
<table border="1" cellpadding="8" style="border-collapse:collapse;width:100%">
<tr><td><strong>Risk Score</strong></td><td>{risk_score}/100</td></tr>
<tr><td><strong>Keyword Hits</strong></td><td>{keyword_hits}</td></tr>
<tr><td><strong>Suspicious URLs</strong></td><td>{suspicious_urls}</td></tr>
</table>
<p><a href="{app_url}" style="background:#2563eb;color:#fff;padding:10px 20px;text-decoration:none;border-radius:6px">View in PhishGuard</a></p>""",
    },
    "weekly_digest": {
        "subject": "📊 PhishGuard Weekly Summary",
        "body_html": """<h2 style="color:#60a5fa">Weekly Security Summary</h2>
<p>Period: {start_date} — {end_date}</p>
<table border="1" cellpadding="8" style="border-collapse:collapse;width:100%">
<tr><td><strong>Total Scans</strong></td><td>{total_scans}</td></tr>
<tr><td><strong>Threats Found</strong></td><td>{threats}</td></tr>
<tr><td><strong>Avg Risk Score</strong></td><td>{avg_score}/100</td></tr>
</table>""",
    },
    "auto_responder": {
        "subject": "⚠️ PhishGuard: Phishing Warning",
        "body_html": """<h2 style="color:#f97316">Phishing Warning</h2>
<p>PhishGuard detected that an email from your address may contain phishing content.</p>
<p>If you did not send this email, please disregard this message.</p>
<p>If your account was compromised, please change your password immediately.</p>""",
    },
}


def init_email_templates():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_key TEXT UNIQUE,
            subject TEXT,
            body_html TEXT,
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    for key, tmpl in DEFAULT_TEMPLATES.items():
        c.execute(
            "INSERT OR IGNORE INTO email_templates (template_key, subject, body_html) VALUES (?, ?, ?)",
            (key, tmpl["subject"], tmpl["body_html"]),
        )
    conn.commit()
    conn.close()


def get_template(key: str) -> dict:
    init_email_templates()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "SELECT subject, body_html FROM email_templates WHERE template_key=?",
        (key,),
    )
    row = c.fetchone()
    conn.close()
    if row:
        return {"subject": row[0], "body_html": row[1]}
    return DEFAULT_TEMPLATES.get(key, {"subject": "", "body_html": ""})


def update_template(key: str, subject: str, body_html: str):
    init_email_templates()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO email_templates (template_key, subject, body_html, updated_at) VALUES (?, ?, ?, datetime('now'))",
        (key, subject, body_html),
    )
    conn.commit()
    conn.close()


def render_email_templates_ui():
    init_email_templates()
    st.markdown("#### 📧 Email Template Customization")
    st.caption("Customize alert, digest, and auto-responder email templates.")

    template_keys = list(DEFAULT_TEMPLATES.keys())
    labels = {
        "alert_high": "🔴 Critical Alert",
        "weekly_digest": "📊 Weekly Digest",
        "auto_responder": "⚠️ Auto-Responder",
    }

    selected = st.selectbox("Template", template_keys,
                            format_func=lambda k: labels.get(k, k),
                            key="et_select")

    tmpl = get_template(selected)
    subject = st.text_input("Subject Line", value=tmpl["subject"], key="et_subject")
    body_html = st.text_area("HTML Body", value=tmpl["body_html"], height=400,
                             key="et_body",
                             help="Available variables: {risk_score}, {severity}, {keyword_hits}, {suspicious_urls}, {app_url}, {total_scans}, {threats}, {avg_score}, {start_date}, {end_date}")

    cols = st.columns([1, 1])
    with cols[0]:
        if st.button("💾 Save Template", type="primary", use_container_width=True):
            update_template(selected, subject, body_html)
            st.success("Template saved")
            st.rerun()
    with cols[1]:
        if st.button("🔄 Reset to Default", use_container_width=True):
            tmpl = DEFAULT_TEMPLATES[selected]
            update_template(selected, tmpl["subject"], tmpl["body_html"])
            st.success("Reset to default")
            st.rerun()

    st.divider()
    st.markdown("##### Preview")
    st.markdown(f"**Subject:** {subject}")
    st.markdown(body_html[:500] + ("..." if len(body_html) > 500 else ""),
                unsafe_allow_html=True)
