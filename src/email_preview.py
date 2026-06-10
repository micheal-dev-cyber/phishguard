import streamlit as st

from src.email_templates import render_html
from src.env import ENV


def render_preview_ui():
    st.markdown("<h3>📧 Email Preview</h3>")
    st.caption("Preview what your users will see in their inbox. SMTP is not configured — emails are stored in the local log instead.")

    templates = ["verify", "welcome", "reset", "magic_link"]
    selected = st.selectbox("Template", templates, key="preview_template_sel")

    app_url = ENV.APP_URL or "http://localhost:8501"
    demo_username = st.text_input("Demo username", value="demo_user", key="preview_user")
    demo_email = st.text_input("Demo email", value="demo@example.com", key="preview_email")

    context = {
        "verify_url": f"{app_url}/?verify=demo_token_123",
        "username": demo_username,
        "quota": 10,
        "app_url": app_url,
        "reset_url": f"{app_url}/?reset=demo_reset_token",
        "magic_url": f"{app_url}/?magic_token=demo_magic&email={demo_email}",
    }

    html = render_html(selected, **context)
    if html:
        st.markdown("#### HTML Preview")
        st.components.v1.html(html, height=500, scrolling=True)
        st.markdown("#### Raw HTML")
        with st.expander("Show raw HTML"):
            st.code(html, language="html")
    else:
        st.warning(f"Template '{selected}' not found.")
