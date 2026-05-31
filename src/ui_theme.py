import streamlit as st

_THEME_CSS = {
    "dark": """
        .stApp { background-color: #0b0f1a; }
    """,
    "light": """
        .stApp { background-color: #f8fafc; }
        .stButton button[kind="primary"] { background: linear-gradient(135deg, #2563eb, #4f46e5) !important; color: #fff !important; }
    """,
}

def apply_theme(theme: str):
    theme = theme if theme in _THEME_CSS else "dark"
    st.markdown(f"<style>{_THEME_CSS[theme]}</style>", unsafe_allow_html=True)

def render_theme_toggle():
    current = st.session_state.get("theme", "dark")
    label = "☀️" if current == "dark" else "🌙"
    if st.button(label, key="theme_toggle_btn", use_container_width=True, help="Toggle theme"):
        st.session_state["theme"] = "light" if current == "dark" else "dark"
        st.rerun()
