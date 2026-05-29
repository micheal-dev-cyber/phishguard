import streamlit as st

_THEME_CSS = {
    "dark": """
        .stApp { background-color: #0a0f1e; }
        h1, h2, h3, h4, h5, h6, p, span, div, label { color: #e2e8f0 !important; }
        .stTextInput input, .stSelectbox, .stNumberInput input, .stTextArea textarea {
            background-color: #111827 !important; color: #e2e8f0 !important;
            border-color: #1e3a5f !important;
        }
        .stButton button {
            background-color: #1e3a5f !important; color: #e2e8f0 !important;
        }
        .stButton button[kind="primary"] {
            background-color: #2563eb !important;
        }
        div[data-testid="stDataFrame"] { background-color: #111827 !important; }
    """,
    "light": """
        .stApp { background-color: #f8fafc; }
        h1, h2, h3, h4, h5, h6, p, span, div, label { color: #1e293b !important; }
        .stTextInput input, .stSelectbox, .stNumberInput input, .stTextArea textarea {
            background-color: #ffffff !important; color: #1e293b !important;
            border-color: #cbd5e1 !important;
        }
        .stButton button {
            background-color: #e2e8f0 !important; color: #1e293b !important;
        }
        .stButton button[kind="primary"] {
            background-color: #2563eb !important; color: #ffffff !important;
        }
        div[data-testid="stDataFrame"] { background-color: #ffffff !important; }
        .tag { background: #e2e8f0 !important; color: #1e293b !important; }
        .url-box { background: #fff5f5 !important; border-color: #fca5a5 !important; color: #dc2626 !important; }
        .safe-url-box { background: #f0fdf4 !important; border-color: #86efac !important; color: #16a34a !important; }
        .stat-card { background: #ffffff !important; border-color: #e2e8f0 !important; }
    """,
}


def apply_theme(theme: str):
    theme = theme if theme in _THEME_CSS else "dark"
    st.markdown(
        f"<style>{_THEME_CSS[theme]}</style>",
        unsafe_allow_html=True,
    )


def render_theme_toggle():
    current = st.session_state.get("theme", "dark")
    new_theme = "light" if current == "dark" else "dark"
    label = "🌙 Dark" if current == "light" else "☀️ Light"
    if st.toggle(label, value=(current == "dark"), key="theme_toggle_main"):
        st.session_state["theme"] = "dark"
    else:
        st.session_state["theme"] = "light"
    if st.session_state.get("theme") != current:
        st.rerun()
