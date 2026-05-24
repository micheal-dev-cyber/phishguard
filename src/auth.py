import streamlit as st


def check_password() -> bool:
    """Show login form and return True if authenticated."""

    # Already logged in
    if st.session_state.get("authenticated"):
        return True

    # Login UI
    st.markdown("""
    <div style='max-width:400px; margin: 80px auto 0 auto;'>
        <h1 style='color:#60a5fa; text-align:center; font-size:2rem'>
            🛡️ PhishGuard AI
        </h1>
        <p style='color:#94a3b8; text-align:center; margin-bottom:32px'>
            AI-Powered Phishing Detection Platform
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("#### 🔐 Login")
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password",
                                  placeholder="Enter password")
        login_btn = st.button("Login", use_container_width=True, type="primary")

        if login_btn:
            if not username or not password:
                st.error("Please enter username and password.")
                return False

            try:
                stored = st.secrets.get("passwords", {})
                if username in stored and stored[username] == password:
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = username
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
                    return False
            except Exception as e:
                st.error(f"Auth error: {e}")
                return False

    return False


def logout():
    """Clear session and log out."""
    st.session_state["authenticated"] = False
    st.session_state["username"] = ""
    st.rerun()