# src/auth.py
import streamlit as st
from src.tenants import verify_tenant, seed_from_secrets, init_tenants, PLANS


def check_password() -> bool:
    if st.session_state.get("authenticated"):
        return True

    init_tenants()
    seed_from_secrets()

    st.markdown("""
    <div style='max-width:400px;margin:80px auto 0'>
      <h1 style='color:#60a5fa;text-align:center;font-size:2rem'>🛡 PhishGuard AI</h1>
      <p style='color:#94a3b8;text-align:center;margin-bottom:32px'>
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

            tenant = verify_tenant(username, password)
            if tenant:
                if not tenant["is_active"]:
                    st.error("This account has been suspended. Contact support.")
                    return False
                st.session_state["authenticated"] = True
                st.session_state["username"]      = tenant["username"]
                st.session_state["plan"]          = tenant["plan"]
                st.session_state["is_admin"]      = bool(tenant["is_admin"])
                st.session_state["email"]         = tenant["email"]
                st.rerun()
            else:
                # Fallback: check Streamlit secrets (backward compat)
                try:
                    stored = st.secrets.get("passwords", {})
                    if username in stored and stored[username] == password:
                        st.session_state["authenticated"] = True
                        st.session_state["username"]      = username
                        st.session_state["plan"]          = "starter"
                        st.session_state["is_admin"]      = (username == "admin")
                        st.session_state["email"]         = ""
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")
                except Exception:
                    st.error("Invalid username or password.")
            return False

    return False


def logout():
    for key in ["authenticated", "username", "plan", "is_admin", "email"]:
        st.session_state.pop(key, None)
    st.rerun()