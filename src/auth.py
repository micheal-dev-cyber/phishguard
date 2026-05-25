# src/auth.py
import streamlit as st
from src.database import verify_user_login, register_premium_user

def logout():
    """Clears authentication state and reruns the app."""
    st.session_state["password_correct"] = False
    st.session_state["username"] = "user"
    st.session_state["role"] = None
    st.rerun()

def check_password():
    """
    Returns True if the user has logged in successfully, False otherwise.
    Renders login and activation screens if unauthenticated.
    """
    if st.session_state.get("password_correct", False):
        return True

    # Center-aligned, modern authentication form styling
    st.markdown("""
        <div style='text-align: center; margin-bottom: 2rem;'>
            <h2 style='color: #60a5fa; margin-bottom: 0.2rem;'>🛡️ PhishGuard AI Portal</h2>
            <p style='color: #94a3b8; font-size: 0.95rem;'>Commercial Threat Intelligence & Header Analysis</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Create distinct views for logging in vs provisioning a new customer subscription
    tab_login, tab_register = st.tabs(["🔑 Sign In", "💳 Activate Premium Sub"])
    
    with tab_login:
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="e.g., admin or your chosen user tag")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submit_login = st.form_submit_button("Login to Workspace", use_container_width=True)
            
            if submit_login:
                if not username or not password:
                    st.error("Please enter both username and password.")
                else:
                    auth_res = verify_user_login(username, password)
                    if auth_res["authenticated"]:
                        st.session_state["password_correct"] = True
                        st.session_state["username"] = username
                        st.session_state["role"] = auth_res["role"]
                        st.success("Authentication successful! Loading container...")
                        st.rerun()
                    else:
                        st.error("❌ Invalid credentials or inactive account subscription.")
                        
    with tab_register:
        st.markdown("""
        <p style='color:#94a3b8; font-size: 0.85rem; margin-bottom: 12px;'>
        Bought a plan on Whop or Payoneer? Enter your payment confirmation or Order ID below to instantly activate your premium workspace license.
        </p>
        """, unsafe_allow_html=True)
        
        with st.form("register_form"):
            reg_username = st.text_input("Desired Username", placeholder="Choose an individual or company handle")
            reg_email = st.text_input("Corporate Email Address", placeholder="name@company.com")
            reg_password = st.text_input("Secure Password", type="password", placeholder="Minimum 6 characters")
            reg_order_id = st.text_input("Whop / Paddle / System Order ID", placeholder="e.g., WHOP-123456789")
            submit_register = st.form_submit_button("Verify & Activate License", use_container_width=True)
            
            if submit_register:
                if not reg_username or not reg_password or not reg_email or not reg_order_id:
                    st.error("All dynamic provisioning fields are required.")
                elif len(reg_password) < 6:
                    st.error("For compliance, your password must be at least 6 characters.")
                else:
                    with st.spinner("Validating token balance logic..."):
                        success, message = register_premium_user(
                            username=reg_username.strip(),
                            password=reg_password,
                            email=reg_email.strip(),
                            order_id=reg_order_id.strip()
                        )
                    if success:
                        st.success(f"✅ {message}")
                    else:
                        st.error(f"❌ {message}")
                        
    return False