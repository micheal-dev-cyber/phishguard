import streamlit as st
from src.database import verify_user_login, register_premium_user
from src.paddle_billing import verify_paddle_order

def check_password() -> bool:
    """Builds a secure graphical onboarding lock screen blocking unauthorized execution access."""
    if st.session_state.get("authenticated"):
        return True

    # Main structural landing cards matching cyber design colors
    st.markdown("""
        <div style='max-width:500px; margin: 40px auto 0 auto;'>
            <h1 style='color:#60a5fa; text-align:center; font-size:2.3rem; margin-bottom:0;'>🛡️ PhishGuard AI</h1>
            <p style='color:#94a3b8; text-align:center; margin-top:4px; margin-bottom:24px;'>
                Enterprise Threat Intelligence & Anti-Phishing Core Platform
            </p>
        </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Create clear authentication and signup routing tabs
        auth_tab, reg_tab = st.tabs(["🔐 Sign In", "🚀 Register & Activate"])
        
        # --- LOGIN LAYER ---
        with auth_tab:
            st.markdown("<br>", unsafe_allow_html=True)
            username = st.text_input("Username", key="login_user", placeholder="Enter your username")
            password = st.text_input("Password", type="password", key="login_pass", placeholder="Enter account password")
            
            if st.button("Authenticate Profile", type="primary", use_container_width=True):
                if not username or not password:
                    st.error("Credential strings cannot be left un-populated.")
                else:
                    auth_result = verify_user_login(username, password)
                    if auth_result["authenticated"]:
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = username
                        st.session_state["role"] = auth_result["role"]
                        st.rerun()
                    else:
                        st.error("Invalid credentials or suspended account sequence flagged.")

        # --- SIGNUP & PADDLE VALIDATION LAYER ---
        with reg_tab:
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("⚠️ **PhishGuard AI Premium Access Requires an Active Subscription.**")
            
            # Anchor element driving users directly to your Paddle checkout assets
            st.markdown("""
                <a href="https://checkout.paddle.com/buy?price=pri_your_price_id_here" target="_blank" style="text-decoration:none;">
                    <div style="background-color:#2563eb; color:white; text-align:center; padding:10px; border-radius:8px; font-weight:bold; margin-bottom:20px;">
                        💳 Open Secure Paddle Checkout Page
                    </div>
                </a>
            """, unsafe_allow_html=True)
            
            st.markdown("---")
            st.markdown("#### Setup Premium Account Access Keys:")
            
            new_user = st.text_input("Choose Username", key="reg_user", placeholder="Minimum 4 characters")
            new_email = st.text_input("Email Address", key="reg_email", placeholder="name@domain.com")
            new_pass = st.text_input("Create Password", type="password", key="reg_pass", placeholder="Minimum 6 characters")
            paddle_id = st.text_input("Paddle Order ID", key="reg_order", placeholder="Paste 'ord_' token from payment confirmation screen")
            
            if st.button("Provision License Key", use_container_width=True):
                if not all([new_user, new_email, new_pass, paddle_id]):
                    st.error("All configuration attributes must be completed to verify activation status.")
                elif len(new_user) < 4 or len(new_pass) < 6:
                    st.error("Username or Password string lengths fail security criteria checks.")
                else:
                    with st.spinner("Validating order authenticity via global payment grids..."):
                        is_valid, validation_msg = verify_paddle_order(paddle_id)
                        
                        if is_valid:
                            # Add user securely into the database ledger
                            success, db_msg = register_premium_user(new_user, new_pass, new_email, paddle_id)
                            if success:
                                st.success(db_msg)
                            else:
                                st.error(db_msg)
                        else:
                            st.error(f"Billing Engine Error: {validation_msg}")
                            
    return False

def logout():
    """Destroys current platform session tokens."""
    st.session_state["authenticated"] = False
    st.session_state.pop("username", None)
    st.session_state.pop("role", None)
    st.rerun()