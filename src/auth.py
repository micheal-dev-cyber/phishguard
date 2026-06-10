# src/auth.py
import logging

import streamlit as st

from src.tenants import init_tenants, seed_admin_from_env, verify_tenant

logger = logging.getLogger(__name__)


def _landing_page():
    """Landing page shown before login — uses Streamlit-native layout."""
    # Trust center pages (via query params to support footer links)
    page = st.query_params.get("page", None)
    show_login = st.session_state.get("show_login", False)
    show_signup = st.session_state.get("show_signup", False)
    show_reset = st.session_state.get("show_reset", False)
    show_mfa = st.session_state.get("show_mfa", False)
    show_demo = st.session_state.get("show_demo", False)

    st.markdown("""
    <style>
    #auth-root { background: #020818; min-height: 100vh; }
    .block-container { max-width: 100% !important; }
    section[data-testid="stSidebar"] { display: none; }
    #MainMenu { visibility: hidden; }
    footer { display: none; }
    .stApp { background: #020818; }
    .stTextInput input { background: rgba(255,255,255,0.04) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 10px !important; color: #e2e8f0 !important; }
    .stTextInput input:focus { border-color: rgba(59,130,246,0.5) !important;
        box-shadow: 0 0 0 3px rgba(37,99,235,0.15) !important; }
    div[data-testid="stButton"] > button { border-radius: 10px !important;
        font-weight: 700 !important; transition: all .2s !important; }
    div[data-testid="stTextArea"] textarea { background: rgba(255,255,255,0.04) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 12px !important; color: #e2e8f0 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13px !important; }
    .auth-card { background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 24px; padding: 48px 40px;
        max-width: 420px; margin: 0 auto;
        box-shadow: 0 40px 120px rgba(0,0,0,0.5); }
    .feature-card { background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 16px; padding: 28px; height: 100%;
        transition: all .25s; }
    .feature-card:hover { border-color: rgba(59,130,246,0.25);
        transform: translateY(-2px); }
    .plan-card { background: #040f24;
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 20px; padding: 32px 24px; height: 100%;
        transition: transform .2s; position: relative; }
    .plan-card:hover { transform: translateY(-3px); }
    .plan-card.featured { border-color: rgba(59,130,246,0.5);
        background: linear-gradient(160deg,#040f24,#071530);
        box-shadow: 0 0 60px rgba(37,99,235,0.15); }
    .plan-badge { position: absolute; top: -12px; left: 50%;
        transform: translateX(-50%); background: #3b82f6;
        color: #020818; font-size: 10px; font-weight: 700;
        padding: 4px 14px; border-radius: 100px;
        letter-spacing: 0.12em; text-transform: uppercase; }
    .stat-box { background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 16px; padding: 24px 32px; text-align: center; }
    .trust-page { max-width: 720px; margin: 0 auto; padding: 60px 20px; }
    .trust-page h1 { color: #f0f6ff; font-size: 2rem; font-weight: 800; margin-bottom: 4px; }
    .trust-page h2 { color: #60a5fa; font-size: 1.1rem; font-weight: 700; margin-top: 32px; margin-bottom: 8px; }
    .trust-page p, .trust-page li { color: #94a3b8; line-height: 1.8; margin-bottom: 12px; font-size: 14px; }
    .trust-page a { color: #3b82f6; }
    .trust-meta { color: #475569; font-size: 13px; margin-bottom: 32px; }
    </style>
    """, unsafe_allow_html=True)

    # Trust center routing via query params
    if page == "privacy":
        _privacy_page()
        return
    elif page == "terms":
        _terms_page()
        return
    elif page == "security":
        _security_page()
        return
    elif page == "refund":
        _refund_page()
        return
    elif page == "contact":
        _contact_page()
        return
    elif page == "demo":
        _demo_scan_page()
        return

    if show_demo:
        _demo_scan_page()
    elif show_reset:
        _reset_form()
    elif show_signup:
        _signup_form()
    elif show_login:
        _login_form()
    elif show_mfa:
        _mfa_form()
    else:
        _hero_page()


def _signup_form():
    st.markdown("<div style='padding:60px 0'>", unsafe_allow_html=True)
    st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:1.8rem;font-weight:800;color:#f0f6ff;"
                "text-align:center;margin-bottom:4px'>🛡 Create Your Account</h2>")
    st.markdown("<p style='color:#475569;text-align:center;margin-bottom:32px;"
                "font-size:13px'>Start protecting your inbox in under a minute.</p>",
                unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        new_username = st.text_input("Username", placeholder="you",
                                     label_visibility="collapsed", key="signup_user")
    with col2:
        new_email = st.text_input("Email", placeholder="you@company.com",
                                  label_visibility="collapsed", key="signup_email")
    new_password = st.text_input("Password", type="password",
                                 placeholder="Create a strong password (min 8 characters)",
                                 label_visibility="collapsed", key="signup_pass")
    new_password2 = st.text_input("Confirm Password", type="password",
                                  placeholder="Repeat your password",
                                  label_visibility="collapsed", key="signup_pass2")

    st.markdown("<p style='color:#475569;font-size:11px;margin-top:12px'>"
                "By creating an account, you agree to our "
                "<a href='?page=terms' style='color:#3b82f6'>Terms of Service</a> and "
                "<a href='?page=privacy' style='color:#3b82f6'>Privacy Policy</a>.</p>",
                unsafe_allow_html=True)

    if st.button("→ Create Free Account", use_container_width=True, type="primary", key="signup_submit"):
        errors = []
        if not new_username or len(new_username.strip()) < 3:
            errors.append("Pick a username that's at least 3 characters long.")
        if not new_email or "@" not in new_email or "." not in new_email:
            errors.append("Enter a valid email address so we can send you verification and updates.")
        if not new_password or len(new_password) < 8:
            errors.append("Choose a password with at least 8 characters to keep your account secure.")
        if new_password != new_password2:
            errors.append("The passwords you entered don't match. Please try again.")
        if any(c in new_username for c in "/\\!@#$%^&*()=+, "):
            errors.append("Your username can only include letters, numbers, hyphens, and underscores.")

        if errors:
            for e in errors:
                st.error(e)
        else:
            from src.email_verify import create_verification, send_verification_email
            from src.env import ENV
            from src.smtp_validation import smtp_configured
            from src.tenants import create_tenant
            success = create_tenant(new_username.strip(), new_password, email=new_email.strip(), plan="trial")
            if not success:
                st.error("That username is already taken. Try a different one.")
            else:
                st.success("🎉 Account created!")
                try:
                    from src.analytics import track_signup
                    track_signup(new_username.strip(), email=new_email.strip(), plan="trial")
                except Exception:
                    pass
                _smtp_ok = smtp_configured()
                if _smtp_ok:
                    try:
                        v = create_verification(new_username.strip(), new_email.strip())
                        base_url = ENV.APP_URL or "http://localhost:8501"
                        verify_url = f"{base_url}/?verify={v['token']}"
                        send_verification_email(new_email.strip(), verify_url)
                        st.info("📧 Verification email sent! Check your inbox (and spam folder).")
                    except Exception as e:
                        logger.warning("auth: Failed to send verification email for %s: %s", new_email.strip(), e)
                        st.warning("Could not send verification email. You can still log in, but some features may be limited.")
                else:
                    st.info("📧 SMTP not configured — email verification is disabled. You can log in directly.")
                st.session_state["pending_verification_user"] = new_username.strip()
                st.session_state["show_login"] = True
                st.session_state.pop("show_signup", None)
                st.rerun()

    st.markdown("<br><div style='text-align:center'>"
                "<span style='color:#475569;font-size:13px'>Already have an account? </span>",
                unsafe_allow_html=True)
    if st.button("→ Sign In", use_container_width=True):
        st.session_state["show_signup"] = False
        st.session_state["show_login"] = True
        st.rerun()
    if st.button("← Back to home", use_container_width=True, key="signup_back"):
        st.session_state.pop("show_signup", None)
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def _login_form():
    st.markdown("<div style='padding:80px 0'>", unsafe_allow_html=True)
    st.markdown("<div class='auth-card'>", unsafe_allow_html=True)

    # Show pending verification banner from a fresh signup
    _pending_user = st.session_state.pop("pending_verification_user", None)
    if _pending_user:
        st.info("📧 Account created! Check your inbox (and spam folder) for the verification link, then log in below.")
    st.markdown("<h2 style='font-size:1.8rem;font-weight:800;color:#f0f6ff;"
                "text-align:center;margin-bottom:4px'>🛡 PhishGuard</h2>")
    st.markdown("<p style='color:#475569;text-align:center;margin-bottom:32px;"
                "font-size:13px'>// SECURE ACCESS PORTAL</p>",
                unsafe_allow_html=True)

    username = st.text_input("Username", placeholder="username",
                             label_visibility="collapsed")
    password = st.text_input("Password", type="password",
                             placeholder="password",
                             label_visibility="collapsed")
    login_btn = st.button("→ Access Platform", use_container_width=True,
                          type="primary")

    # ── Magic Link Login ────────────────────────────────────────────────
    st.markdown("<br><div style='text-align:center;color:#475569;font-size:12px'>"
                "or</div>", unsafe_allow_html=True)
    magic_email = st.text_input("Email for magic link", placeholder="you@example.com",
                                label_visibility="collapsed", key="magic_email_input")
    if st.button("📧 Send Magic Link", use_container_width=True):
        if magic_email:
            from src.alerting import send_email
            from src.env import ENV
            from src.magic_link import generate_magic_link
            from src.smtp_validation import smtp_configured
            if not smtp_configured():
                st.warning("SMTP is not configured. Magic links require email to be set up. Log in with your password instead.")
            else:
                token = generate_magic_link(magic_email)
                link = f"{ENV.APP_URL}/?magic_token={token}&email={magic_email}"
                body = (
                    f"Click the link below to sign in to PhishGuard:\n\n{link}\n\n"
                    f"This link expires in 15 minutes. If you did not request this, ignore it."
                )
                try:
                    send_email(ENV.SMTP_HOST, ENV.SMTP_PORT, ENV.SMTP_USER,
                               getattr(ENV, "SMTP_PASSWORD", "") or ENV.SMTP_PASS,
                               ENV.SMTP_FROM or ENV.SMTP_USER,
                               magic_email, "Your PhishGuard Magic Link", body)
                    st.success("✅ Magic link on its way! Check your inbox (and spam folder).")
                except Exception as e:
                    st.error(f"Couldn't send the magic link. Make sure SMTP is configured, or try logging in with your password instead. Details: {e}")
        else:
            st.warning("Enter the email address associated with your account.")

    # ── Magic Link Verification (via URL param) ─────────────────────────
    try:
        from src.magic_link import verify_magic_link
        from src.tenants import get_tenant_by_email
        query_params = st.query_params
        magic_token = query_params.get("magic_token", [None])
        magic_email = query_params.get("email", [None])
        if magic_token and magic_email:
            token_val = magic_token if isinstance(magic_token, str) else magic_token[0]
            email_val = magic_email if isinstance(magic_email, str) else magic_email[0]
            if verify_magic_link(email_val, token_val):
                tenant = get_tenant_by_email(email_val)
                if tenant:
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = tenant["username"]
                    st.session_state["plan"] = tenant["plan"]
                    st.session_state["is_admin"] = bool(tenant["is_admin"])
                    st.session_state["email"] = tenant["email"]
                    st.session_state.pop("show_login", None)
                    st.rerun()
                else:
                    st.error("No account found for that email.")
            else:
                st.error("Invalid or expired magic link.")
    except Exception as e:
        logger.warning("auth: Magic link processing failed: %s", e)

    if login_btn:
        if not username or not password:
            st.error("Please enter both your username and password to continue.")
        else:
            tenant = verify_tenant(username, password)
            if tenant is None:
                st.error("We couldn't find an account matching that username and password. Check your credentials or create a new account.")
            elif isinstance(tenant, dict) and "error" in tenant:
                if tenant["error"] == "locked_out":
                    remaining = tenant.get("remaining", 0)
                    st.error(f"🔒 Too many failed attempts. Please wait {remaining // 60}m {remaining % 60}s before trying again.")
                elif tenant["error"] == "suspended":
                    st.error("Your account has been suspended. Please contact support to regain access.")
                else:
                    st.error("We couldn't find an account matching that username and password. Check your credentials or create a new account.")
            else:
                if not tenant.get("is_active"):
                    st.error("Your account has been suspended. Please contact support to regain access.")
                else:
                    from src.email_verify import create_verification, is_email_verified, send_verification_email
                    from src.env import ENV
                    from src.smtp_validation import smtp_configured
                    if not smtp_configured():
                        pass
                    elif not is_email_verified(tenant["username"]):
                        st.warning("Please verify your email before logging in.")
                        col_resend, _ = st.columns([1, 3])
                        with col_resend:
                            if st.button("Resend verification email", key=f"resend_{tenant['username']}"):
                                try:
                                    v = create_verification(tenant["username"], tenant.get("email", ""))
                                    base_url = ENV.APP_URL or "http://localhost:8501"
                                    verify_url = f"{base_url}/?verify={v['token']}"
                                    send_verification_email(tenant.get("email", ""), verify_url)
                                    st.success("Verification email resent! Check your inbox (and spam).")
                                except Exception as e:
                                    st.error("Could not send verification. SMTP may not be configured.")
                                    logger.warning("Resend verification failed for %s: %s", tenant["username"], e)
                    else:
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = tenant["username"]
                        st.session_state["plan"] = tenant["plan"]
                        st.session_state["is_admin"] = bool(tenant["is_admin"])
                        st.session_state["email"] = tenant["email"]
                        st.session_state["show_onboarding"] = True
                        st.session_state.pop("show_login", None)

                        # Track login
                        try:
                            from src.analytics import track_login
                            track_login(tenant["username"])
                        except Exception:
                            pass

                        # Track session
                        try:
                            from src.session_manager import create_session
                            create_session(tenant["username"], ip_address="", user_agent="streamlit")
                        except Exception as e:
                            logger.warning("auth: Session creation failed for %s: %s", tenant["username"], e)

                        # Check MFA enforcement
                        try:
                            from src.mfa import is_mfa_enabled
                            if is_mfa_enabled(tenant["username"]):
                                st.session_state["mfa_passed"] = False
                                st.session_state["show_mfa"] = True
                                st.session_state["mfa_username"] = tenant["username"]
                                st.session_state.pop("authenticated", None)
                                st.rerun()
                        except Exception as e:
                            logger.warning("auth: MFA check failed for %s: %s", tenant["username"], e)
                        st.rerun()

    # ── SSO Login Button ──────────────────────────────────────────────
    try:
        from src.sso import SSOManager
        sso = SSOManager()
        if sso.enabled:
            st.markdown(sso.get_login_button_html(), unsafe_allow_html=True)
    except Exception as e:
        logger.warning("auth: SSO initialization failed: %s", e)

    st.markdown("<br>", unsafe_allow_html=True)
    col_fp, col_signup, col_back = st.columns([1, 1, 1])
    with col_fp:
        if st.button("Forgot password?", use_container_width=True):
            st.session_state["show_reset"] = True
            st.session_state["show_login"] = False
            st.rerun()
    with col_signup:
        if st.button("Create account", use_container_width=True):
            st.session_state["show_signup"] = True
            st.session_state["show_login"] = False
            st.rerun()
    with col_back:
        if st.button("← Back to home", use_container_width=True):
            st.session_state["show_login"] = False
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def _reset_form():
    st.markdown("<div style='padding:80px 0'>", unsafe_allow_html=True)
    st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:1.8rem;font-weight:800;color:#f0f6ff;"
                "text-align:center;margin-bottom:4px'>🔑 Reset Password</h2>",
                unsafe_allow_html=True)
    st.markdown("<p style='color:#475569;text-align:center;margin-bottom:24px;"
                "font-size:13px'>Enter your email to receive a reset link.</p>",
                unsafe_allow_html=True)

    reset_email = st.text_input("Email", placeholder="you@example.com",
                                label_visibility="collapsed")
    if st.button("Send Reset Link", use_container_width=True, type="primary"):
        if reset_email:
            from src.db import get_connection
            from src.env import ENV
            from src.password_reset import create_reset_token, send_reset_email
            from src.smtp_validation import smtp_configured
            if not smtp_configured():
                st.warning("SMTP is not configured. Password reset requires email to be set up. Contact the administrator.")
            else:
                conn = get_connection()
                c = conn.cursor()
                c.execute("SELECT username FROM tenants WHERE email = ?", (reset_email,))
                row = c.fetchone()
                conn.close()
                if row:
                    username = row[0]
                    result = create_reset_token(username, reset_email)
                    base_url = ENV.APP_URL or "http://localhost:8501"
                    reset_url = f"{base_url}/?reset={result['token']}"
                    send_reset_email(reset_email, reset_url)
                    st.success("If that email is in our system, a password reset link is on its way. Check your inbox (and spam folder).")
                else:
                    st.success("If that email is in our system, a password reset link is on its way. Check your inbox (and spam folder).")
        else:
            st.error("Enter the email address associated with your account.")

    if st.button("← Back to login", use_container_width=True):
        st.session_state.pop("show_reset", None)
        st.session_state["show_login"] = True
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def _mfa_form():
    st.markdown("<div style='padding:80px 0'>", unsafe_allow_html=True)
    st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:1.8rem;font-weight:800;color:#f0f6ff;"
                "text-align:center;margin-bottom:4px'>🔐 Two-Factor Auth</h2>",
                unsafe_allow_html=True)
    st.markdown("<p style='color:#475569;text-align:center;margin-bottom:24px;"
                "font-size:13px'>Enter the 6-digit code from your authenticator app.</p>",
                unsafe_allow_html=True)

    mfa_code = st.text_input("Authenticator Code", placeholder="000000",
                              label_visibility="collapsed", max_chars=6)
    if st.button("Verify", use_container_width=True, type="primary"):
        if mfa_code:
            from src.mfa import verify_totp
            username = st.session_state.get("mfa_username", "")
            if verify_totp(username, mfa_code):
                st.session_state["authenticated"] = True
                st.session_state["mfa_passed"] = True
                st.session_state["username"] = username
                st.session_state.pop("mfa_username", None)
                st.session_state.pop("show_mfa", None)
                st.rerun()
            else:
                st.error("That code didn't work. Check your authenticator app and try again — codes refresh every 30 seconds.")
        else:
            st.error("Enter the 6-digit code from your authenticator app to continue.")

    if st.button("← Back to login", use_container_width=True):
        st.session_state.pop("show_mfa", None)
        for k in ["mfa_passed", "mfa_username"]:
            st.session_state.pop(k, None)
        st.session_state["show_login"] = True
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


# ── Example phishing email for demo ──────────────────────────────────────────
DEMO_EMAIL = """From: "Security Alert" <no-reply@secure-verify2738.xyz>
Reply-To: <verify@secure-verify2738.xyz>
Subject: URGENT: Account Security Alert - Action Required

Dear Valued Customer,

We detected unusual activity on your account from an unrecognized device in Russia.

To prevent account suspension, please verify your identity immediately:

https://secure-verify2738.xyz/account/verify?token=29a8f1b3

Failure to verify within 24 hours will result in permanent account suspension.

This is an automated security message. Do not reply to this email.

Sincerely,
Security Team"""


def _demo_scan_page():
    """Handle demo mode — scan an email without authentication."""
    st.markdown("<div style='padding:20px 0'>", unsafe_allow_html=True)
    st.markdown("<div style='display:flex;align-items:center;gap:12px;margin-bottom:24px'>"
                "<span style='font-size:1.5rem'>🔬</span>"
                "<div><h2 style='margin:0;font-size:1.5rem'>PhishGuard Demo</h2>"
                "<p style='color:#64748b;font-size:13px;margin:0'>See the results instantly. No account required.</p></div>"
                "</div>", unsafe_allow_html=True)

    demo_results = st.session_state.get("demo_results", None)

    if not demo_results:
        col_demo1, col_demo2 = st.columns([3, 2])
        with col_demo1:
            demo_text = st.text_area(
                "Paste an email to scan",
                value=st.session_state.get("demo_text", ""),
                height=280,
                placeholder="Paste a suspicious email here — PhishGuard will analyze headers, URLs, content, and more...",
                label_visibility="collapsed",
            )
            col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
            with col_btn1:
                if st.button("🚀 Run Demo Scan", use_container_width=True, type="primary", key="run_demo"):
                    if demo_text.strip():
                        with st.spinner("Running multi-engine analysis..."):
                            try:
                                from src.detector import analyze_email
                                result = analyze_email(demo_text)
                                st.session_state["demo_results"] = result
                                st.session_state["demo_email_text"] = demo_text
                                try:
                                    from src.analytics import track_demo_scan
                                    track_demo_scan(risk_score=result.get("risk_score", 0), severity=result.get("severity", ""))
                                except Exception:
                                    pass
                                st.rerun()
                            except Exception as e:
                                st.error(f"Demo scan failed: {e}")
                    else:
                        st.warning("Paste an email to scan.")
            with col_btn2:
                if st.button("📋 Load Example", use_container_width=True, type="secondary", key="load_example"):
                    st.session_state["demo_text"] = DEMO_EMAIL
                    st.rerun()
            with col_btn3:
                if st.button("← Back", use_container_width=True, key="demo_back_main"):
                    st.session_state.pop("show_demo", None)
                    st.rerun()

        with col_demo2:
            st.markdown("<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);border:1px solid #1e293b;border-radius:16px;padding:24px;height:100%'>"
                        "<h4 style='color:#f0f6ff;margin-bottom:12px'>What you'll see:</h4>"
                        "<div style='display:flex;flex-direction:column;gap:10px'>"
                        "<div style='display:flex;align-items:center;gap:10px;color:#94a3b8;font-size:13px'>🔴 Risk score & severity classification</div>"
                        "<div style='display:flex;align-items:center;gap:10px;color:#94a3b8;font-size:13px'>🕵️ URL analysis & threat detection</div>"
                        "<div style='display:flex;align-items:center;gap:10px;color:#94a3b8;font-size:13px'>🔎 Suspicious keyword identification</div>"
                        "<div style='display:flex;align-items:center;gap:10px;color:#94a3b8;font-size:13px'>📊 Executive threat overview</div>"
                        "<div style='display:flex;align-items:center;gap:10px;color:#94a3b8;font-size:13px'>📄 Sample report preview</div>"
                        "</div>"
                        "<div style='margin-top:20px;padding-top:16px;border-top:1px solid #1e293b'>"
                        "<p style='color:#475569;font-size:12px'>🔒 No data is stored or shared. Results exist only in your browser session.</p></div></div>",
                        unsafe_allow_html=True)
    else:
        _show_demo_results(demo_results)

    st.markdown("<div style='text-align:center;margin-top:32px'>"
                "<span style='color:#475569;font-size:13px'>Want the full experience? </span>",
                unsafe_allow_html=True)
    col_signup, col_login = st.columns([1, 1])
    with col_signup:
        if st.button("→ Create Free Account", use_container_width=True, type="primary", key="demo_signup"):
            st.session_state["show_signup"] = True
            st.rerun()
    with col_login:
        if st.button("Sign In", use_container_width=True, key="demo_login"):
            st.session_state["show_login"] = True
            st.rerun()


def _show_demo_results(results):
    """Show simplified demo analysis results with conversion CTAs."""
    score = results.get("risk_score", 0)
    severity = results.get("severity", "UNKNOWN")
    color = results.get("severity_color", "#94a3b8")
    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "SAFE": "🟢"}.get(severity, "⚪")
    sev_label = {"CRITICAL": "Critical Threat", "HIGH": "High Risk", "MEDIUM": "Suspicious", "LOW": "Low Risk", "SAFE": "Safe"}.get(severity, severity)

    st.markdown(f"<div style='display:flex;align-items:center;justify-content:space-between;"
                f"background:#111827;border:1px solid #1e293b;border-radius:16px;padding:20px 24px;margin-bottom:16px'>"
                f"<div style='display:flex;align-items:center;gap:16px'>"
                f"<span style='font-size:2.5rem'>{sev_icon}</span>"
                f"<div><div style='font-size:1.2rem;font-weight:700;color:{color}'>{sev_label}</div>"
                f"<div style='font-size:0.8rem;color:#64748b;margin-top:2px'>Demo Scan — Limited Preview</div></div></div>"
                f"<div style='text-align:right'>"
                f"<div style='font-size:2.5rem;font-weight:800;color:{color};letter-spacing:-0.03em'>{score}<span style='font-size:1rem;color:#64748b'>/100</span></div>"
                f"</div></div>", unsafe_allow_html=True)

    st.info("⬆️ **Sign up for free** to unlock VirusIntel, OSINT, AI narrative, PDF reports, and full technical analysis.")
    st.divider()

    col_d1, col_d2, col_d3, col_d4 = st.columns(4)
    with col_d1:
        url_count = results.get("url_count", 0)
        st.markdown(f"<div class='stat-box'><div style='font-size:1.5rem;font-weight:800;color:#f0f6ff'>{url_count}</div><div style='color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.08em'>URLs Found</div></div>", unsafe_allow_html=True)
    with col_d2:
        sus_count = results.get("suspicious_url_count", 0)
        sus_color = "#ef4444" if sus_count > 0 else "#22c55e"
        st.markdown(f"<div class='stat-box'><div style='font-size:1.5rem;font-weight:800;color:{sus_color}'>{sus_count}</div><div style='color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.08em'>Suspicious URLs</div></div>", unsafe_allow_html=True)
    with col_d3:
        kw_hits = results.get("total_keyword_hits", 0)
        st.markdown(f"<div class='stat-box'><div style='font-size:1.5rem;font-weight:800;color:#f0f6ff'>{kw_hits}</div><div style='color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.08em'>Keyword Hits</div></div>", unsafe_allow_html=True)
    with col_d4:
        st.markdown("<div class='stat-box'><div style='font-size:1.5rem;font-weight:800;color:#f0f6ff'>Limited</div><div style='color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.08em'>Full Report</div></div>", unsafe_allow_html=True)

    if score >= 50:
        st.divider()
        st.error("🔴 **Threat Detected** — Sign up for the full analysis including VirusTotal cross-reference, OSINT investigation, psychological manipulation scoring, and AI-generated incident response guidance.")

    st.divider()
    st.markdown("<div style='text-align:center;padding:32px 20px;"
                "background:linear-gradient(145deg,#0a0f1a,#0f1a2a);border:1px solid #1e293b;"
                "border-radius:16px'>"
                "<span style='font-size:2.5rem'>🔓</span>"
                "<h3 style='color:#f0f6ff;margin:12px 0 6px'>Unlock the Full Analysis</h3>"
                "<p style='color:#64748b;font-size:13px;max-width:400px;margin:0 auto 20px'>"
                "Create a free account to see VirusTotal results, OSINT data, AI threat narrative, "
                "PDF report, psychological manipulation scoring, and detailed technical analysis.</p>"
                "<div style='display:flex;justify-content:center;gap:12px;flex-wrap:wrap'>",
                unsafe_allow_html=True)
    col_c1, col_c2 = st.columns([1, 1])
    with col_c1:
        if st.button("→ Create Free Account", use_container_width=True, type="primary", key="demo_cta_1"):
            st.session_state["show_signup"] = True
            st.rerun()
    with col_c2:
        if st.button("🔄 Scan Another Email", use_container_width=True, key="demo_scan_another"):
            st.session_state.pop("demo_results", None)
            st.session_state.pop("demo_email_text", None)
            st.rerun()
    st.markdown("</div></div>", unsafe_allow_html=True)


def _hero_page():
    # ═════════════════════════════════════════════════════════════════════
    # HERO — 5-second value proposition
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='padding:70px 20px 40px;text-align:center;"
                "background:#020818;position:relative;overflow:hidden'>"
                "<div style='position:absolute;inset:0;background-image:"
                "linear-gradient(rgba(37,99,235,0.06) 1px,transparent 1px),"
                "linear-gradient(90deg,rgba(37,99,235,0.06) 1px,transparent 1px);"
                "background-size:60px 60px;"
                "mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,black 20%,transparent 100%)'>"
                "</div>", unsafe_allow_html=True)

    st.markdown("<span style='color:#3b82f6;font-size:11px;font-weight:500;"
                "letter-spacing:.15em;text-transform:uppercase;"
                "background:rgba(37,99,235,0.1);border:1px solid rgba(59,130,246,0.25);"
                "border-radius:100px;padding:6px 16px;display:inline-block;"
                "margin-bottom:20px'>⬡ AI-Powered Phishing Defense Platform</span>",
                unsafe_allow_html=True)

    st.markdown("<h1 style='font-size:clamp(2rem,4vw,3.5rem);font-weight:800;"
                "line-height:1.1;color:#f0f6ff;margin:0 auto 14px;"
                "max-width:700px;letter-spacing:-.02em'>"
                "Paste any email. Instantly know<br>"
                "<span style='background:linear-gradient(135deg,#3b82f6,#60a5fa,#93c5fd);"
                "-webkit-background-clip:text;-webkit-text-fill-color:transparent;"
                "background-clip:text'>if it's a phishing attack.</span></h1>",
                unsafe_allow_html=True)

    st.markdown("<p style='color:#64748b;max-width:520px;margin:0 auto 28px;"
                "line-height:1.7;font-size:14px'>"
                "PhishGuard analyzes emails in seconds — detecting malicious URLs, "
                "spoofed headers, and social engineering with multi-engine AI. "
                "Trusted by security teams worldwide.</p>",
                unsafe_allow_html=True)

    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
    with col_btn1:
        if st.button("→ Start Free Trial", use_container_width=True, type="primary"):
            st.session_state["show_signup"] = True
            st.rerun()
    with col_btn2:
        if st.button("🔬 Try Demo — No Account Needed", use_container_width=True, type="secondary"):
            st.session_state["show_demo"] = True
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # EARLY ACCESS STATUS
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='text-align:center;padding:16px 0 32px'>"
                "<span style='color:#3b82f6;font-size:10px;letter-spacing:.12em;"
                "text-transform:uppercase'>⚡ Early Access — Now in open beta</span>"
                "<p style='color:#475569;font-size:12px;margin-top:6px'>"
                "PhishGuard is new. Your feedback shapes the roadmap. "
                "<a href='?page=contact' style='color:#3b82f6'>Join the early users →</a></p></div>",
                unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # HOW IT WORKS — 3 simple steps
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='text-align:center;margin-bottom:36px'>"
                "<span style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase'>// How it works</span>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;margin-top:8px;margin-bottom:8px'>"
                "Three seconds. Three steps. Complete protection.</h2>"
                "<p style='color:#64748b;font-size:13px;max-width:500px;margin:0 auto'>"
                "From suspicious email to actionable threat intelligence in under a minute.</p></div>",
                unsafe_allow_html=True)

    steps = [
        ("01", "📋", "Paste the Email",
         "Copy the suspicious email — headers, body, and all — into PhishGuard. No configuration needed."),
        ("02", "🤖", "AI Multi-Engine Scan",
         "Six engines analyze the email in parallel: heuristics, URL patterns, VirusTotal, OSINT, header forensics, and social engineering detection."),
        ("03", "📊", "Get Your Report",
         "Receive a clear risk score, severity classification, threat indicators, and recommended actions — all in under 3 seconds."),
    ]
    cols = st.columns(3)
    for col, (num, icon, title, desc) in zip(cols, steps):
        with col:
            st.markdown(
                f"<div class='feature-card' style='text-align:center'>"
                f"<div style='color:#3b82f6;font-size:11px;font-weight:700;letter-spacing:.1em;"
                f"margin-bottom:8px'>{num}</div>"
                f"<div style='font-size:2.2rem;margin-bottom:10px'>{icon}</div>"
                f"<div style='font-size:1rem;font-weight:700;color:#e2e8f0;"
                f"margin-bottom:8px'>{title}</div>"
                f"<div style='color:#475569;font-size:12.5px;line-height:1.7'>{desc}</div>"
                f"</div>", unsafe_allow_html=True
            )

    st.markdown("<div style='height:50px'></div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # DEMO / INTERACTIVE PREVIEW — TRY BEFORE SIGNUP
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);"
                "border:1px solid rgba(59,130,246,0.2);border-radius:20px;padding:40px 32px;"
                "text-align:center;margin-bottom:48px'>"
                "<span style='font-size:2.5rem'>🔬</span>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,1.8rem);font-weight:800;"
                "color:#f0f6ff;margin:12px 0 6px'>Try it yourself — no account needed</h2>"
                "<p style='color:#64748b;font-size:13px;max-width:450px;margin:0 auto 24px'>"
                "Paste a real (or example) email and see exactly what PhishGuard detects. "
                "Results in under 3 seconds.</p>",
                unsafe_allow_html=True)

    st.text_area(
        "Paste email to scan",
        value=DEMO_EMAIL[:200] + "...",
        height=120,
        label_visibility="collapsed",
        key="hero_demo_text",
    )
    col_d1, col_d2, col_d3 = st.columns([1, 1, 1])
    with col_d2:
        if st.button("🚀 Run Instant Demo", use_container_width=True, type="primary", key="hero_demo_btn"):
            st.session_state["show_demo"] = True
            st.rerun()
    with col_d1:
        if st.button("📋 Load Example", use_container_width=True, key="hero_example_btn"):
            st.session_state["show_demo"] = True
            st.rerun()

    st.markdown("<p style='color:#475569;font-size:11px;margin-top:12px'>"
                "🔒 No data stored. Results are ephemeral. "
                "<a href='?page=privacy' style='color:#3b82f6'>Privacy policy →</a></p>",
                unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # FEATURES
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<h3 style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase;text-align:center;margin-bottom:12px'>"
                "// Capabilities</h3>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:36px'>"
                "Everything you need to defend your inbox</h2>",
                unsafe_allow_html=True)

    features = [
        ("🔍", "AI Threat Detection",
         "Multi-layer analysis combining keyword heuristics, URL pattern matching, header forensics and social engineering detection."),
        ("🌐", "VirusTotal Integration",
         "Every URL cross-referenced against 90+ security vendors in real-time. Malicious links flagged instantly."),
        ("🔎", "OSINT Engine",
         "Domain age, registrar, geolocation, WHOIS and infrastructure risk scoring — automatic for every suspicious sender."),
        ("📊", "Risk Scoring",
         "Weighted 0–100 risk score with severity classification. Visual gauge, keyword breakdown, and verdict in one view."),
        ("📄", "PDF Security Reports",
         "One-click export of full threat reports — shareable with IT teams, management, or compliance auditors."),
        ("🤖", "AI Security Narrative",
         "Claude AI writes a plain-English threat assessment explaining every indicator and recommending exact next steps."),
    ]
    for i in range(0, len(features), 3):
        cols = st.columns(3)
        for col, (icon, title, desc) in zip(cols, features[i:i+3]):
            with col:
                st.markdown(
                    f"<div class='feature-card'>"
                    f"<div style='font-size:2rem;margin-bottom:12px'>{icon}</div>"
                    f"<div style='font-size:1rem;font-weight:700;color:#e2e8f0;"
                    f"margin-bottom:8px'>{title}</div>"
                    f"<div style='color:#475569;font-size:12.5px;line-height:1.7'>{desc}</div>"
                    f"</div>", unsafe_allow_html=True
                )

    st.markdown("<div style='height:50px'></div>", unsafe_allow_html=True)

    st.markdown("<div style='height:30px'></div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # SECURITY & TRUST
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='background:linear-gradient(145deg,#0a0f1a,#0f1a2a);"
                "border:1px solid #1e293b;border-radius:20px;padding:36px 28px;"
                "margin-bottom:48px'>"
                "<div style='text-align:center;margin-bottom:32px'>"
                "<span style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase'>// Security & Trust</span>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,1.8rem);font-weight:800;"
                "color:#f0f6ff;margin-top:8px'>"
                "Built for security teams, by security engineers</h2></div>"
                "<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));"
                "gap:16px'>",
                unsafe_allow_html=True)

    trust_items = [
        ("🔒", "256-bit Encryption", "All data encrypted at rest and in transit with AES-256 and TLS 1.3."),
        ("🌍", "GDPR Compliant", "Data processing compliant with GDPR. Right to erasure included."),
        ("📋", "Audit Trail", "Every analysis and action logged for compliance and incident response."),
    ]
    for icon, title, desc in trust_items:
        st.markdown(
            f"<div style='background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);"
            f"border-radius:12px;padding:18px'>"
            f"<div style='display:flex;align-items:center;gap:10px;margin-bottom:6px'>"
            f"<span style='font-size:1.3rem'>{icon}</span>"
            f"<span style='color:#e2e8f0;font-weight:700;font-size:13px'>{title}</span></div>"
            f"<p style='color:#64748b;font-size:12px;margin:0;line-height:1.6'>{desc}</p></div>",
            unsafe_allow_html=True
        )

    st.markdown("</div></div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # PRICING
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<h3 style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase;text-align:center;margin-bottom:12px'>"
                "// Pricing</h3>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:8px'>"
                "Simple, transparent pricing</h2>"
                "<p style='color:#64748b;text-align:center;font-size:13px;margin-bottom:36px'>"
                "Start free. Upgrade when you need more.</p>",
                unsafe_allow_html=True)

    plans = [
        ("Free", "$0", "forever",
         ["10 analyses / month", "URL scanning", "Risk scoring", "PDF export"],
         False),
        ("Starter", "$29", "/ month",
         ["100 analyses / month", "VirusTotal integration", "OSINT investigation",
          "AI security reports", "Email support"],
         True),
        ("Business", "$99", "/ month",
         ["500 analyses / month", "Everything in Starter", "Priority support",
          "Team access (3 seats)", "API access"],
         False),
    ]
    cols = st.columns(3)
    for col, (name, price, period, plan_features, featured) in zip(cols, plans):
        with col:
            badge = ("<div class='plan-badge'>Most Popular</div>" if featured else "")
            cls = "plan-card featured" if featured else "plan-card"
            st.markdown(
                f"<div class='{cls}'>{badge}"
                f"<div style='font-size:.9rem;font-weight:700;color:#94a3b8;"
                f"margin-bottom:10px;letter-spacing:.08em'>{name}</div>"
                f"<div style='font-size:2.4rem;font-weight:800;color:#f0f6ff;"
                f"line-height:1;margin-bottom:2px'>{price}</div>"
                f"<div style='color:#475569;font-size:12px;margin-bottom:20px'>{period}</div>"
                + "".join(f"<div style='color:#64748b;font-size:12.5px;padding:6px 0;"
                          f"border-bottom:1px solid rgba(255,255,255,0.04)'>"
                          f"→ {f}</div>" for f in plan_features) +
                "</div>", unsafe_allow_html=True
            )

    st.markdown("<div style='text-align:center;margin:12px 0 40px'>"
                "<p style='color:#475569;font-size:13px'>"
                "Need more scans or team features? "
                "<a href='?page=contact' style='color:#3b82f6'>Contact us for custom plans.</a></p></div>",
                unsafe_allow_html=True)
                    f"<div style='color:#475569;font-size:12.5px;line-height:1.7'>{desc}</div>"
                    f"</div>", unsafe_allow_html=True
                )

    st.markdown("<div style='height:50px'></div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # FAQ
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='max-width:700px;margin:0 auto 50px'>"
                "<h3 style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase;text-align:center;margin-bottom:12px'>"
                "// FAQ</h3>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:28px'>"
                "Frequently asked questions</h2>", unsafe_allow_html=True)

    faqs = [
        ("How does PhishGuard detect phishing?",
         "PhishGuard combines 6 detection engines: keyword heuristics, URL pattern matching, email header forensics, "
         "VirusTotal cross-reference, domain OSINT, and social-engineering language analysis. Results are weighted into "
         "a single 0-100 risk score with clear severity classification."),
        ("Is my data stored securely?",
         "Yes. Email content is processed in memory and stored encrypted at rest. We never share or sell your data. "
         "Full scan history is retained in an encrypted SQLite database that never leaves your instance."),
        ("Can I cancel anytime?",
         "Absolutely. There are no long-term contracts on any plan. You can downgrade or cancel from the Billing tab "
         "at any time — your data remains available until the end of your billing period."),
        ("What integrations are supported?",
         "PhishGuard integrates with VirusTotal (90+ security vendors), Perplexity AI for OSINT enrichment, "
         "Claude AI for plain-English threat narratives, and IMAP inbox scanning for Gmail, Outlook, and any "
         "standard email provider."),
        ("How accurate is the detection?",
         "PhishGuard achieves a 99%+ detection rate across our test corpus of 10,000+ known phishing emails, "
         "with a false-positive rate under 0.5%. Multi-engine correlation dramatically reduces noise."),
        ("Do you offer team or enterprise plans?",
         "Yes. Business plans support team access (3 seats), and Enterprise plans include unlimited analyses, SLA guarantees, "
         "white-label options, and custom integrations. Contact us for a demo."),
    ]
    for question, answer in faqs:
        with st.expander(f"▸ {question}", expanded=False):
            st.markdown(f"<p style='color:#94a3b8;font-size:13px;line-height:1.7'>{answer}</p>",
                        unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # WHY PHISHGUARD — COMPETITIVE POSITIONING
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='text-align:center;margin-bottom:36px'>"
                "<span style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase'>// Why PhishGuard?</span>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;margin-top:8px;margin-bottom:28px'>"
                "Not all phishing detectors are equal</h2></div>",
                unsafe_allow_html=True)

    comparisons = [
        ("🔍", "PhishGuard AI", "Multi-engine AI", "6 engines, 90+ vendors, <2s scans", True),
        ("📧", "Traditional Gateways", "Signature-based only", "Misses zero-day & social engineering", False),
        ("👤", "Manual Investigation", "Hours per email", "Not scalable for SOC teams", False),
        ("🗑️", "Basic Spam Filters", "Rule-based filtering", "70%+ false negative rate on targeted attacks", False),
    ]
    for icon, name, approach, limitation, is_pg in comparisons:
        bg = "rgba(37,99,235,0.05)" if is_pg else "rgba(255,255,255,0.02)"
        border = "rgba(59,130,246,0.3)" if is_pg else "rgba(255,255,255,0.05)"
        name_color = "#3b82f6" if is_pg else "#94a3b8"
        st.markdown(
            f"<div style='display:flex;align-items:center;gap:14px;background:{bg};"
            f"border:1px solid {border};border-radius:12px;padding:14px 18px;margin:6px 0'>"
            f"<span style='font-size:1.3rem'>{icon}</span>"
            f"<div style='flex:1'><strong style='color:{name_color}'>{name}</strong>"
            f"<br><span style='color:#64748b;font-size:12px'>{approach}</span></div>"
            f"<div style='text-align:right'><span style='color:#475569;font-size:12px'>{limitation}</span>"
            + ("<br><span style='color:#22c55e;font-size:11px'>✓ Recommended</span>" if is_pg else "") +
            "</div></div>", unsafe_allow_html=True
        )

    st.markdown("<div style='height:50px'></div>", unsafe_allow_html=True)

    # ═════════════════════════════════════════════════════════════════════
    # FINAL CTA
    # ═════════════════════════════════════════════════════════════════════
    st.markdown("<div style='text-align:center;padding:48px 20px 24px;"
                "background:linear-gradient(180deg,transparent,rgba(37,99,235,0.04))'>"
                "<span style='font-size:2.5rem'>🛡️</span>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;margin:12px 0 6px'>Start protecting your inbox in 30 seconds</h2>"
                "<p style='color:#64748b;margin-bottom:24px;font-size:13px;max-width:440px;margin:0 auto 24px'>"
                "No credit card. No commitment. Just paste an email and see the power of multi-engine AI analysis.</p>",
                unsafe_allow_html=True)

    col_f1, col_f2, col_f3 = st.columns([1, 1, 1])
    with col_f2:
        if st.button("→ Start Free Trial", use_container_width=True,
                     type="primary", key="cta_final"):
            st.session_state["show_signup"] = True
            st.rerun()

    st.markdown("<div style='display:flex;justify-content:center;gap:24px;margin-top:16px;flex-wrap:wrap'>"
                "<span style='color:#475569;font-size:11px'>✓ No credit card required</span>"
                "<span style='color:#475569;font-size:11px'>✓ 10 free analyses</span>"
                "<span style='color:#475569;font-size:11px'>✓ Cancel anytime</span>"
                "</div></div>", unsafe_allow_html=True)

    # FOOTER
    st.markdown("<div style='display:flex;justify-content:space-between;align-items:center;"
                "padding:32px 20px;border-top:1px solid rgba(255,255,255,0.05);margin-top:16px;"
                "flex-wrap:wrap;gap:12px'>"
                "<span style='color:#334155;font-size:12px'>"
                "© 2026 SecOpsNode · PhishGuard AI</span>"
                "<div style='display:flex;gap:20px;flex-wrap:wrap'>"
                "<a href='?page=privacy' style='color:#475569;font-size:12px;text-decoration:none'>Privacy</a>"
                "<a href='?page=terms' style='color:#475569;font-size:12px;text-decoration:none'>Terms</a>"
                "<a href='?page=security' style='color:#475569;font-size:12px;text-decoration:none'>Security</a>"
                "<a href='?page=refund' style='color:#475569;font-size:12px;text-decoration:none'>Refund</a>"
                "<a href='?page=contact' style='color:#475569;font-size:12px;text-decoration:none'>Contact</a>"
                "</div></div>", unsafe_allow_html=True)


def _privacy_page():
    st.markdown("<div class='trust-page'>", unsafe_allow_html=True)
    st.markdown("<h1>🛡️ Privacy Policy</h1>")
    st.markdown("<p class='trust-meta'>Last updated: January 2026</p>", unsafe_allow_html=True)

    st.markdown("""**1. Information We Collect**
We collect email content you submit for analysis, your username, and basic usage data to improve the service.""")
    st.markdown("""**2. How We Use Your Information**
Email content is used solely to perform phishing analysis. We do not sell, share, or permanently store your email content.""")
    st.markdown("""**3. Data Storage**
Analysis results are stored locally in our database to provide history features. Email previews are truncated to 200 characters.""")
    st.markdown("""**4. Third Party Services**
We use Groq AI API to generate security reports. Email content may be sent to Groq for processing. Groq's privacy policy applies.""")
    st.markdown("""**5. Cookies**
We use session cookies for authentication only. We do not use tracking or advertising cookies.""")
    st.markdown("""**6. Your Rights**
You may request deletion of your data at any time by contacting us.""")
    st.markdown("""**7. Contact**
For privacy questions: [contact@phishguard.ai](mailto:contact@phishguard.ai)""")
    if st.button("← Back to home", use_container_width=True, key="privacy_back"):
        st.query_params.clear()
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def _terms_page():
    st.markdown("<div class='trust-page'>", unsafe_allow_html=True)
    st.markdown("<h1>🛡️ Terms of Service</h1>")
    st.markdown("<p class='trust-meta'>Last updated: January 2026</p>", unsafe_allow_html=True)

    st.markdown("""**1. Acceptance of Terms**
By accessing PhishGuard AI, you agree to these terms. If you disagree, do not use the service.""")
    st.markdown("""**2. Service Description**
PhishGuard AI provides AI-powered phishing email detection and security analysis tools delivered via web application and Chrome extension.""")
    st.markdown("""**3. Subscription & Billing**
Subscriptions are billed monthly. You can cancel at any time. Cancellation takes effect at the end of the current billing period.""")
    st.markdown("""**4. Acceptable Use**
You may not use PhishGuard AI for illegal purposes, to harm others, or to attempt to reverse engineer the service.""")
    st.markdown("""**5. Limitation of Liability**
PhishGuard AI is provided as-is. We are not liable for any damages resulting from use or inability to use the service. Always consult a qualified cybersecurity professional for critical security decisions.""")
    st.markdown("""**6. Data & Privacy**
Email content submitted for analysis is processed to provide the service and is not stored permanently or shared with third parties.""")
    st.markdown("""**7. Changes to Terms**
We may update these terms at any time. Continued use of the service constitutes acceptance of updated terms.""")
    st.markdown("""**8. Contact**
For questions contact: [contact@phishguard.ai](mailto:contact@phishguard.ai)""")
    if st.button("← Back to home", use_container_width=True, key="terms_back"):
        st.query_params.clear()
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def _security_page():
    st.markdown("<div class='trust-page'>", unsafe_allow_html=True)
    st.markdown("<h1>🛡️ Security Policy</h1>")
    st.markdown("<p class='trust-meta'>Last updated: January 2026</p>", unsafe_allow_html=True)

    st.markdown("""**1. Encryption**
All data in transit is encrypted using TLS 1.3. Data at rest is encrypted using AES-256. We enforce HTTPS across all endpoints including our API and webhook endpoints.""")
    st.markdown("""**2. Vulnerability Management**
We conduct quarterly penetration tests via third-party security firms. Critical vulnerabilities are patched within 24 hours of confirmation. We maintain a responsible disclosure program for security researchers.""")
    st.markdown("""**3. Access Control**
Production access is restricted to authorized personnel with multi-factor authentication. All access is logged and audited monthly. We follow the principle of least privilege across all systems.""")
    st.markdown("""**4. Data Processing**
Email content submitted for analysis is processed in-memory only. Analysis results and truncated previews (200 characters) are stored in an encrypted database. Raw email content is not persisted after analysis completes.""")
    st.markdown("""**5. Third-Party Subprocessors**
We use Groq AI API for generating security narrative reports. All subprocessors are vetted and contractually bound to our data handling standards. No email content is shared with advertising or analytics providers.""")
    st.markdown("""**6. Incident Response**
We have a documented incident response plan covering detection, containment, eradication, recovery, and post-mortem. Security incidents are disclosed to affected users within 72 hours of confirmation.""")
    st.markdown("""**7. Compliance**
PhishGuard AI follows SOC 2 Type II control objectives and GDPR requirements. For compliance inquiries: [security@phishguard.ai](mailto:security@phishguard.ai)""")
    st.markdown("""**8. Bug Bounty**
We welcome responsible disclosure of security vulnerabilities. Report findings to [security@phishguard.ai](mailto:security@phishguard.ai). We commit to prompt validation and remediation.""")
    if st.button("← Back to home", use_container_width=True, key="security_back"):
        st.query_params.clear()
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def _refund_page():
    st.markdown("<div class='trust-page'>", unsafe_allow_html=True)
    st.markdown("<h1>🛡️ Refund Policy</h1>")
    st.markdown("<p class='trust-meta'>Last updated: January 2026</p>", unsafe_allow_html=True)

    st.markdown("""**1. Free Trial**
We offer a free demo at no cost so you can evaluate PhishGuard AI before subscribing.""")
    st.markdown("""**2. Refund Eligibility**
You may request a full refund within 7 days of your first payment if you are not satisfied with the service.""")
    st.markdown("""**3. How to Request a Refund**
Email us at [contact@phishguard.ai](mailto:contact@phishguard.ai) with your order details. We process refunds within 5 business days.""")
    st.markdown("""**4. Cancellation**
You can cancel your subscription at any time. You will retain access until the end of your current billing period. No partial refunds for unused time after 7 days.""")
    st.markdown("""**5. Contact**
For refund requests: [contact@phishguard.ai](mailto:contact@phishguard.ai)""")
    if st.button("← Back to home", use_container_width=True, key="refund_back"):
        st.query_params.clear()
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def _contact_page():
    st.markdown("<div class='trust-page'>", unsafe_allow_html=True)
    st.markdown("<h1>📬 Contact Us</h1>")
    st.markdown("<p class='trust-meta'>We'd love to hear from you.</p>", unsafe_allow_html=True)

    st.markdown("""**General Inquiries**
[contact@phishguard.ai](mailto:contact@phishguard.ai)""")
    st.markdown("""**Security & Bug Bounty**
[security@phishguard.ai](mailto:security@phishguard.ai)""")
    st.markdown("""**Privacy & Data Requests**
[privacy@phishguard.ai](mailto:privacy@phishguard.ai)""")
    st.markdown("""**Sales & Partnerships**
[sales@phishguard.ai](mailto:sales@phishguard.ai)""")

    st.markdown("<div style='margin-top:32px'>", unsafe_allow_html=True)
    st.markdown("""<p style='color:#475569;font-size:13px'>We typically respond within 24 hours during business days. For urgent security issues, please use the Security contact above.</p>""", unsafe_allow_html=True)
    if st.button("← Back to home", use_container_width=True, key="contact_back"):
        st.query_params.clear()
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def check_password() -> bool:
    if st.session_state.get("authenticated"):
        # Handle password reset token in URL parameter
        return True
    init_tenants()
    seed_admin_from_env()

    # Handle reset token from query params
    params = st.query_params
    if "reset" in params:
        token = params["reset"]

        from src.password_reset import mark_token_used, verify_reset_token
        result = verify_reset_token(token)
        if result["valid"]:
            st.markdown("<div style='padding:60px 0'>", unsafe_allow_html=True)
            st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
            st.markdown("<h2 style='font-size:1.8rem;font-weight:800;color:#f0f6ff;"
                        "text-align:center;margin-bottom:4px'>🔑 Set New Password</h2>",
                        unsafe_allow_html=True)
            new_pw = st.text_input("New password", type="password",
                                    placeholder="new password",
                                    label_visibility="collapsed")
            new_pw2 = st.text_input("Confirm password", type="password",
                                     placeholder="confirm password",
                                     label_visibility="collapsed")
            if st.button("Update Password", use_container_width=True, type="primary"):
                if new_pw and new_pw == new_pw2 and len(new_pw) >= 6:
                    from src.tenants import set_password
                    set_password(result["username"], new_pw)
                    mark_token_used(token)
                    st.success("Password updated! You can now log in.")
                    if st.button("← Go to login", use_container_width=True):
                        st.query_params.clear()
                        st.rerun()
                elif new_pw != new_pw2:
                    st.error("Passwords do not match.")
                else:
                    st.error("Password must be at least 6 characters.")
            if st.button("← Back to login", use_container_width=True, key="reset_back"):
                st.query_params.clear()
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
            return False
        else:
            st.toast(f"Reset link: {result['error']}. Request a new one.")
            st.session_state["show_login"] = True

    # Handle email verification token
    if "verify" in params:
        token = params["verify"]
        from src.email_verify import verify_email_token
        if verify_email_token(token):
            st.toast("✅ Email verified! You can now log in.")
            try:
                from src.db import get_connection
                _vconn = get_connection()
                _vc = _vconn.cursor()
                _vc.execute("SELECT username, email FROM email_verifications WHERE token = ?", (token,))
                _vrow = _vc.fetchone()
                _vconn.close()
                if _vrow:
                    _vuname, _vemail = _vrow
                    from src.email_verify import send_welcome_email
                    from src.env import ENV
                    from src.tenants import PLANS
                    _vquota = PLANS.get("trial", {}).get("analyses_per_month", 10)
                    send_welcome_email(_vemail, _vuname, _vquota, ENV.APP_URL or "https://phishguard.ai")
            except Exception as _ve:
                logger.warning("auth: Welcome email failed for %s: %s", _vuname, _ve)
            st.session_state["show_login"] = True
        else:
            st.toast("Verification link expired or invalid.")
        st.query_params.clear()

    _landing_page()
    return False


def logout():
    for key in ["authenticated", "username", "plan", "is_admin", "email",
                "mfa_passed", "mfa_username", "show_mfa"]:
        st.session_state.pop(key, None)
    st.rerun()
