# src/auth.py
import streamlit as st
from src.tenants import verify_tenant, seed_admin_from_env, init_tenants


def _landing_page():
    """Landing page shown before login — uses Streamlit-native layout."""
    show_login = st.session_state.get("show_login", False)
    show_reset = st.session_state.get("show_reset", False)
    show_mfa = st.session_state.get("show_mfa", False)

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
    </style>
    """, unsafe_allow_html=True)

    if show_reset:
        _reset_form()
    elif show_login:
        _login_form()
    elif show_mfa:
        _mfa_form()
    else:
        _hero_page()


def _login_form():
    st.markdown("<div style='padding:80px 0'>", unsafe_allow_html=True)
    st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
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
            from src.magic_link import generate_magic_link
            from src.alerting import send_email
            from src.env import ENV
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
                st.success("✅ Magic link sent! Check your inbox.")
            except Exception as e:
                st.error(f"Failed to send: {e}")
        else:
            st.warning("Enter your email address.")

    # ── Magic Link Verification (via URL param) ─────────────────────────
    try:
        from urllib.parse import parse_qs
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
    except Exception:
        pass

    if login_btn:
        if not username or not password:
            st.error("Enter username and password.")
        else:
            tenant = verify_tenant(username, password)
            if tenant is None:
                st.error("Invalid credentials.")
            elif isinstance(tenant, dict) and "error" in tenant:
                if tenant["error"] == "locked_out":
                    remaining = tenant.get("remaining", 0)
                    st.error(f"🔒 Account locked. Try again in {remaining // 60}m {remaining % 60}s.")
                elif tenant["error"] == "suspended":
                    st.error("Account suspended. Contact support.")
                else:
                    st.error("Invalid credentials.")
            else:
                if not tenant.get("is_active"):
                    st.error("Account suspended. Contact support.")
                else:
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = tenant["username"]
                    st.session_state["plan"] = tenant["plan"]
                    st.session_state["is_admin"] = bool(tenant["is_admin"])
                    st.session_state["email"] = tenant["email"]
                    st.session_state.pop("show_login", None)

                    # Track session
                    try:
                        from src.session_manager import create_session
                        create_session(tenant["username"], ip_address="", user_agent="streamlit")
                    except Exception:
                        pass

                    # Check MFA enforcement
                    try:
                        from src.mfa import is_mfa_enabled
                        if is_mfa_enabled(tenant["username"]):
                            st.session_state["mfa_passed"] = False
                            st.session_state["show_mfa"] = True
                            st.session_state["mfa_username"] = tenant["username"]
                            st.session_state.pop("authenticated", None)
                            st.rerun()
                    except Exception:
                        pass
                    st.rerun()

    # ── SSO Login Button ──────────────────────────────────────────────
    try:
        from src.sso import SSOManager
        sso = SSOManager()
        if sso.enabled:
            st.markdown(sso.get_login_button_html(), unsafe_allow_html=True)
    except Exception:
        pass

    st.markdown("<br>", unsafe_allow_html=True)
    col_fp, col_back = st.columns([1, 1])
    with col_fp:
        if st.button("Forgot password?", use_container_width=True):
            st.session_state["show_reset"] = True
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
            from src.password_reset import create_reset_token, send_reset_email
            import sqlite3
            from pathlib import Path
            db = Path(__file__).parent.parent / "data" / "phishguard.db"
            conn = sqlite3.connect(str(db))
            c = conn.cursor()
            c.execute("SELECT username FROM tenants WHERE email = ?", (reset_email,))
            row = c.fetchone()
            conn.close()
            if row:
                username = row[0]
                result = create_reset_token(username, reset_email)
                base_url = st.secrets.get("base_url", "http://localhost:8501")
                reset_url = f"{base_url}/?reset={result['token']}"
                send_reset_email(reset_email, reset_url)
                st.success("If that email is registered, a reset link has been sent.")
            else:
                st.success("If that email is registered, a reset link has been sent.")
        else:
            st.error("Enter your email address.")

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
                st.error("Invalid code. Try again.")
        else:
            st.error("Enter the 6-digit code.")

    if st.button("← Back to login", use_container_width=True):
        st.session_state.pop("show_mfa", None)
        for k in ["mfa_passed", "mfa_username"]:
            st.session_state.pop(k, None)
        st.session_state["show_login"] = True
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def _hero_page():
    # HERO
    st.markdown("<div style='padding:100px 20px 60px;text-align:center;"
                "background:#020818;position:relative;overflow:hidden'>",
                unsafe_allow_html=True)
    st.markdown("<div style='position:absolute;inset:0;background-image:"
                "linear-gradient(rgba(37,99,235,0.06) 1px,transparent 1px),"
                "linear-gradient(90deg,rgba(37,99,235,0.06) 1px,transparent 1px);"
                "background-size:60px 60px;"
                "mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,black 20%,transparent 100%)"
                "'>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<span style='color:#3b82f6;font-size:11px;font-weight:500;"
                "letter-spacing:.15em;text-transform:uppercase;"
                "background:rgba(37,99,235,0.1);border:1px solid rgba(59,130,246,0.25);"
                "border-radius:100px;padding:6px 16px;display:inline-block;"
                "margin-bottom:32px'>⬡ AI-Powered Cybersecurity Platform</span>",
                unsafe_allow_html=True)

    st.markdown("<h1 style='font-size:clamp(2.5rem,5vw,4.5rem);font-weight:800;"
                "line-height:1.05;color:#f0f6ff;margin:0 auto 20px;"
                "max-width:800px;letter-spacing:-.02em'>"
                "Stop phishing attacks<br>"
                "<span style='background:linear-gradient(135deg,#3b82f6,#60a5fa,#93c5fd);"
                "-webkit-background-clip:text;-webkit-text-fill-color:transparent;"
                "background-clip:text'>before they land.</span></h1>",
                unsafe_allow_html=True)

    st.markdown("<p style='color:#64748b;max-width:520px;margin:0 auto 40px;"
                "line-height:1.7;font-size:15px'>"
                "PhishGuard scans emails in real-time — detecting threats, "
                "analyzing URLs, running OSINT, and generating AI security "
                "reports in seconds.</p>", unsafe_allow_html=True)

    if st.button("→ Get Started", use_container_width=True, type="primary"):
        st.session_state["show_login"] = True
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    # STATS
    cols = st.columns(4)
    stats = [("99%", "Detection rate"), ("<2s", "Scan time"),
             ("4+", "Threat engines"), ("24/7", "Always on")]
    for col, (num, label) in zip(cols, stats):
        with col:
            st.markdown("<div class='stat-box'><div style='font-size:1.8rem;"
                        "font-weight:800;color:#f0f6ff;line-height:1'>"
                        f"{num}</div>"
                        "<div style='color:#475569;font-size:11px;margin-top:4px;"
                        "letter-spacing:.08em;text-transform:uppercase'>"
                        f"{label}</div></div>", unsafe_allow_html=True)

    st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)

    # FEATURES
    st.markdown("<h3 style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase;text-align:center;margin-bottom:12px'>"
                "// Capabilities</h3>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:clamp(1.5rem,3vw,2.5rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:48px'>"
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
                    f"<div style='font-size:1.05rem;font-weight:700;color:#e2e8f0;"
                    f"margin-bottom:8px'>{title}</div>"
                    f"<div style='color:#475569;font-size:12.5px;line-height:1.7'>{desc}</div>"
                    f"</div>", unsafe_allow_html=True
                )

    st.markdown("<div style='height:60px'></div>", unsafe_allow_html=True)

    # PRICING
    st.markdown("<h3 style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase;text-align:center;margin-bottom:12px'>"
                "// Pricing</h3>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:clamp(1.5rem,3vw,2.5rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:48px'>"
                "Simple, transparent pricing</h2>", unsafe_allow_html=True)

    plans = [
        ("Trial", "Free", "forever",
         ["10 analyses / month", "URL scanning", "Risk scoring", "PDF export"],
         False),
        ("Starter", "$29", "/ month",
         ["100 analyses / month", "VirusTotal integration", "OSINT investigation",
          "AI security reports", "Usage dashboard"],
         True),
        ("Business", "$99", "/ month",
         ["500 analyses / month", "Everything in Starter", "Priority support",
          "Team access", "Export + API access"],
         False),
        ("Enterprise", "Custom", "contact us",
         ["Unlimited analyses", "SLA guarantee", "White-label option",
          "Dedicated support", "Custom integrations"],
         False),
    ]
    cols = st.columns(4)
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

    st.markdown("<div style='height:60px'></div>", unsafe_allow_html=True)

    # BOTTOM CTA
    st.markdown("<div style='text-align:center;padding:40px 20px 20px'>"
                "<h2 style='font-size:clamp(1.5rem,3vw,2.2rem);font-weight:800;"
                "color:#f0f6ff;margin-bottom:12px'>Ready to secure your inbox?</h2>"
                "<p style='color:#475569;margin-bottom:32px;font-size:13px'>"
                "Join security teams already using PhishGuard to stop phishing "
                "attacks before they cause damage.</p></div>",
                unsafe_allow_html=True)

    if st.button("→ Start Free Trial", use_container_width=True,
                 type="primary", key="cta2"):
        st.session_state["show_login"] = True
        st.rerun()

    # FOOTER
    st.markdown("<div style='text-align:center;padding:40px 20px;"
                "border-top:1px solid rgba(255,255,255,0.05);margin-top:40px'>"
                "<span style='color:#334155;font-size:12px'>"
                "© 2025 PhishGuard AI · Built with Claude + Streamlit</span></div>",
                unsafe_allow_html=True)


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
        from src.password_reset import verify_reset_token, mark_token_used
        import sqlite3
        from pathlib import Path
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
                    db = Path(__file__).parent.parent / "data" / "phishguard.db"
                    conn = sqlite3.connect(str(db))
                    c = conn.cursor()
                    import hashlib
                    pw_hash = hashlib.sha256(new_pw.encode()).hexdigest()
                    c.execute("UPDATE tenants SET password_hash = ? WHERE username = ?",
                              (pw_hash, result["username"]))
                    conn.commit()
                    conn.close()
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
            st.toast("✅ Email verified! You can now scan emails.")
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
