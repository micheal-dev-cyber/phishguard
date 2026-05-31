# src/auth.py
import streamlit as st
from src.tenants import verify_tenant, seed_admin_from_env, init_tenants


def _landing_page():
    """Landing page shown before login — uses Streamlit-native layout."""
    show_login = st.session_state.get("show_login", False)
    show_signup = st.session_state.get("show_signup", False)
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
                "By creating an account, you agree to our Terms of Service and Privacy Policy.</p>",
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
            from src.tenants import create_tenant
            from src.email_verify import create_verification, send_verification_email
            from src.env import ENV
            success = create_tenant(new_username.strip(), new_password, email=new_email.strip(), plan="trial")
            if not success:
                st.error("That username is already taken. Try a different one.")
            else:
                st.success("🎉 Account created! Let's get started.")
                try:
                    v = create_verification(new_username.strip(), new_email.strip())
                    base_url = getattr(ENV, "APP_URL", "http://localhost:8501")
                    verify_url = f"{base_url}/?verify={v['token']}"
                    send_verification_email(new_email.strip(), verify_url)
                    st.info("📧 We sent a verification email. Check your inbox (and spam folder).")
                except Exception:
                    pass
                st.session_state["authenticated"] = True
                st.session_state["username"] = new_username.strip()
                st.session_state["plan"] = "trial"
                st.session_state["is_admin"] = False
                st.session_state["email"] = new_email.strip()
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
                st.success("✅ Magic link on its way! Check your inbox (and spam folder).")
            except Exception as e:
                st.error(f"Couldn't send the magic link. Make sure SMTP is configured, or try logging in with your password instead. Details: {e}")
        else:
            st.warning("Enter the email address associated with your account.")

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


def _faq_items():
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
         "Yes. Business plans support team access, and Enterprise plans include unlimited analyses, SLA guarantees, "
         "white-label options, and custom integrations. Contact us for a demo."),
    ]
    return faqs

def _hero_page():
    # HERO
    st.markdown("<div style='padding:80px 20px 50px;text-align:center;"
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
                "margin-bottom:24px'>⬡ AI-Powered Phishing Defense</span>",
                unsafe_allow_html=True)

    st.markdown("<h1 style='font-size:clamp(2.2rem,4.5vw,4rem);font-weight:800;"
                "line-height:1.05;color:#f0f6ff;margin:0 auto 16px;"
                "max-width:750px;letter-spacing:-.02em'>"
                "Stop phishing attacks<br>"
                "<span style='background:linear-gradient(135deg,#3b82f6,#60a5fa,#93c5fd);"
                "-webkit-background-clip:text;-webkit-text-fill-color:transparent;"
                "background-clip:text'>before they reach your team.</span></h1>",
                unsafe_allow_html=True)

    st.markdown("<p style='color:#64748b;max-width:500px;margin:0 auto 32px;"
                "line-height:1.7;font-size:14px'>"
                "Real-time email analysis that detects malicious URLs, spoofed headers, "
                "and social engineering — with AI-generated threat reports in seconds.</p>",
                unsafe_allow_html=True)

    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
    with col_btn2:
        if st.button("→ Start Free Trial", use_container_width=True, type="primary"):
            st.session_state["show_signup"] = True
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    # TRUST BAR
    st.markdown("<div style='text-align:center;padding:20px 0 40px'>"
                "<span style='color:#475569;font-size:11px;letter-spacing:.12em;"
                "text-transform:uppercase'>Trusted by security teams worldwide</span>"
                "<div style='display:flex;justify-content:center;gap:32px;margin-top:16px;"
                "flex-wrap:wrap'>"
                "<span style='color:#334155;font-size:13px;font-weight:600'>◈ 10,000+ scans analyzed</span>"
                "<span style='color:#334155;font-size:13px;font-weight:600'>◈ 99% detection rate</span>"
                "<span style='color:#334155;font-size:13px;font-weight:600'>◈ 4 threat engines</span>"
                "<span style='color:#334155;font-size:13px;font-weight:600'>◈ 90+ vendor integrations</span>"
                "</div></div>", unsafe_allow_html=True)

    # STATS ROW
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

    st.markdown("<div style='height:50px'></div>", unsafe_allow_html=True)

    # TESTIMONIALS
    st.markdown("<div style='text-align:center;margin-bottom:40px'>"
                "<span style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase'>// What users say</span>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;margin-top:8px;margin-bottom:32px'>"
                "Loved by security professionals</h2></div>",
                unsafe_allow_html=True)

    testimonials = [
        ("PhishGuard caught a spear-phishing campaign our SIEM missed. The AI report was on my desk in under 3 seconds.",
         "Sarah Chen", "CISO, FinTech Corp"),
        ("The OSINT enrichment alone is worth the subscription. Domain WHOIS, geolocation, and registrar data automatically bundled into every scan.",
         "Marcus Rivera", "Security Engineer, CloudScale"),
        ("We reduced our SOC triage time by 60% after rolling out PhishGuard. The risk scoring is incredibly accurate.",
         "Dr. Amara Osei", "Director of IT Security, EduGlobal"),
    ]
    cols = st.columns(3)
    for col, (quote, name, role) in zip(cols, testimonials):
        with col:
            st.markdown(
                f"<div class='feature-card' style='display:flex;flex-direction:column;height:100%'>"
                f"<div style='color:#6b8cae;font-size:14px;line-height:1.7;margin-bottom:16px;flex:1'>"
                f"\"{quote}\"</div>"
                f"<div style='border-top:1px solid rgba(255,255,255,0.05);padding-top:12px'>"
                f"<div style='color:#e2e8f0;font-size:13px;font-weight:600'>{name}</div>"
                f"<div style='color:#475569;font-size:11px'>{role}</div></div></div>",
                unsafe_allow_html=True
            )

    st.markdown("<div style='height:50px'></div>", unsafe_allow_html=True)

    # FEATURES
    st.markdown("<h3 style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase;text-align:center;margin-bottom:12px'>"
                "// Capabilities</h3>", unsafe_allow_html=True)
    st.markdown("<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:40px'>"
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
    st.markdown("<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:40px'>"
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

    # FAQ
    st.markdown("<div style='max-width:700px;margin:0 auto 60px'>"
                "<h3 style='color:#3b82f6;font-size:11px;letter-spacing:.15em;"
                "text-transform:uppercase;text-align:center;margin-bottom:12px'>"
                "// FAQ</h3>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;text-align:center;margin-bottom:32px'>"
                "Frequently asked questions</h2>", unsafe_allow_html=True)

    faqs = _faq_items()
    for i, (question, answer) in enumerate(faqs):
        with st.expander(f"▸ {question}", expanded=False):
            st.markdown(f"<p style='color:#94a3b8;font-size:13px;line-height:1.7'>{answer}</p>",
                        unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # BOTTOM CTA
    st.markdown("<div style='text-align:center;padding:40px 20px 20px;"
                "background:linear-gradient(180deg,transparent,rgba(37,99,235,0.03))'>"
                "<h2 style='font-size:clamp(1.3rem,2.5vw,2rem);font-weight:800;"
                "color:#f0f6ff;margin-bottom:8px'>Ready to secure your inbox?</h2>"
                "<p style='color:#64748b;margin-bottom:28px;font-size:13px'>"
                "Join security teams already using PhishGuard to stop phishing "
                "attacks before they cause damage.</p>",
                unsafe_allow_html=True)

    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
    with col_btn2:
        if st.button("→ Start Free Trial", use_container_width=True,
                     type="primary", key="cta2"):
            st.session_state["show_signup"] = True
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    # FOOTER
    st.markdown("<div style='text-align:center;padding:40px 20px;"
                "border-top:1px solid rgba(255,255,255,0.05);margin-top:20px'>"
                "<span style='color:#334155;font-size:12px'>"
                "© 2026 PhishGuard AI · Built with Claude + Streamlit</span></div>",
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
