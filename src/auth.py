# src/auth.py
import streamlit as st
from src.tenants import verify_tenant, seed_from_secrets, init_tenants


def _landing_page():
    """Full landing page shown before login."""
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        background-color: #020818 !important;
    }
    .block-container {
        padding: 0 !important;
        max-width: 100% !important;
    }
    section[data-testid="stSidebar"] { display: none; }

    /* ── HERO ── */
    .pg-hero {
        min-height: 100vh;
        background: #020818;
        background-image:
            radial-gradient(ellipse 80% 50% at 50% -10%, rgba(37,99,235,0.18) 0%, transparent 70%),
            radial-gradient(ellipse 40% 30% at 80% 20%, rgba(59,130,246,0.08) 0%, transparent 60%);
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 80px 24px 60px;
        position: relative;
        overflow: hidden;
    }
    .pg-grid {
        position: absolute;
        inset: 0;
        background-image:
            linear-gradient(rgba(37,99,235,0.06) 1px, transparent 1px),
            linear-gradient(90deg, rgba(37,99,235,0.06) 1px, transparent 1px);
        background-size: 60px 60px;
        mask-image: radial-gradient(ellipse 80% 80% at 50% 50%, black 20%, transparent 100%);
    }
    .pg-badge {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        font-weight: 500;
        letter-spacing: 0.15em;
        color: #3b82f6;
        background: rgba(37,99,235,0.1);
        border: 1px solid rgba(59,130,246,0.25);
        border-radius: 100px;
        padding: 6px 16px;
        margin-bottom: 32px;
        text-transform: uppercase;
    }
    .pg-headline {
        font-family: 'Syne', sans-serif;
        font-size: clamp(2.8rem, 6vw, 5rem);
        font-weight: 800;
        line-height: 1.05;
        text-align: center;
        color: #f0f6ff;
        margin: 0 0 24px;
        max-width: 820px;
        letter-spacing: -0.02em;
    }
    .pg-headline span {
        background: linear-gradient(135deg, #3b82f6 0%, #60a5fa 50%, #93c5fd 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    .pg-sub {
        font-family: 'JetBrains Mono', monospace;
        font-size: 15px;
        color: #64748b;
        text-align: center;
        max-width: 540px;
        line-height: 1.7;
        margin: 0 0 48px;
    }
    .pg-cta-row {
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
        justify-content: center;
        margin-bottom: 80px;
    }
    .pg-btn-primary {
        font-family: 'Syne', sans-serif;
        font-weight: 700;
        font-size: 15px;
        background: #2563eb;
        color: #fff;
        border: none;
        border-radius: 10px;
        padding: 14px 32px;
        cursor: pointer;
        transition: all 0.2s;
        text-decoration: none;
        display: inline-block;
        box-shadow: 0 0 40px rgba(37,99,235,0.35);
    }
    .pg-btn-primary:hover {
        background: #1d4ed8;
        transform: translateY(-1px);
        box-shadow: 0 0 60px rgba(37,99,235,0.5);
    }
    .pg-btn-ghost {
        font-family: 'Syne', sans-serif;
        font-weight: 600;
        font-size: 15px;
        background: transparent;
        color: #94a3b8;
        border: 1px solid rgba(148,163,184,0.2);
        border-radius: 10px;
        padding: 14px 32px;
        cursor: pointer;
        transition: all 0.2s;
        text-decoration: none;
        display: inline-block;
    }
    .pg-btn-ghost:hover {
        border-color: rgba(148,163,184,0.5);
        color: #cbd5e1;
    }

    /* ── STATS BAR ── */
    .pg-stats {
        display: flex;
        gap: 48px;
        flex-wrap: wrap;
        justify-content: center;
        padding: 32px 48px;
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 16px;
        margin-bottom: 0;
    }
    .pg-stat {
        text-align: center;
    }
    .pg-stat-num {
        font-family: 'Syne', sans-serif;
        font-size: 2rem;
        font-weight: 800;
        color: #f0f6ff;
        line-height: 1;
    }
    .pg-stat-num span { color: #3b82f6; }
    .pg-stat-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #475569;
        margin-top: 4px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }

    /* ── FEATURES ── */
    .pg-section {
        background: #020818;
        padding: 100px 24px;
    }
    .pg-section-inner {
        max-width: 1100px;
        margin: 0 auto;
    }
    .pg-section-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #3b82f6;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        text-align: center;
        margin-bottom: 16px;
    }
    .pg-section-title {
        font-family: 'Syne', sans-serif;
        font-size: clamp(1.8rem, 3.5vw, 2.8rem);
        font-weight: 800;
        color: #f0f6ff;
        text-align: center;
        margin: 0 0 64px;
        letter-spacing: -0.02em;
    }
    .pg-features {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 24px;
    }
    .pg-feature {
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 16px;
        padding: 32px;
        transition: all 0.25s;
        position: relative;
        overflow: hidden;
    }
    .pg-feature::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(59,130,246,0.4), transparent);
        opacity: 0;
        transition: opacity 0.25s;
    }
    .pg-feature:hover { border-color: rgba(59,130,246,0.25); transform: translateY(-2px); }
    .pg-feature:hover::before { opacity: 1; }
    .pg-feature-icon {
        font-size: 2rem;
        margin-bottom: 16px;
        display: block;
    }
    .pg-feature-title {
        font-family: 'Syne', sans-serif;
        font-size: 1.1rem;
        font-weight: 700;
        color: #e2e8f0;
        margin-bottom: 10px;
    }
    .pg-feature-desc {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12.5px;
        color: #475569;
        line-height: 1.7;
    }

    /* ── PRICING ── */
    .pg-pricing {
        background: rgba(255,255,255,0.015);
        border-top: 1px solid rgba(255,255,255,0.05);
        border-bottom: 1px solid rgba(255,255,255,0.05);
        padding: 100px 24px;
    }
    .pg-plans {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 24px;
        max-width: 1000px;
        margin: 0 auto;
    }
    .pg-plan {
        background: #040f24;
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 20px;
        padding: 36px 28px;
        position: relative;
        transition: transform 0.2s;
    }
    .pg-plan:hover { transform: translateY(-3px); }
    .pg-plan.featured {
        border-color: rgba(59,130,246,0.5);
        background: linear-gradient(160deg, #040f24, #071530);
        box-shadow: 0 0 60px rgba(37,99,235,0.15);
    }
    .pg-plan-badge {
        position: absolute;
        top: -12px;
        left: 50%;
        transform: translateX(-50%);
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        font-weight: 500;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #020818;
        background: #3b82f6;
        padding: 4px 14px;
        border-radius: 100px;
    }
    .pg-plan-name {
        font-family: 'Syne', sans-serif;
        font-size: 1.1rem;
        font-weight: 700;
        color: #94a3b8;
        margin-bottom: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    .pg-plan-price {
        font-family: 'Syne', sans-serif;
        font-size: 2.6rem;
        font-weight: 800;
        color: #f0f6ff;
        line-height: 1;
        margin-bottom: 4px;
    }
    .pg-plan-period {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #475569;
        margin-bottom: 28px;
    }
    .pg-plan-features {
        list-style: none;
        padding: 0;
        margin: 0 0 32px;
    }
    .pg-plan-features li {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12.5px;
        color: #64748b;
        padding: 7px 0;
        border-bottom: 1px solid rgba(255,255,255,0.04);
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .pg-plan-features li::before {
        content: '→';
        color: #3b82f6;
        flex-shrink: 0;
    }

    /* ── LOGIN FORM ── */
    .pg-login-wrap {
        background: #020818;
        padding: 100px 24px;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .pg-login-box {
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 24px;
        padding: 52px 44px;
        width: 100%;
        max-width: 440px;
        box-shadow: 0 40px 120px rgba(0,0,0,0.5);
    }
    .pg-login-title {
        font-family: 'Syne', sans-serif;
        font-size: 1.8rem;
        font-weight: 800;
        color: #f0f6ff;
        text-align: center;
        margin-bottom: 8px;
    }
    .pg-login-sub {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #475569;
        text-align: center;
        margin-bottom: 36px;
    }

    /* ── FOOTER ── */
    .pg-footer {
        background: #020818;
        border-top: 1px solid rgba(255,255,255,0.05);
        padding: 40px 24px;
        text-align: center;
    }
    .pg-footer-text {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #334155;
    }

    /* Override Streamlit button in login form */
    div[data-testid="stButton"] > button {
        background: #2563eb !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        font-family: 'Syne', sans-serif !important;
        font-weight: 700 !important;
        font-size: 15px !important;
        padding: 12px 0 !important;
        box-shadow: 0 0 30px rgba(37,99,235,0.3) !important;
        transition: all 0.2s !important;
    }
    div[data-testid="stButton"] > button:hover {
        background: #1d4ed8 !important;
        box-shadow: 0 0 50px rgba(37,99,235,0.5) !important;
    }
    div[data-testid="stTextInput"] input {
        background: rgba(255,255,255,0.04) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 10px !important;
        color: #e2e8f0 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 14px !important;
    }
    div[data-testid="stTextInput"] input:focus {
        border-color: rgba(59,130,246,0.5) !important;
        box-shadow: 0 0 0 3px rgba(37,99,235,0.15) !important;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Show login form or landing page based on state ──
    show_login = st.session_state.get("show_login", False)

    if show_login:
        # LOGIN FORM
        st.markdown("<div class='pg-login-wrap'>", unsafe_allow_html=True)
        st.markdown("""
        <div class='pg-login-box'>
          <div class='pg-login-title'>🛡 PhishGuard</div>
          <div class='pg-login-sub'>// SECURE ACCESS PORTAL</div>
        </div>
        """, unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            username = st.text_input("Username", placeholder="username",
                                     label_visibility="collapsed")
            password = st.text_input("Password", type="password",
                                     placeholder="password",
                                     label_visibility="collapsed")
            login_btn = st.button("→ Access Platform", use_container_width=True)

            if login_btn:
                if not username or not password:
                    st.error("Enter username and password.")
                else:
                    tenant = verify_tenant(username, password)
                    if tenant:
                        if not tenant["is_active"]:
                            st.error("Account suspended. Contact support.")
                        else:
                            st.session_state["authenticated"] = True
                            st.session_state["username"]      = tenant["username"]
                            st.session_state["plan"]          = tenant["plan"]
                            st.session_state["is_admin"]      = bool(tenant["is_admin"])
                            st.session_state["email"]         = tenant["email"]
                            st.session_state.pop("show_login", None)
                            st.rerun()
                    else:
                        # Fallback: Streamlit secrets
                        try:
                            stored = st.secrets.get("passwords", {})
                            if username in stored and stored[username] == password:
                                st.session_state["authenticated"] = True
                                st.session_state["username"]      = username
                                st.session_state["plan"]          = "starter"
                                st.session_state["is_admin"]      = (username == "admin")
                                st.session_state["email"]         = ""
                                st.session_state.pop("show_login", None)
                                st.rerun()
                            else:
                                st.error("Invalid credentials.")
                        except Exception:
                            st.error("Invalid credentials.")

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("← Back to home", use_container_width=True):
                st.session_state["show_login"] = False
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

    else:
        # ── LANDING PAGE ──

        # HERO
        st.markdown("""
        <div class='pg-hero'>
          <div class='pg-grid'></div>
          <div class='pg-badge'>⬡ AI-Powered Cybersecurity Platform</div>
          <h1 class='pg-headline'>
            Stop phishing attacks<br><span>before they land.</span>
          </h1>
          <p class='pg-sub'>
            PhishGuard scans emails in real-time — detecting threats,
            analyzing URLs, running OSINT, and generating AI security reports
            in seconds.
          </p>
        </div>
        """, unsafe_allow_html=True)

        # CTA button via Streamlit (so it works)
        col1, col2, col3 = st.columns([2, 1, 2])
        with col2:
            if st.button("→ Get Started", use_container_width=True):
                st.session_state["show_login"] = True
                st.rerun()

        # STATS
        st.markdown("""
        <div style='background:#020818;padding:0 24px 80px;display:flex;justify-content:center'>
          <div class='pg-stats'>
            <div class='pg-stat'>
              <div class='pg-stat-num'>99<span>%</span></div>
              <div class='pg-stat-label'>Detection rate</div>
            </div>
            <div class='pg-stat'>
              <div class='pg-stat-num'>&lt;2<span>s</span></div>
              <div class='pg-stat-label'>Scan time</div>
            </div>
            <div class='pg-stat'>
              <div class='pg-stat-num'>4<span>+</span></div>
              <div class='pg-stat-label'>Threat engines</div>
            </div>
            <div class='pg-stat'>
              <div class='pg-stat-num'>24<span>/7</span></div>
              <div class='pg-stat-label'>Always on</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # FEATURES
        st.markdown("""
        <div class='pg-section'>
          <div class='pg-section-inner'>
            <div class='pg-section-label'>// Capabilities</div>
            <h2 class='pg-section-title'>Everything you need to<br>defend your inbox</h2>
            <div class='pg-features'>
              <div class='pg-feature'>
                <span class='pg-feature-icon'>🔍</span>
                <div class='pg-feature-title'>AI Threat Detection</div>
                <div class='pg-feature-desc'>
                  Multi-layer analysis combining keyword heuristics, URL pattern
                  matching, header forensics and social engineering detection.
                </div>
              </div>
              <div class='pg-feature'>
                <span class='pg-feature-icon'>🌐</span>
                <div class='pg-feature-title'>VirusTotal Integration</div>
                <div class='pg-feature-desc'>
                  Every URL cross-referenced against 90+ security vendors in
                  real-time. Malicious links flagged instantly with vendor detail.
                </div>
              </div>
              <div class='pg-feature'>
                <span class='pg-feature-icon'>🔎</span>
                <div class='pg-feature-title'>OSINT Engine</div>
                <div class='pg-feature-desc'>
                  Domain age, registrar, geolocation, WHOIS and infrastructure
                  risk scoring — automatic for every suspicious sender.
                </div>
              </div>
              <div class='pg-feature'>
                <span class='pg-feature-icon'>📊</span>
                <div class='pg-feature-title'>Risk Scoring</div>
                <div class='pg-feature-desc'>
                  Weighted 0–100 risk score with severity classification.
                  Visual gauge, keyword breakdown, and verdict in one view.
                </div>
              </div>
              <div class='pg-feature'>
                <span class='pg-feature-icon'>📄</span>
                <div class='pg-feature-title'>PDF Security Reports</div>
                <div class='pg-feature-desc'>
                  One-click export of full threat reports — shareable with
                  IT teams, management, or compliance auditors.
                </div>
              </div>
              <div class='pg-feature'>
                <span class='pg-feature-icon'>🤖</span>
                <div class='pg-feature-title'>AI Security Narrative</div>
                <div class='pg-feature-desc'>
                  Claude AI writes a plain-English threat assessment explaining
                  every indicator and recommending exact next steps.
                </div>
              </div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # PRICING
        st.markdown("""
        <div class='pg-pricing'>
          <div class='pg-section-inner'>
            <div class='pg-section-label'>// Pricing</div>
            <h2 class='pg-section-title'>Simple, transparent pricing</h2>
            <div class='pg-plans'>

              <div class='pg-plan'>
                <div class='pg-plan-name'>Trial</div>
                <div class='pg-plan-price'>Free</div>
                <div class='pg-plan-period'>forever</div>
                <ul class='pg-plan-features'>
                  <li>10 analyses / month</li>
                  <li>URL scanning</li>
                  <li>Risk scoring</li>
                  <li>PDF export</li>
                </ul>
              </div>

              <div class='pg-plan featured'>
                <div class='pg-plan-badge'>Most Popular</div>
                <div class='pg-plan-name'>Starter</div>
                <div class='pg-plan-price'>$29</div>
                <div class='pg-plan-period'>/ month</div>
                <ul class='pg-plan-features'>
                  <li>100 analyses / month</li>
                  <li>VirusTotal integration</li>
                  <li>OSINT investigation</li>
                  <li>AI security reports</li>
                  <li>Usage dashboard</li>
                </ul>
              </div>

              <div class='pg-plan'>
                <div class='pg-plan-name'>Business</div>
                <div class='pg-plan-price'>$99</div>
                <div class='pg-plan-period'>/ month</div>
                <ul class='pg-plan-features'>
                  <li>500 analyses / month</li>
                  <li>Everything in Starter</li>
                  <li>Priority support</li>
                  <li>Team access</li>
                  <li>Export + API access</li>
                </ul>
              </div>

              <div class='pg-plan'>
                <div class='pg-plan-name'>Enterprise</div>
                <div class='pg-plan-price'>Custom</div>
                <div class='pg-plan-period'>contact us</div>
                <ul class='pg-plan-features'>
                  <li>Unlimited analyses</li>
                  <li>SLA guarantee</li>
                  <li>White-label option</li>
                  <li>Dedicated support</li>
                  <li>Custom integrations</li>
                </ul>
              </div>

            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # BOTTOM CTA
        st.markdown("""
        <div class='pg-section' style='padding:80px 24px'>
          <div style='text-align:center;max-width:600px;margin:0 auto'>
            <h2 style='font-family:Syne,sans-serif;font-size:2.4rem;font-weight:800;
                       color:#f0f6ff;margin-bottom:16px;letter-spacing:-0.02em'>
              Ready to secure your inbox?
            </h2>
            <p style='font-family:JetBrains Mono,monospace;font-size:13px;
                      color:#475569;margin-bottom:40px'>
              Join security teams already using PhishGuard to stop phishing
              attacks before they cause damage.
            </p>
          </div>
        </div>
        """, unsafe_allow_html=True)

        col1, col2, col3 = st.columns([2, 1, 2])
        with col2:
            if st.button("→ Start Free Trial", use_container_width=True, key="cta2"):
                st.session_state["show_login"] = True
                st.rerun()

        # FOOTER
        st.markdown("""
        <div class='pg-footer'>
          <div class='pg-footer-text'>
            © 2025 PhishGuard AI · Built with Claude + Streamlit
          </div>
        </div>
        """, unsafe_allow_html=True)


def check_password() -> bool:
    if st.session_state.get("authenticated"):
        return True
    init_tenants()
    seed_from_secrets()
    _landing_page()
    return False


def logout():
    for key in ["authenticated", "username", "plan", "is_admin", "email"]:
        st.session_state.pop(key, None)
    st.rerun()