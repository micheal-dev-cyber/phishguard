import streamlit as st

ONBOARDING_STEPS = [
    {
        "title": "Welcome to PhishGuard AI",
        "icon": "🛡",
        "description": "You just took the first step toward protecting your inbox from phishing attacks. Let's get you set up — you'll run your first scan in under 2 minutes.",
        "action": ("🚀 Jump to Scan", lambda: st.session_state.update({"show_onboarding": False, "active_tab": 0})),
    },
    {
        "title": "How It Works",
        "icon": "🔍",
        "description": "PhishGuard uses 6 detection engines: heuristics, URL reputation, VirusTotal, OSINT, email header forensics, and social engineering detection. Paste any suspicious email and get a risk score in seconds.",
    },
    {
        "title": "Your First Scan",
        "icon": "📋",
        "description": "Ready? Go to the Scan tab, paste an email, and click Analyze. We've loaded a sample phishing email to try — just head to Scan and press the button.",
        "action": ("🔍 Take Me to Scan", lambda: st.session_state.update({"show_onboarding": False, "active_tab": 0})),
    },
    {
        "title": "Understanding Results",
        "icon": "📊",
        "description": "Each scan shows a risk score (0-100), severity level, and a detailed breakdown. Toggle 'Show technical details' for VirusTotal, OSINT, and psychological manipulation analysis. Generate PDF reports or STIX threat intel bundles.",
    },
    {
        "title": "You're Ready!",
        "icon": "🚀",
        "description": "Explore the Dashboard for analytics, check your billing usage, and upgrade when you need more capacity. The AI Copilot is always here to help. Your 14-day free trial includes 50 scans.",
    },
]


def render_onboarding(username: str):
    step = st.session_state.get("onboarding_step", 1)
    total = len(ONBOARDING_STEPS)
    idx = step - 1
    s = ONBOARDING_STEPS[idx]

    st.markdown("""
    <style>
    .block-container { max-width: 640px !important; }
    section[data-testid="stSidebar"] { display: none; }
    #MainMenu { visibility: hidden; }
    footer { display: none; }
    .stApp { background: #020818; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("<div style='padding:40px 0 20px'>", unsafe_allow_html=True)

    # Progress bar
    pct = int(step / total * 100)
    st.markdown(
        f"<div style='margin-bottom:32px'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:8px'>"
        f"<span style='color:#475569;font-size:11px;letter-spacing:.1em;text-transform:uppercase'>"
        f"Step {step} of {total}</span>"
        f"<span style='color:#3b82f6;font-size:11px;font-weight:600'>{pct}% complete</span></div>"
        f"<div style='background:#1e293b;border-radius:6px;height:6px;overflow:hidden'>"
        f"<div style='background:linear-gradient(90deg,#3b82f6,#6366f1);width:{pct}%;height:100%;"
        f"border-radius:6px;transition:width 0.3s ease'></div></div></div>",
        unsafe_allow_html=True
    )

    # Step indicator dots
    dots = []
    for i in range(total):
        if i + 1 == step:
            dots.append("<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#3b82f6;margin:0 4px'></span>")
        elif i + 1 < step:
            dots.append("<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#22c55e;margin:0 4px'></span>")
        else:
            dots.append("<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#1e293b;margin:0 4px'></span>")
    st.markdown(f"<div style='text-align:center;margin-bottom:40px'>{''.join(dots)}</div>",
                unsafe_allow_html=True)

    # Step content card
    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div style='background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.08);"
        f"border-radius:24px;padding:40px 36px;text-align:center'>"
        f"<div style='font-size:3.5rem;margin-bottom:16px'>{s['icon']}</div>"
        f"<h2 style='font-size:1.5rem;font-weight:800;color:#f0f6ff;margin-bottom:12px;"
        f"line-height:1.3'>{s['title']}</h2>"
        f"<p style='color:#94a3b8;font-size:14px;line-height:1.7;max-width:460px;margin:0 auto 32px'>"
        f"{s['description']}</p>",
        unsafe_allow_html=True
    )

    # Action button (if step has one)
    action = s.get("action")
    if action:
        label, _ = action
        if st.button(label, use_container_width=True, type="primary", key=f"onboarding_action_{step}"):
            _, fn = action
            fn()
            st.rerun()

    # Navigation buttons
    col_left, col_right = st.columns([1, 1])
    with col_left:
        if step > 1:
            if st.button("← Back", use_container_width=True, key="onboarding_back"):
                st.session_state["onboarding_step"] = step - 1
                st.rerun()
    with col_right:
        if step < total:
            if st.button("Continue →", use_container_width=True, type="primary" if not action else "secondary", key="onboarding_next"):
                st.session_state["onboarding_step"] = step + 1
                st.rerun()
        else:
            if st.button("🚀 Start Using PhishGuard", use_container_width=True, type="primary", key="onboarding_finish"):
                st.session_state.pop("show_onboarding", None)
                st.session_state.pop("onboarding_step", None)
                st.session_state["checklist_account"] = True
                st.rerun()

    # Skip link
    if st.button("Skip tutorial →", use_container_width=True, key="onboarding_skip"):
        st.session_state.pop("show_onboarding", None)
        st.session_state.pop("onboarding_step", None)
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
