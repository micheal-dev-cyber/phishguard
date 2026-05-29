import streamlit as st
from src.onboarding import get_onboarding_steps, complete_onboarding_step, activate_plan, PLAN_PRICING


def render_onboarding_wizard(username: str):
    steps = get_onboarding_steps(username)
    all_done = all(s["done"] for s in steps)

    if all_done:
        return

    st.markdown("""
    <style>
    .onboarding-card {
        background: linear-gradient(135deg, #1e3a5f 0%, #111827 100%);
        border: 1px solid #2563eb;
        border-radius: 16px;
        padding: 24px;
        margin: 16px 0;
    }
    .onboarding-step {
        display: flex; align-items: center;
        padding: 8px 12px; margin: 4px 0;
        background: rgba(255,255,255,0.02);
        border-radius: 8px;
    }
    .onboarding-step.done { opacity: 0.5; }
    .onboarding-step-number {
        width: 28px; height: 28px; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-weight: 700; font-size: 13px; margin-right: 12px; flex-shrink: 0;
    }
    </style>
    """, unsafe_allow_html=True)

    with st.container():
        st.markdown(f"""
        <div class="onboarding-card">
            <h3 style="color:#60a5fa;margin:0 0 4px 0">🚀 Welcome to PhishGuard</h3>
            <p style="color:#94a3b8;font-size:13px;margin:0 0 16px 0">
                Complete these steps to get the most out of the platform.
            </p>
        </div>
        """, unsafe_allow_html=True)

        for i, step in enumerate(steps, 1):
            done = step["done"]
            color = "#22c55e" if done else "#475569"
            icon = "✓" if done else str(i)
            bg = "#064e3b" if done else "#1e293b"

            st.markdown(f"""
            <div class="onboarding-step {'done' if done else ''}">
                <div class="onboarding-step-number" style="background:{bg};color:{color}">{icon}</div>
                <div style="flex:1">
                    <span style="color:{'#22c55e' if done else '#e2e8f0'};font-weight:600;font-size:14px">
                        {step['label']}
                    </span>
                    <span style="color:#475569;font-size:11px;margin-left:8px">
                        {'✅ Done' if done else '⏳ Pending'}
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            if not done and i == _get_current_step_index(steps):
                if step["step"] == "connect_email":
                    _render_email_step(username, step)
                elif step["step"] == "first_scan":
                    _render_scan_step(username, step)
                elif step["step"] == "configure_alerts":
                    _render_alerts_step(username, step)
                elif step["step"] == "invite_team":
                    _render_invite_step(username, step)
                elif step["step"] == "weekly_report":
                    _render_report_step(username, step)

        st.progress(sum(1 for s in steps if s["done"]) / max(len(steps), 1))
        st.caption(f"{sum(1 for s in steps if s['done'])} / {len(steps)} steps complete")

        # Plan selector at bottom of wizard
        st.divider()
        st.markdown("##### 💳 Choose Your Plan")
        plan_options = {v["label"]: k for k, v in PLAN_PRICING.items()}
        selected_label = st.selectbox("Plan", list(plan_options.keys()), key="onboard_plan")
        selected_plan = plan_options[selected_label]
        pricing = PLAN_PRICING[selected_plan]
        price_str = "Custom pricing" if pricing.get("custom") else f"${pricing['price']}/mo"
        st.markdown(
            f"<p style='color:#94a3b8;font-size:13px'>{pricing['scans']} scans/month — {price_str}</p>",
            unsafe_allow_html=True,
        )
        if st.button("Activate Plan", type="primary", use_container_width=True):
            activate_plan(username, selected_plan)
            st.success(f"{selected_label} plan activated!")
            st.rerun()

        if st.button("✕ Dismiss", use_container_width=True):
            st.session_state["onboarding_dismissed"] = True
            st.rerun()


def _get_current_step_index(steps: list) -> int:
    for i, s in enumerate(steps):
        if not s["done"]:
            return i + 1
    return len(steps)


def _complete(username, step):
    complete_onboarding_step(username, step)
    st.rerun()


def _render_email_step(username, step):
    st.text_input("Email address", placeholder="you@company.com",
                  key="onboard_email", label_visibility="collapsed")
    if st.button("📩 Send Verification", key="onboard_email_btn", use_container_width=True):
        _complete(username, step["step"])


def _render_scan_step(username, step):
    st.text_area("Paste an email to scan", placeholder="Paste suspicious email content...",
                 height=100, key="onboard_scan_text", label_visibility="collapsed")
    if st.button("🔍 Run First Scan", key="onboard_scan_btn", use_container_width=True):
        _complete(username, step["step"])


def _render_alerts_step(username, step):
    st.markdown("Connect a notification channel:")
    if st.button("🔗 Connect Slack", key="onboard_slack", use_container_width=True):
        _complete(username, step["step"])
    if st.button("🔗 Connect Teams", key="onboard_teams", use_container_width=True):
        _complete(username, step["step"])


def _render_invite_step(username, step):
    col_i1, col_i2 = st.columns([2, 1])
    with col_i1:
        invite_user = st.text_input("Username to invite", placeholder="colleague@company.com",
                                    key="onboard_invite", label_visibility="collapsed")
    with col_i2:
        if st.button("📨 Invite", key="onboard_invite_btn", use_container_width=True):
            _complete(username, step["step"])


def _render_report_step(username, step):
    st.markdown("Get a weekly PDF summary of threats and trends sent to your inbox.")
    if st.button("📊 Enable Weekly Report", key="onboard_report_btn", use_container_width=True):
        _complete(username, step["step"])
