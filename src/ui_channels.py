import streamlit as st

from src.notification_channels import (
    SUPPORTED_CHANNELS,
    delete_channel,
    enable_channel,
    get_channels,
    init_channels,
    set_channel,
)


def render_notification_channels_ui(username: str):
    st.markdown("#### 🔔 Notification Channels")
    st.caption("Connect Slack, Teams, Discord, or PagerDuty for real-time alerts.")

    init_channels()
    channels = get_channels(username)

    col_a, col_b = st.columns(2)
    with col_a:
        ch_type = st.selectbox("Channel", SUPPORTED_CHANNELS, key="ch_type",
                               format_func=lambda x: x.title())
    with col_b:
        ch_url = st.text_input("Webhook URL",
                               placeholder="https://hooks.slack.com/...",
                               key="ch_url_input")

    col_c, col_d = st.columns(2)
    with col_c:
        ch_label = st.text_input("Display name (optional)", key="ch_label")
    with col_d:
        ch_notify = st.text_input("Notify on", value="critical,high",
                                  key="ch_notify",
                                  help="Comma-separated: critical,high,medium,low,info")

    if st.button("💾 Save Channel", type="primary", use_container_width=True) and ch_url:
        set_channel(username, ch_type, ch_url, display_name=ch_label, notify_on=ch_notify)
        st.success(f"{ch_type.title()} channel configured!")
        st.rerun()

    if channels:
        st.markdown("##### Connected Channels")
        for ch in channels:
            status = "🟢 Active" if ch["enabled"] else "🔴 Disabled"
            col_a, col_b, col_c, col_d = st.columns([1, 2, 2, 1])
            icon = {"slack": "💬", "teams": "💼", "discord": "🎮", "pagerduty": "📟"}
            col_a.markdown(icon.get(ch["channel_type"], "🔔"))
            col_b.markdown(f"**{ch['channel_type'].title()}**")
            col_c.caption(f"Notify: {ch.get('notify_on', 'critical,high')}")
            col_d.markdown(status)
            if ch["enabled"]:
                if col_d.button("⏹", key=f"dis_ch_{ch['id']}"):
                    enable_channel(username, ch["channel_type"], False)
                    st.rerun()
            else:
                if col_d.button("▶", key=f"en_ch_{ch['id']}"):
                    enable_channel(username, ch["channel_type"], True)
                    st.rerun()
            if col_d.button("🗑", key=f"del_ch_{ch['id']}"):
                delete_channel(username, ch["channel_type"])
                st.rerun()
