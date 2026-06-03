import streamlit as st

from src.webhook_routing import (
    EVENT_TYPES,
    delete_webhook_route,
    enable_route,
    get_webhook_routes,
    init_webhook_routes,
    set_webhook_route,
)


def render_webhook_routing_ui(username: str):
    st.markdown("#### 🔀 Granular Webhook Routing")
    st.caption("Configure different webhook URLs for different event types.")

    init_webhook_routes()
    routes = get_webhook_routes(username)

    with st.expander("➕ Add Route", expanded=not bool(routes)):
        col_a, col_b = st.columns(2)
        with col_a:
            evt = st.selectbox("Event type", EVENT_TYPES, key="wh_evt")
        with col_b:
            wh_url = st.text_input("Webhook URL", placeholder="https://hooks.example.com/...", key="wh_url")
        if st.button("Save Route", type="primary", use_container_width=True) and wh_url:
            set_webhook_route(username, evt, wh_url)
            st.success(f"Route for '{evt}' saved")
            st.rerun()

    if routes:
        st.markdown("##### Configured Routes")
        for r in routes:
            status = "🟢" if r["enabled"] else "🔴"
            col_a, col_b, col_c = st.columns([2, 3, 1])
            col_a.markdown(f"{status} **{r['event_type']}**")
            col_b.code(r["webhook_url"], language="text")
            if col_c.button("🗑", key=f"del_route_{r['id']}"):
                delete_webhook_route(username, r["event_type"])
                st.rerun()
            if r["enabled"]:
                if col_c.button("⏹", key=f"dis_route_{r['id']}"):
                    enable_route(r["id"], False)
                    st.rerun()
            else:
                if col_c.button("▶", key=f"en_route_{r['id']}"):
                    enable_route(r["id"], True)
                    st.rerun()
