import streamlit as st
from src.plugin_manager import (
    init_plugins, register_plugin, unregister_plugin,
    list_plugins, enable_plugin, disable_plugin,
)


def render_plugin_manager_ui():
    st.markdown("#### 🔌 Plugin Manager")
    st.caption("Register and manage custom analysis plugins from the plugins/ directory.")

    init_plugins()
    plugins = list_plugins()

    with st.expander("➕ Register New Plugin", expanded=False):
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            p_name = st.text_input("Plugin name", placeholder="my_detector", key="pl_name")
            p_module = st.text_input("Module path", placeholder="my_detector", key="pl_module",
                                     help="Filename in plugins/ dir (without .py)")
        with col_p2:
            p_handler = st.text_input("Handler function", value="detect", key="pl_handler",
                                      help="Function name in the plugin file")
            p_desc = st.text_input("Description", placeholder="Detects X", key="pl_desc")
        if st.button("Register", type="primary", use_container_width=True) and p_name and p_module:
            register_plugin(p_name, p_module, handler=p_handler, description=p_desc)
            st.success(f"Plugin '{p_name}' registered")
            st.rerun()

    if plugins:
        st.markdown("##### Installed Plugins")
        for p in plugins:
            status = "🟢 Enabled" if p["enabled"] else "🔴 Disabled"
            col_a, col_b, col_c, col_d = st.columns([2, 2, 1, 1])
            col_a.markdown(f"**{p['name']}**")
            col_b.caption(f"{p.get('description', '')[:50]} v{p.get('version', '1.0')}")
            col_c.markdown(status)
            if p["enabled"]:
                if col_d.button("⏹ Disable", key=f"dis_pl_{p['id']}", use_container_width=True):
                    disable_plugin(p["name"])
                    st.rerun()
            else:
                if col_d.button("▶ Enable", key=f"en_pl_{p['id']}", use_container_width=True):
                    enable_plugin(p["name"])
                    st.rerun()
            if col_d.button("🗑", key=f"del_pl_{p['id']}"):
                unregister_plugin(p["name"])
                st.rerun()
    else:
        st.info("No plugins registered. Add .py files to the plugins/ directory and register them above.")
