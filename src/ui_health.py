import streamlit as st

from src.health import (
    get_health_summary,
    list_backups,
    run_backup,
)


def render_health_ui():
    st.markdown("#### 🩺 System Health")
    st.caption("Monitor system components and manage database backups.")

    if st.button("🔄 Run Health Check", type="primary", use_container_width=True):
        summary = get_health_summary()
        overall = summary["status"]
        color = "#22c55e" if overall == "healthy" else "#ff8800"
        st.markdown(f"<h3 style='color:{color}'>Status: {overall.upper()}</h3>", unsafe_allow_html=True)
        for chk in summary["checks"]:
            c = "#22c55e" if chk["status"] == "healthy" else "#ff8800" if chk["status"] == "degraded" else "#ff4444"
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;padding:6px 10px;"
                f"background:#111827;border:1px solid #1e3a5f;border-radius:6px;margin:3px 0'>"
                f"<span>{chk['component']}</span>"
                f"<span style='color:{c}'>{chk['status'].upper()}</span>"
                f"<span style='color:#94a3b8;font-size:12px'>{chk['message']}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

    st.divider()
    st.markdown("#### 💾 Database Backups")
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("📀 Create Backup Now", type="primary", use_container_width=True):
            result = run_backup()
            if result["success"]:
                st.success(f"Backup created: {result['size_mb']}MB")
            else:
                st.error(result.get("error", "Backup failed"))
    with col_b:
        backups = list_backups()
        if backups:
            st.caption(f"{len(backups)} backups available")
            for b in backups[:5]:
                st.text(f"{b['filename']} ({b['size_mb']}MB)")
        else:
            st.caption("No backups yet")
