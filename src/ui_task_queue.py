import logging
import time

import streamlit as st

logger = logging.getLogger("ui-task-queue")


def render_task_queue_ui():
    st.markdown("## 📋 Task Queue Monitor")
    st.markdown(
        "<p style='color:#64748b;margin-top:-8px'>Background jobs scheduled and processing. "
        "Long-running tasks (email analysis, URL sandbox) run on a background worker so the UI stays responsive.</p>",
        unsafe_allow_html=True,
    )

    try:
        from src.task_queue import _update_status, get_pending_count, get_tasks

        pending = get_pending_count()

        col1, col2, col3 = st.columns(3)
        col1.markdown(
            f"<div class='stat-card'><div style='font-size:1.5rem;font-weight:900;color:#eab308'>{pending}</div>"
            f"<div style='color:#64748b;font-size:0.85rem'>Pending</div></div>",
            unsafe_allow_html=True,
        )
        col2.markdown(
            f"<div class='stat-card'><div style='font-size:1.5rem;font-weight:900;color:#3b82f6'>"
            f"{sum(1 for t in get_tasks(limit=500, status='running') if t)}</div>"
            f"<div style='color:#64748b;font-size:0.85rem'>Running</div></div>",
            unsafe_allow_html=True,
        )
        col3.markdown(
            f"<div class='stat-card'><div style='font-size:1.5rem;font-weight:900;color:#ef4444'>"
            f"{sum(1 for t in get_tasks(limit=500, status='failed') if t)}</div>"
            f"<div style='color:#64748b;font-size:0.85rem'>Failed</div></div>",
            unsafe_allow_html=True,
        )

        st.divider()

        tasks = get_tasks(limit=50)
        if not tasks:
            st.info("No tasks in the queue yet.")
            return

        status_colors = {
            "pending": "#eab308",
            "running": "#3b82f6",
            "completed": "#22c55e",
            "failed": "#ef4444",
        }

        for t in tasks:
            color = status_colors.get(t["status"], "#94a3b8")
            expand = t["status"] in ("failed", "running")
            with st.expander(
                f"<span style='color:{color}'>●</span> "
                f"{t['task_name']} #<strong>{t['id']}</strong> "
                f"<span style='color:{color}'>{t['status']}</span>",
                expanded=expand,
            ):
                cols = st.columns(4)
                cols[0].markdown(f"**Created:** {t.get('created_at', 'N/A')[:19]}")
                cols[1].markdown(f"**Started:** {t.get('started_at', 'N/A')[:19]}")
                cols[2].markdown(f"**Completed:** {t.get('completed_at', 'N/A')[:19]}")
                cols[3].markdown(f"**Retries:** {t.get('retry_count', 0)}")
                if t.get("error"):
                    st.error(t["error"])
    except Exception as e:
        st.warning(f"Task queue unavailable: {e}")
