import streamlit as st
from src.scheduler import (
    init_scheduler, create_schedule, list_schedules,
    delete_schedule, toggle_schedule,
)


def render_scheduler_ui(username: str):
    st.markdown("#### ⏰ Scheduled Scans")
    st.caption("Automatically scan connected mailboxes on a recurring schedule.")

    init_scheduler()
    schedules = list_schedules(username)

    col_s1, col_s2, col_s3, col_s4 = st.columns(4)
    with col_s1:
        mailbox = st.text_input("Mailbox", value="inbox", key="sched_mailbox",
                                help="IMAP mailbox folder name")
    with col_s2:
        interval = st.number_input("Interval (min)", min_value=5, value=60, step=5,
                                   key="sched_interval")
    with col_s3:
        max_per = st.number_input("Max per run", min_value=1, value=10,
                                  key="sched_max", help="Max emails to scan per run")
    with col_s4:
        if st.button("➕ Add Schedule", type="primary", use_container_width=True):
            create_schedule(username, mailbox=mailbox, interval_minutes=interval,
                            max_per_run=max_per)
            st.success(f"Schedule created: every {interval}min on '{mailbox}'")
            st.rerun()

    if schedules:
        st.markdown("##### Your Schedules")
        for s in schedules:
            status = "🟢 Active" if s["enabled"] else "🔴 Paused"
            col_a, col_b, col_c, col_d, col_e = st.columns([2, 1, 1, 1, 1])
            col_a.markdown(f"**{s['mailbox']}**")
            col_b.caption(f"Every {s['interval_minutes']}min")
            col_c.caption(status)
            col_d.caption(f"Max {s['max_per_run']}")
            if col_e.button("🗑", key=f"del_sched_{s['id']}"):
                delete_schedule(s["id"])
                st.rerun()
            if s["enabled"]:
                if col_e.button("⏸", key=f"pause_sched_{s['id']}"):
                    toggle_schedule(s["id"], False)
                    st.rerun()
            else:
                if col_e.button("▶", key=f"resume_sched_{s['id']}"):
                    toggle_schedule(s["id"], True)
                    st.rerun()
    else:
        st.info("No schedules yet. Create one above.")
