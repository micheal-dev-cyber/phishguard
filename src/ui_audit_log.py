import streamlit as st

from src.db import get_connection


def render_audit_log_tab():
    st.markdown("#### 📋 Audit Log")
    st.caption("Track all admin actions, configuration changes, and security events.")

    col_f1, col_f2, col_f3 = st.columns([1, 1, 2])
    with col_f1:
        limit = st.number_input("Max entries", 10, 500, 100, step=10, key="audit_limit")
    with col_f2:
        action_filter = st.text_input("Action filter", placeholder="delete, invite, update...",
                                      key="audit_filter", label_visibility="collapsed")
    with col_f3:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()

    if action_filter:
        kw = action_filter.lower()
        rows = [r for r in rows if kw in (r["action"] or "").lower()
                or kw in (r["details"] or "").lower()
                or kw in (r["username"] or "").lower()]

    if not rows:
        st.info("No matching audit log entries.")
        return

    data = []
    for r in rows:
        data.append({
            "ID": r["id"],
            "Timestamp": r["timestamp"][:19] if r["timestamp"] else "",
            "User": r["username"],
            "Action": r["action"],
            "Details": (r["details"] or "")[:80],
            "IP": r.get("ip_address", ""),
        })

    st.dataframe(data, use_container_width=True, hide_index=True)

    cols = st.columns([1, 1])
    with cols[0]:
        if st.button("📥 Export CSV", use_container_width=True):
            import csv
            import io
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["ID", "Timestamp", "User", "Action", "Details", "IP"])
            for r in data:
                w.writerow([r["ID"], r["Timestamp"], r["User"], r["Action"], r["Details"], r["IP"]])
            st.download_button("💾 Download", buf.getvalue(), "audit_log.csv",
                               "text/csv", use_container_width=True)
    with cols[1]:
        if st.button("🗑 Clear Log", use_container_width=True):
            conn = get_connection()
            conn.execute("DELETE FROM audit_log")
            conn.commit()
            conn.close()
            st.success("Audit log cleared")
            st.rerun()
