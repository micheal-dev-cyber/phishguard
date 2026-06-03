
import streamlit as st

from src.db import get_connection


def _get_db():
    return get_connection()


def render_admin_tab():
    st.markdown("## ⚙ Admin Dashboard")
    st.caption("System-wide oversight, user management, and feature controls.")

    conn = _get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses")
    total_analyses = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    admin_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE severity='CRITICAL'")
    critical_count = c.fetchone()[0]

    col_s1, col_s2, col_s3, col_s4 = st.columns(4)
    col_s1.metric("Total Users", total_users)
    col_s2.metric("Total Analyses", total_analyses)
    col_s3.metric("Admins", admin_count)
    col_s4.metric("Critical Threats", critical_count, delta_color="inverse")
    st.divider()

    # ── Recent Analyses Table ───────────────────────────────────────────
    st.markdown("#### 📋 Recent Analyses")
    c.execute(
        "SELECT id, timestamp, risk_score, severity, email_preview FROM analyses ORDER BY id DESC LIMIT 50",
    )
    rows = c.fetchall()
    if rows:
        data = [
            {"ID": r["id"], "Time": r["timestamp"][:16], "Score": r["risk_score"],
             "Severity": r["severity"], "Preview": (r["email_preview"] or "")[:60]}
            for r in rows
        ]
        st.dataframe(data, use_container_width=True, hide_index=True)
    else:
        st.info("No analyses yet.")

    st.divider()

    # ── User Management ─────────────────────────────────────────────────
    st.markdown("#### 👥 User Management")
    c.execute("SELECT username, email, role, status, created_at FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    if users:
        user_data = [
            {"Username": u["username"], "Email": u["email"] or "", "Role": u["role"],
             "Status": u["status"], "Created": (u["created_at"] or "")[:10]}
            for u in users
        ]
        st.dataframe(user_data, use_container_width=True, hide_index=True)

        col_u1, col_u2, col_u3 = st.columns(3)
        with col_u1:
            del_user = st.text_input("Delete username", placeholder="user@example.com",
                                     key="admin_del_user")
        with col_u2:
            new_role = st.selectbox("New role", ["user", "admin", "viewer"],
                                    key="admin_new_role")
        with col_u3:
            target_user = st.text_input("Set role for username", placeholder="user@example.com",
                                        key="admin_role_user")
        if st.button("Update Role", use_container_width=True) and target_user and new_role:
            c.execute("UPDATE users SET role=? WHERE username=?", (new_role, target_user))
            conn.commit()
            if c.rowcount:
                st.success(f"Role updated for {target_user}")
                st.rerun()
            else:
                st.error("User not found")

        if st.button("🗑 Delete User", type="secondary", use_container_width=True) and del_user:
            c.execute("DELETE FROM analyses WHERE username=?", (del_user,))
            c.execute("DELETE FROM users WHERE username=?", (del_user,))
            conn.commit()
            if c.rowcount:
                st.success(f"Deleted {del_user}")
                st.rerun()
            else:
                st.error("User not found")
    else:
        st.info("No users registered yet.")

    st.divider()

    # ── Feature Toggles ─────────────────────────────────────────────────
    st.markdown("#### 🔧 Feature Toggles")
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        st.toggle("Enable Registration", value=True, key="admin_toggle_reg")
        st.toggle("Enable API Keys", value=True, key="admin_toggle_api")
    with col_f2:
        st.toggle("Enable AI Analysis", value=True, key="admin_toggle_ai")
        st.toggle("Enable URL Sandbox", value=True, key="admin_toggle_url")

    st.divider()

    # ── Workspace Management ────────────────────────────────────────────
    try:
        from src.workspace import create_workspace, list_workspaces
        st.markdown("#### 🏢 Workspaces & RBAC")
        workspaces = list_workspaces()
        if workspaces:
            ws_data = [{"ID": w[0], "Name": w[1], "Members": w[3] or 0} for w in workspaces]
            st.dataframe(ws_data, use_container_width=True, hide_index=True)
        else:
            st.info("No workspaces yet.")

        with st.expander("➕ Create Workspace"):
            ws_name = st.text_input("Workspace name", key="admin_ws_name")
            ws_owner = st.text_input("Owner username", key="admin_ws_owner")
            if st.button("Create Workspace", use_container_width=True) and ws_name and ws_owner:
                try:
                    create_workspace(ws_name, ws_owner)
                    st.success(f"Workspace '{ws_name}' created")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
    except ImportError:
        st.caption("Workspace module not available.")

    conn.close()
