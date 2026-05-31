import logging
from datetime import datetime, timedelta
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from src.db import get_connection
from src.tenants import PLANS

logger = logging.getLogger(__name__)


def _db():
    return get_connection()


def get_founder_metrics():
    conn = _db()
    c = conn.cursor()
    try:
        # Total users
        c.execute("SELECT COUNT(*) FROM tenants")
        total_users = c.fetchone()[0]

        # Signups over time (last 30 days)
        c.execute("""
            SELECT DATE(created_at) as day, COUNT(*) as cnt
            FROM tenants
            WHERE created_at >= DATE('now', '-30 days')
            GROUP BY DATE(created_at)
            ORDER BY day
        """)
        signups_raw = c.fetchall()
        signup_dates = [r["day"] for r in signups_raw]
        signup_counts = [r["cnt"] for r in signups_raw]

        # Plan distribution
        c.execute("SELECT plan, COUNT(*) as cnt FROM tenants GROUP BY plan ORDER BY cnt DESC")
        plan_raw = c.fetchall()
        plan_labels = [r["plan"] for r in plan_raw]
        plan_values = [r["cnt"] for r in plan_raw]

        # Active vs suspended
        c.execute("SELECT is_active, COUNT(*) as cnt FROM tenants GROUP BY is_active")
        active_raw = {r["is_active"]: r["cnt"] for r in c.fetchall()}
        active_users = active_raw.get(1, 0)
        suspended_users = active_raw.get(0, 0)

        # Admin vs non-admin
        c.execute("SELECT COUNT(*) FROM tenants WHERE is_admin=1")
        admin_count = c.fetchone()[0]

        # Users who have ever scanned
        c.execute("SELECT COUNT(DISTINCT tenant_username) FROM analyses")
        scanning_users = c.fetchone()[0]

        # Users active this month (from usage_log)
        month_start = datetime.now().strftime("%Y-%m") + "%"
        c.execute("SELECT COUNT(DISTINCT username) FROM usage_log WHERE timestamp LIKE ? AND action='analysis'", (month_start,))
        active_this_month = c.fetchone()[0]

        # Users active this week
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        c.execute("SELECT COUNT(DISTINCT username) FROM usage_log WHERE timestamp > ? AND action='analysis'", (week_ago,))
        active_this_week = c.fetchone()[0]

        # Total scans
        c.execute("SELECT COUNT(*) FROM analyses")
        total_scans = c.fetchone()[0]

        # Scans last 30 days
        c.execute("SELECT COUNT(*) FROM analyses WHERE timestamp >= DATE('now', '-30 days')")
        scans_30d = c.fetchone()[0]

        # Scans today
        today = datetime.now().strftime("%Y-%m-%d")
        c.execute("SELECT COUNT(*) FROM analyses WHERE timestamp LIKE ?", (today + "%",))
        scans_today = c.fetchone()[0]

        # Avg risk score
        c.execute("SELECT AVG(risk_score) FROM analyses")
        avg_risk = round(c.fetchone()[0] or 0, 1)

        # Severity distribution
        c.execute("SELECT severity, COUNT(*) as cnt FROM analyses GROUP BY severity")
        sev_raw = c.fetchall()
        severity_counts = {r["severity"]: r["cnt"] for r in sev_raw}

        # Subscription stats
        c.execute("SELECT status, COUNT(*) as cnt FROM paddle_subscriptions GROUP BY status")
        sub_raw = c.fetchall()
        sub_statuses = {r["status"]: r["cnt"] for r in sub_raw}
        active_subs = sub_statuses.get("active", 0)
        cancelled_subs = sub_statuses.get("cancelled", 0)
        paused_subs = sub_statuses.get("paused", 0)

        # MRR estimation
        c.execute("SELECT plan FROM tenants WHERE is_active=1")
        plans = [r["plan"] for r in c.fetchall()]
        mrr = sum(PLANS.get(p, {}).get("price_monthly", 0) for p in plans)
        arr = mrr * 12

        # Feedback accuracy
        try:
            c.execute("SELECT COUNT(*) FROM feedback_loop WHERE user_label='correct'")
            correct = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM feedback_loop")
            total_fb = c.fetchone()[0]
            accuracy = round(correct / total_fb * 100, 1) if total_fb > 0 else None
        except Exception as e:
            logger.warning("ui_founder_analytics: Feedback accuracy query failed: %s", e)
            accuracy = None

        # Recent signups (last 10)
        c.execute("""
            SELECT username, email, plan, created_at, is_active
            FROM tenants ORDER BY id DESC LIMIT 10
        """)
        recent_signups = c.fetchall()

        # Top users by scan count
        c.execute("""
            SELECT tenant_username as username, COUNT(*) as scans,
                   MAX(risk_score) as max_risk
            FROM analyses GROUP BY tenant_username
            ORDER BY scans DESC LIMIT 10
        """)
        top_users = c.fetchall()

        return {
            "total_users": total_users,
            "active_users": active_users,
            "suspended_users": suspended_users,
            "admin_count": admin_count,
            "scanning_users": scanning_users,
            "active_this_month": active_this_month,
            "active_this_week": active_this_week,
            "total_scans": total_scans,
            "scans_30d": scans_30d,
            "scans_today": scans_today,
            "avg_risk": avg_risk,
            "severity_counts": severity_counts,
            "signup_dates": signup_dates,
            "signup_counts": signup_counts,
            "plan_labels": plan_labels,
            "plan_values": plan_values,
            "active_subs": active_subs,
            "cancelled_subs": cancelled_subs,
            "paused_subs": paused_subs,
            "mrr": mrr,
            "arr": arr,
            "accuracy": accuracy,
            "recent_signups": recent_signups,
            "top_users": top_users,
        }
    finally:
        conn.close()


def render_founder_analytics():
    st.markdown("## 📊 Founder Analytics")
    st.markdown(
        "<p style='color:#94a3b8'>Key metrics for growth, activation, retention, and revenue</p>",
        unsafe_allow_html=True,
    )

    metrics = get_founder_metrics()

    # ── KPI Cards ──────────────────────────────────────────────────────
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.markdown(
        f"<div class='stat-card'><div style='font-size:1.6rem;font-weight:900;color:#60a5fa'>${metrics['mrr']}</div>"
        f"<div style='color:#64748b;font-size:0.8rem'>MRR</div>"
        f"<div style='color:#475569;font-size:0.7rem'>${metrics['arr']}/yr ARR</div></div>",
        unsafe_allow_html=True,
    )
    k2.markdown(
        f"<div class='stat-card'><div style='font-size:1.6rem;font-weight:900;color:#22c55e'>{metrics['total_users']}</div>"
        f"<div style='color:#64748b;font-size:0.8rem'>Total Users</div>"
        f"<div style='color:#475569;font-size:0.7rem'>{metrics['active_users']} active · {metrics['scanning_users']} scanned</div></div>",
        unsafe_allow_html=True,
    )
    k3.markdown(
        f"<div class='stat-card'><div style='font-size:1.6rem;font-weight:900;color:#3b82f6'>{metrics['total_scans']}</div>"
        f"<div style='color:#64748b;font-size:0.8rem'>Total Scans</div>"
        f"<div style='color:#475569;font-size:0.7rem'>{metrics['scans_30d']} in 30d · {metrics['active_this_month']} active</div></div>",
        unsafe_allow_html=True,
    )
    k4.markdown(
        f"<div class='stat-card'><div style='font-size:1.6rem;font-weight:900;color={'#22c55e' if metrics['accuracy'] and metrics['accuracy'] > 80 else '#ffaa00'}'>{metrics['accuracy'] or 'N/A'}%</div>"
        f"<div style='color:#64748b;font-size:0.8rem'>Detection Accuracy</div>"
        f"<div style='color:#475569;font-size:0.7rem'>feedback loop</div></div>",
        unsafe_allow_html=True,
    )
    sub_color = "#22c55e"
    k5.markdown(
        f"<div class='stat-card'><div style='font-size:1.6rem;font-weight:900;color:{sub_color}'>{metrics['active_subs']}</div>"
        f"<div style='color:#64748b;font-size:0.8rem'>Active Subs</div>"
        f"<div style='color:#475569;font-size:0.7rem'>{metrics['cancelled_subs']} cancelled · {metrics['paused_subs']} paused</div></div>",
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts row ─────────────────────────────────────────────────────
    col_a, col_b = st.columns(2)

    with col_a:
        # Signups over time
        if metrics["signup_dates"]:
            fig = go.Figure(go.Scatter(
                x=metrics["signup_dates"], y=metrics["signup_counts"],
                mode="lines+markers", line=dict(color="#3b82f6", width=2),
                fill="tozeroy", fillcolor="rgba(59,130,246,0.1)",
            ))
            fig.update_layout(
                title="New Signups (Last 30 Days)",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=280, margin=dict(t=40, b=20, l=20, r=20),
                xaxis=dict(showgrid=False), yaxis=dict(gridcolor="#1e3a5f"),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No signup data yet.")

    with col_b:
        # Plan distribution
        if metrics["plan_labels"]:
            colors = {"free": "#64748b", "trial": "#60a5fa", "starter": "#22c55e",
                      "business": "#3b82f6", "consultant": "#a855f7", "enterprise": "#f59e0b"}
            fig = go.Figure(go.Pie(
                labels=metrics["plan_labels"],
                values=metrics["plan_values"],
                marker_colors=[colors.get(p, "#60a5fa") for p in metrics["plan_labels"]],
                hole=0.4, textinfo="label+percent",
            ))
            fig.update_layout(
                title="Plan Distribution",
                paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                height=280, margin=dict(t=40, b=20, l=20, r=20),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No plan data yet.")

    # ── Second row: engagement & severity ──────────────────────────────
    col_c, col_d = st.columns(2)

    with col_c:
        # Severity distribution
        if metrics["severity_counts"]:
            sev_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                          "MEDIUM": "#ffaa00", "LOW": "#44aa44"}
            fig = go.Figure(go.Bar(
                x=list(metrics["severity_counts"].keys()),
                y=list(metrics["severity_counts"].values()),
                marker_color=[sev_colors.get(k, "#60a5fa") for k in metrics["severity_counts"]],
                text=list(metrics["severity_counts"].values()),
                textposition="outside",
            ))
            fig.update_layout(
                title="Scan Severity Distribution",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=260, margin=dict(t=40, b=20, l=20, r=20),
                xaxis=dict(showgrid=False), yaxis=dict(gridcolor="#1e3a5f"),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No scan severity data yet.")

    with col_d:
        # MRR breakdown by plan
        if metrics["plan_labels"]:
            plan_mrr = {p: metrics["plan_values"][i] * PLANS.get(p, {}).get("price_monthly", 0)
                        for i, p in enumerate(metrics["plan_labels"])}
            plan_mrr = {k: v for k, v in plan_mrr.items() if v > 0}
            if plan_mrr:
                colors = {"starter": "#22c55e", "business": "#3b82f6",
                          "consultant": "#a855f7", "enterprise": "#f59e0b"}
                fig = go.Figure(go.Pie(
                    labels=list(plan_mrr.keys()),
                    values=list(plan_mrr.values()),
                    marker_colors=[colors.get(k, "#60a5fa") for k in plan_mrr],
                    hole=0.4, textinfo="label+percent",
                    hovertemplate="%{label}: $%{value}/mo<extra></extra>",
                ))
                fig.update_layout(
                    title=f"MRR Breakdown (${metrics['mrr']}/mo)",
                    paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                    height=260, margin=dict(t=40, b=20, l=20, r=20),
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No paid plans yet.")
        else:
            st.info("No plan data yet.")

    # ── Tables row ─────────────────────────────────────────────────────
    col_e, col_f = st.columns(2)

    with col_e:
        st.markdown("### 👤 Recent Signups")
        if metrics["recent_signups"]:
            data = []
            for r in metrics["recent_signups"]:
                status_icon = "✅" if r["is_active"] else "⛔"
                data.append({
                    "User": r["username"],
                    "Plan": r["plan"],
                    "Status": status_icon,
                    "Joined": r["created_at"][:10] if r["created_at"] else "N/A",
                })
            st.dataframe(data, use_container_width=True, hide_index=True,
                         column_config={"Status": st.column_config.TextColumn(width="small")})
        else:
            st.info("No users yet.")

    with col_f:
        st.markdown("### 🏆 Top Users by Scans")
        if metrics["top_users"]:
            data = []
            for r in metrics["top_users"]:
                data.append({
                    "User": r["username"],
                    "Scans": r["scans"],
                    "Max Risk": f"{r['max_risk']}/100",
                })
            st.dataframe(data, use_container_width=True, hide_index=True)
        else:
            st.info("No scan data yet.")

    st.caption("Data refreshed on page load. All metrics from local database.")
