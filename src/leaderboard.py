"""
PhishGuard AI — Gamified Security Champions Leaderboard

Tracks user contributions, awards points for threat reports, and
displays a "Security Champions" dashboard in Streamlit.

Features:
- Points awarded per scan + bonus for HIGH/CRITICAL reports
- Top 10 leaderboard with medals
- User's personal stats card
- Point history audit trail
"""

import streamlit as st
import plotly.graph_objects as go
from src.database import (
    get_leaderboard,
    get_user_rank,
    record_scan,
    LEADERBOARD_SCORING,
)


def render_leaderboard(username: str):
    """Main leaderboard UI component."""
    st.markdown("## 🏆 Security Champions Leaderboard")
    st.markdown(
        "<p style='color:#64748b;margin-top:-8px'>Earn points by scanning emails "
        "and reporting threats. Compete with your team to be the top defender!</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    # Scoring guide
    with st.expander("📋 How Scoring Works"):
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.markdown("**Base Actions**")
            st.markdown(f"- Email scan: **+{LEADERBOARD_SCORING['scan']} pts**")
            st.markdown(f"- Daily login: **+{LEADERBOARD_SCORING['daily_login']} pts**")
        with col_s2:
            st.markdown("**Threat Bonuses**")
            st.markdown(f"- Medium risk: **+{LEADERBOARD_SCORING['medium_report']} pts**")
            st.markdown(f"- High risk: **+{LEADERBOARD_SCORING['high_report']} pts**")
            st.markdown(f"- Critical: **+{LEADERBOARD_SCORING['critical_report']} pts**")

    st.divider()

    # User's personal rank
    user_data = get_user_rank(username)
    if user_data:
        col_u1, col_u2, col_u3, col_u4 = st.columns(4)
        rank = user_data.get("rank", "—")
        rank_icon = "🥇" if rank == 1 else "🥈" if rank == 2 else "🥉" if rank <= 3 else f"#{rank}"
        col_u1.markdown(
            f"<div style='background:#111827;border:1px solid #1e3a5f;border-radius:12px;"
            f"padding:16px;text-align:center'>"
            f"<div style='font-size:1.8rem'>{rank_icon}</div>"
            f"<div style='color:#64748b;font-size:0.75rem'>Your Rank</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
        col_u2.metric("Total Points", user_data.get("total_points", 0))
        col_u3.metric("Threats Reported", user_data.get("threats_reported", 0))
        col_u4.metric("Scans", user_data.get("total_scans", 0))

        st.divider()

    # Top 10 leaderboard
    st.markdown("### 🥇 Top Defenders")
    rows = get_leaderboard(limit=20)

    if not rows:
        st.info("No leaderboard data yet. Scan your first email to get started!")
        return

    # Prepare chart data
    names = []
    points = []
    medals = []

    for i, row in enumerate(rows):
        uname, dept, scans, threats, crit, high, pts, last_active = row
        display_name = uname[:12] + (".." if len(uname) > 12 else "")
        names.append(display_name)
        points.append(pts)
        if i == 0:
            medals.append("🥇")
        elif i == 1:
            medals.append("🥈")
        elif i == 2:
            medals.append("🥉")
        elif i < 5:
            medals.append("🏅")
        else:
            medals.append("")

    # Horizontal bar chart
    fig = go.Figure(go.Bar(
        x=points[::-1],
        y=names[::-1],
        orientation="h",
        marker=dict(
            color=["#ffd700" if i == 0 else "#c0c0c0" if i == 1 else "#cd7f32" if i == 2 else "#3b82f6" for i in range(len(points) - 1, -1, -1)],
            line=dict(color="#1e3a5f", width=1),
        ),
        text=[f"{p} pts" for p in points[::-1]],
        textposition="outside",
        textfont=dict(size=11),
    ))
    fig.update_layout(
        title="Points Leaderboard",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0",
        height=max(300, len(rows) * 30),
        margin=dict(t=30, b=10, l=10, r=80),
        xaxis=dict(gridcolor="#1e3a5f", title="Points"),
        yaxis=dict(gridcolor="#1e3a5f", autorange="reversed"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

    # Table view
    st.markdown("### 📊 Full Rankings")
    table_data = []
    for i, row in enumerate(rows):
        uname, dept, scans, threats, crit, high, pts, last_active = row
        rank_str = medals[i] if i < 5 else f"#{i + 1}"
        table_data.append({
            "Rank": rank_str,
            "Username": uname,
            "Department": dept,
            "Scans": scans,
            "Threats Reported": threats,
            f"Critical (🔥)": crit,
            f"High (⚠️)": high,
            "Points": pts,
            "Last Active": (last_active or "—")[:10],
        })

    st.dataframe(
        table_data,
        use_container_width=True,
        column_config={
            "Points": st.column_config.NumberColumn(format="%d pts"),
        },
        hide_index=True,
    )

    # Threat detection rate
    st.divider()
    st.markdown("### 📈 Detection Impact")
    total_threats = sum(r[3] for r in rows)
    total_scans_all = sum(r[2] for r in rows)
    detection_rate = (total_threats / total_scans_all * 100) if total_scans_all > 0 else 0

    col_m1, col_m2, col_m3 = st.columns(3)
    col_m1.metric("Total Community Scans", total_scans_all)
    col_m2.metric("Total Threats Reported", total_threats)
    col_m3.metric("Detection Rate", f"{detection_rate:.1f}%")

    # Department breakdown
    st.markdown("### 🏢 Department Performance")
    dept_stats = {}
    for row in rows:
        uname, dept, scans, threats, crit, high, pts, _ = row
        if dept not in dept_stats:
            dept_stats[dept] = {"users": 0, "scans": 0, "threats": 0, "criticals": 0, "points": 0}
        dept_stats[dept]["users"] += 1
        dept_stats[dept]["scans"] += scans
        dept_stats[dept]["threats"] += threats
        dept_stats[dept]["criticals"] += crit
        dept_stats[dept]["points"] += pts

    if dept_stats:
        dept_names = list(dept_stats.keys())
        dept_points = [dept_stats[d]["points"] for d in dept_names]
        dept_scans = [dept_stats[d]["scans"] for d in dept_names]
        dept_threats = [dept_stats[d]["threats"] for d in dept_names]

        fig_dept = go.Figure()
        fig_dept.add_trace(go.Bar(
            x=dept_names, y=dept_points,
            name="Points", marker_color="#3b82f6",
            text=dept_points, textposition="outside",
        ))
        fig_dept.add_trace(go.Bar(
            x=dept_names, y=dept_threats,
            name="Threats Reported", marker_color="#ff4444",
            text=dept_threats, textposition="outside",
        ))
        fig_dept.update_layout(
            title="Department Contributions",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            height=300,
            margin=dict(t=30, b=20, l=20, r=60),
            xaxis=dict(gridcolor="#1e3a5f"),
            yaxis=dict(gridcolor="#1e3a5f", title="Count"),
            barmode="group",
            legend=dict(orientation="h", y=1.1),
        )
        st.plotly_chart(fig_dept, use_container_width=True)

    # Threat breakdown
    st.divider()
    st.markdown("### 📊 Threat Distribution (All Users)")
    total_crit = sum(r[4] for r in rows)
    total_high = sum(r[5] for r in rows)

    if total_crit + total_high > 0:
        fig_td = go.Figure(go.Pie(
            labels=["Critical", "High"],
            values=[total_crit, total_high],
            hole=0.4,
            marker_colors=["#ff4444", "#ff8800"],
            textinfo="label+value+percent",
            textfont=dict(size=13, color="#e2e8f0"),
        ))
        fig_td.update_layout(
            title="Critical vs High Threats",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            height=280,
            margin=dict(t=30, b=10, l=10, r=10),
            showlegend=False,
        )
        st.plotly_chart(fig_td, use_container_width=True)
    else:
        st.info("No critical or high threats reported yet. Stay vigilant!")
