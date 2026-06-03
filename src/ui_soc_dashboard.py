import re
from datetime import datetime, timedelta

import plotly.graph_objects as go
import streamlit as st

from src.db import get_connection


def _get_db():
    return get_connection()


@st.cache_data(ttl=15)
def _query_today_counts():
    today = datetime.now().strftime("%Y-%m-%d")
    conn = _get_db()
    c = conn.cursor()
    c.execute(
        "SELECT COUNT(*) FROM analyses WHERE timestamp >= ?",
        (today,),
    )
    total_today = c.fetchone()[0]
    c.execute(
        "SELECT COUNT(*) FROM analyses WHERE timestamp >= ? AND severity = 'CRITICAL'",
        (today,),
    )
    critical_today = c.fetchone()[0]
    c.execute(
        "SELECT COUNT(*) FROM analyses WHERE timestamp >= ? AND severity = 'HIGH'",
        (today,),
    )
    high_today = c.fetchone()[0]
    c.execute(
        "SELECT COALESCE(SUM(scans_used), 0) FROM scan_consumption WHERE period_start >= ?",
        (today,),
    )
    scans_today = c.fetchone()[0]
    conn.close()
    return total_today, critical_today, high_today, scans_today


@st.cache_data(ttl=15)
def _query_recent_analyses(limit=50):
    conn = _get_db()
    c = conn.cursor()
    c.execute(
        "SELECT id, timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview "
        "FROM analyses ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


@st.cache_data(ttl=15)
def _query_hourly_timeline():
    cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    conn = _get_db()
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, severity FROM analyses WHERE timestamp >= ? ORDER BY timestamp",
        (cutoff,),
    )
    rows = c.fetchall()
    conn.close()

    hourly = {}
    for ts, sev in rows:
        hour_key = ts[:13] + ":00" if ts else ""
        if not hour_key:
            continue
        if hour_key not in hourly:
            hourly[hour_key] = {"total": 0, "critical": 0, "high": 0}
        hourly[hour_key]["total"] += 1
        if sev == "CRITICAL":
            hourly[hour_key]["critical"] += 1
        elif sev == "HIGH":
            hourly[hour_key]["high"] += 1

    sorted_hours = sorted(hourly.keys())
    return sorted_hours, hourly


@st.cache_data(ttl=15)
def _query_top_domains():
    conn = _get_db()
    c = conn.cursor()
    c.execute(
        "SELECT sender_domain, COUNT(*) as cnt FROM sender_profiles "
        "GROUP BY sender_domain ORDER BY cnt DESC LIMIT 5",
    )
    rows = c.fetchall()
    conn.close()
    if rows:
        return [{"domain": r["sender_domain"], "count": r["cnt"]} for r in rows]

    conn = _get_db()
    c = conn.cursor()
    c.execute(
        "SELECT email_preview FROM analyses WHERE email_preview IS NOT NULL AND email_preview != '' "
        "ORDER BY id DESC LIMIT 200",
    )
    previews = c.fetchall()
    conn.close()
    domain_counts = {}
    for row in previews:
        preview = row["email_preview"] or ""
        found = re.findall(r'@([\w.-]+\.[a-z]{2,})', preview, re.IGNORECASE)
        for d in found:
            domain_counts[d.lower()] = domain_counts.get(d.lower(), 0) + 1
    sorted_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:5]
    return [{"domain": d, "count": c} for d, c in sorted_domains]


@st.cache_data(ttl=15)
def _query_sender_geo():
    conn = _get_db()
    c = conn.cursor()
    c.execute(
        "SELECT sender_domain, COUNT(*) as cnt, "
        "ROUND(AVG(trust_score), 1) as avg_trust, "
        "ROUND(AVG(avg_risk_score), 1) as avg_risk "
        "FROM sender_profiles GROUP BY sender_domain ORDER BY cnt DESC LIMIT 10",
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def render_soc_dashboard(username, is_admin):
    st.markdown("## 🛡 SOC Dashboard")
    st.caption(
        "Real-time security operations centre — threat metrics, live feed, and trend analysis."
    )
    st.divider()

    total_today, critical_today, high_today, scans_today = _query_today_counts()

    col_k1, col_k2, col_k3, col_k4 = st.columns(4)
    col_k1.metric("Total Threats Today", total_today)
    col_k2.metric("Critical", critical_today, delta_color="inverse")
    col_k3.metric("High", high_today, delta_color="inverse")
    col_k4.metric("Scans Today", scans_today)
    st.divider()

    st.markdown("#### ⚡ Live Threat Feed")
    st.caption("Most recent analyses — auto-updates every 15 seconds")
    analyses = _query_recent_analyses(50)
    if analyses:
        ticker_data = [
            {
                "ID": r["id"],
                "Time": r["timestamp"][:16] if r["timestamp"] else "",
                "Score": r["risk_score"],
                "Severity": r["severity"],
                "Preview": (r["email_preview"] or "")[:60],
            }
            for r in analyses[:20]
        ]
        st.dataframe(ticker_data, use_container_width=True, hide_index=True)
    else:
        st.info("No analyses recorded yet. Scan an email to see results here.")

    st.divider()

    col_ch1, col_ch2 = st.columns(2)

    with col_ch1:
        st.markdown("#### 🛡 Severity Breakdown")
        sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in analyses:
            sev = r["severity"] or "LOW"
            if sev in sev_counts:
                sev_counts[sev] += 1
        labels_donut = ["Safe", "Medium", "High", "Critical"]
        values_donut = [
            sev_counts["LOW"],
            sev_counts["MEDIUM"],
            sev_counts["HIGH"],
            sev_counts["CRITICAL"],
        ]
        colors_donut = ["#44aa44", "#ffaa00", "#ff8800", "#ff4444"]
        fig_donut = go.Figure(
            go.Pie(
                labels=labels_donut,
                values=values_donut,
                marker_colors=colors_donut,
                hole=0.5,
                textinfo="label+percent",
                textfont_color="#e2e8f0",
            )
        )
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            height=300,
            margin=dict(t=10, b=10, l=10, r=10),
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with col_ch2:
        st.markdown("#### 📈 Timeline (Last 24h)")
        sorted_hours, hourly = _query_hourly_timeline()
        if sorted_hours:
            fig_timeline = go.Figure()
            fig_timeline.add_trace(
                go.Scatter(
                    x=sorted_hours,
                    y=[hourly[h]["total"] for h in sorted_hours],
                    mode="lines+markers",
                    name="Total",
                    line=dict(color="#60a5fa"),
                )
            )
            fig_timeline.add_trace(
                go.Scatter(
                    x=sorted_hours,
                    y=[hourly[h]["critical"] for h in sorted_hours],
                    mode="lines+markers",
                    name="Critical",
                    line=dict(color="#ff4444"),
                )
            )
            fig_timeline.add_trace(
                go.Scatter(
                    x=sorted_hours,
                    y=[hourly[h]["high"] for h in sorted_hours],
                    mode="lines+markers",
                    name="High",
                    line=dict(color="#ff8800"),
                )
            )
            fig_timeline.update_layout(
                xaxis_title="Hour",
                yaxis_title="Count",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0",
                height=300,
                margin=dict(t=10, b=10, l=10, r=10),
                legend=dict(
                    orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1
                ),
            )
            fig_timeline.update_xaxes(gridcolor="#1e3a5f")
            fig_timeline.update_yaxes(gridcolor="#1e3a5f")
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.caption("No data in the last 24 hours.")

    st.divider()

    col_t1, col_t2 = st.columns(2)

    with col_t1:
        st.markdown("#### 🎯 Top 5 Most Targeted Domains")
        top_domains = _query_top_domains()
        if top_domains:
            domain_data = [
                {"Domain": d["domain"], "Occurrences": d["count"]}
                for d in top_domains
            ]
            st.dataframe(domain_data, use_container_width=True, hide_index=True)
        else:
            st.caption("No domain data available yet.")

    with col_t2:
        st.markdown("#### 🌐 Sender Domain Overview")
        geo_data = _query_sender_geo()
        if geo_data:
            geo_rows = []
            for g in geo_data:
                geo_rows.append(
                    {
                        "Domain": g["sender_domain"],
                        "Emails": g["cnt"],
                        "Trust": f'{g["avg_trust"]}/100',
                        "Risk": f'{g["avg_risk"]}/100',
                    }
                )
            st.dataframe(geo_rows, use_container_width=True, hide_index=True)
        else:
            st.caption("Sender profiling data not yet available. Run analyses to populate.")

    st.divider()
    st.caption("🔄 Dashboard auto-refreshes every 15 seconds")
    st.markdown(
        '<meta http-equiv="refresh" content="15">',
        unsafe_allow_html=True
    )
