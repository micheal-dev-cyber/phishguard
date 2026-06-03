from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from src.database import get_history

WIDGETS = {
    "soc_metrics": "🎯 Key SOC Metrics",
    "donut": "🛡 Threat Level Distribution",
    "severity_bar": "📊 Threat Severity Counts",
    "trend_line": "📅 Phishing Trend Timeline",
    "psych_triggers": "🧠 Psychological Triggers",
    "ai_trend": "🤖 AI-Generated Text Trend",
    "exports": "📤 Export & Compliance",
}


def render_analytics_tab():
    st.markdown("## 📈 SOC Analytics Dashboard")
    st.caption("Real-time threat intelligence, security metrics, and phishing trend analysis.")

    col_top1, col_top2, col_top3 = st.columns([1, 2, 2])
    with col_top1:
        if st.button("🔄 Refresh", key="refresh_analytics_cust"):
            st.cache_data.clear()
            st.rerun()
    with col_top2:
        lookback_days = st.selectbox(
            "Time range", ["All Time", "Last 30 Days", "Last 7 Days", "Today"],
            index=0, key="soc_range_cust", label_visibility="collapsed",
        )
    with col_top3:
        default_widgets = list(WIDGETS.keys())
        visible = st.multiselect(
            "Widgets", options=list(WIDGETS.keys()),
            default=default_widgets,
            format_func=lambda k: WIDGETS[k],
            key="visible_widgets", label_visibility="collapsed",
        )
    st.divider()

    history = st.cache_data(
        get_history, ttl=60
    )(500)
    if not history:
        st.info("No scan data yet. Go to Analyze and scan your first email.")
        return

    scores = [row[1] for row in history]
    severities = [row[2] for row in history]
    timestamps = [row[0] for row in history]

    if lookback_days != "All Time":
        day_map = {"Today": 1, "Last 7 Days": 7, "Last 30 Days": 30}
        limit = day_map.get(lookback_days, 30)
        cutoff = datetime.now().isoformat()[:10]
        import datetime as dt
        cutoff = (dt.datetime.now() - dt.timedelta(days=limit)).strftime("%Y-%m-%d")
        filtered = [(ts, sc, sev) for ts, sc, sev, *_ in history if ts[:10] >= cutoff]
        if filtered:
            scores = [r[1] for r in filtered]
            severities = [r[2] for r in filtered]
            timestamps = [r[0] for r in filtered]

    total_scans = len(history)
    filtered_count = len(scores)
    avg_score = round(sum(scores) / filtered_count, 1) if filtered_count else 0
    critical_count = sum(1 for s in severities if s == "CRITICAL")
    high_count = sum(1 for s in severities if s == "HIGH")
    medium_count = sum(1 for s in severities if s == "MEDIUM")
    safe_count = sum(1 for s in severities if s == "LOW")
    threats_neutralized = critical_count + high_count

    if "soc_metrics" in visible:
        st.markdown("#### 🎯 Key SOC Metrics")
        col_k1, col_k2, col_k3, col_k4, col_k5 = st.columns(5)
        col_k1.metric("Total Scans", filtered_count,
                       delta=total_scans - filtered_count if filtered_count != total_scans else None)
        col_k2.metric("Avg Risk Score", f"{avg_score}/100")
        col_k3.metric("Threats Neutralized", threats_neutralized, delta_color="inverse")
        col_k4.metric("Critical", critical_count, delta_color="inverse")
        col_k5.metric("Safe %", f"{round(safe_count / filtered_count * 100, 1) if filtered_count else 0}%")
        st.divider()

    if "donut" in visible:
        st.markdown("#### 🛡 Threat Level Distribution")
        labels_donut = ["Safe", "Medium", "High", "Critical"]
        values_donut = [safe_count, medium_count, high_count, critical_count]
        colors_donut = ["#44aa44", "#ffaa00", "#ff8800", "#ff4444"]
        fig_donut = go.Figure(go.Pie(
            labels=labels_donut, values=values_donut,
            marker_colors=colors_donut, hole=0.5,
            textinfo="label+percent", textfont_color="#e2e8f0",
        ))
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
            height=300, margin=dict(t=10, b=10, l=10, r=10),
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    if "severity_bar" in visible:
        st.markdown("#### 📊 Threat Severity Counts")
        sev_labels = ["Safe", "Medium", "High", "Critical"]
        sev_counts = [safe_count, medium_count, high_count, critical_count]
        sev_colors = ["#44aa44", "#ffaa00", "#ff8800", "#ff4444"]
        fig_bar_sev = go.Figure(go.Bar(
            x=sev_labels, y=sev_counts, marker_color=sev_colors,
            text=sev_counts, textposition="outside",
        ))
        fig_bar_sev.update_layout(
            yaxis_title="Count", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
            height=300, margin=dict(t=10, b=10, l=10, r=10),
        )
        fig_bar_sev.update_yaxes(gridcolor="#1e3a5f")
        st.plotly_chart(fig_bar_sev, use_container_width=True)

    if "trend_line" in visible:
        st.markdown("#### 📅 Phishing Trend Timeline")
        daily_counts = {}
        for ts, sev in zip(timestamps, severities):
            day = ts[:10]
            if day not in daily_counts:
                daily_counts[day] = {"total": 0, "critical": 0, "high": 0}
            daily_counts[day]["total"] += 1
            if sev == "CRITICAL":
                daily_counts[day]["critical"] += 1
            elif sev == "HIGH":
                daily_counts[day]["high"] += 1
        sorted_days = sorted(daily_counts.keys())
        fig_line = go.Figure()
        fig_line.add_trace(go.Scatter(
            x=sorted_days,
            y=[daily_counts[d]["total"] for d in sorted_days],
            mode="lines+markers", name="Total Scans", line=dict(color="#60a5fa"),
        ))
        fig_line.add_trace(go.Scatter(
            x=sorted_days,
            y=[daily_counts[d]["critical"] for d in sorted_days],
            mode="lines+markers", name="Critical", line=dict(color="#ff4444"),
        ))
        fig_line.add_trace(go.Scatter(
            x=sorted_days,
            y=[daily_counts[d]["high"] for d in sorted_days],
            mode="lines+markers", name="High", line=dict(color="#ff8800"),
        ))
        fig_line.update_layout(
            yaxis_title="Count", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
            height=350, margin=dict(t=10, b=10, l=10, r=10),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        fig_line.update_xaxes(gridcolor="#1e3a5f")
        fig_line.update_yaxes(gridcolor="#1e3a5f")
        st.plotly_chart(fig_line, use_container_width=True)

    if "psych_triggers" in visible:
        xai = st.session_state.get("xai_result", {})
        if xai:
            st.markdown("#### 🧠 Psychological Triggers (Last Scan)")
            triggers = xai if isinstance(xai, dict) else {}
            trigger_names = list(triggers.keys())[:8]
            trigger_values = [triggers.get(k, 0) for k in trigger_names]
            fig_bar = go.Figure(go.Bar(
                x=trigger_values,
                y=trigger_names,
                orientation="h",
                marker_color="#60a5fa",
                text=trigger_values,
                textposition="outside",
            ))
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=300,
                margin=dict(t=10, b=10, l=10, r=10),
                xaxis_title="Confidence %",
            )
            fig_bar.update_xaxes(gridcolor="#1e3a5f", range=[0, 100])
            st.plotly_chart(fig_bar, use_container_width=True)

    if "ai_trend" in visible:
        st.markdown("#### 🤖 AI-Generated Text Trend")
        recent = history[:20]
        ai_probs = []
        for r in recent:
            ts_key = r[0]
            p = st.session_state.get(f"_perplex_{ts_key}", 0)
            ai_probs.append(p)
        if ai_probs and any(ai_probs):
            ai_labels = [f"#{i+1}" for i in range(len(recent))]
            fig_ai = go.Figure()
            fig_ai.add_trace(go.Scatter(
                x=ai_labels, y=ai_probs, mode="lines+markers",
                name="AI Probability", line=dict(color="#a855f7"),
            ))
            fig_ai.add_hline(y=50, line_dash="dash", line_color="#ff4444",
                             annotation_text="Threshold (50%)")
            fig_ai.update_layout(
                yaxis_title="AI Probability %", yaxis_range=[0, 100],
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0", height=300,
                margin=dict(t=10, b=10, l=10, r=10),
            )
            fig_ai.update_xaxes(showgrid=False)
            fig_ai.update_yaxes(gridcolor="#1e3a5f")
            st.plotly_chart(fig_ai, use_container_width=True)
        else:
            st.caption("Run AI-powered analysis on emails to populate this chart.")

    if "exports" in visible:
        st.divider()
        st.markdown("#### 📤 Export & Compliance")
        col_e1, col_e2, col_e3 = st.columns(3)
        with col_e1:
            import csv
            import io
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["timestamp","risk_score","severity","keyword_hits","suspicious_urls","email_preview"])
            for r in history:
                w.writerow([str(v) for v in r])
            csv_data = buf.getvalue()
            st.download_button("📥 Export CSV", csv_data, "phishguard_analytics.csv", "text/csv",
                               use_container_width=True)

        with col_e2:
            import json
            json_data = json.dumps(
                [{"timestamp": r[0], "risk_score": r[1], "severity": r[2],
                  "keyword_hits": r[3], "suspicious_urls": r[4], "email_preview": r[5][:80]}
                 for r in history], indent=2,
            )
            st.download_button("📥 Export JSON", json_data, "phishguard_analytics.json",
                               "application/json", use_container_width=True)

        with col_e3:
            if history:
                last = history[0]
                last_json = json.dumps({
                    "timestamp": last[0], "risk_score": last[1], "severity": last[2],
                    "keyword_hits": last[3], "suspicious_urls": last[4],
                    "email_preview": last[5][:200],
                }, indent=2)
                st.download_button("📥 Last Analysis JSON", last_json,
                                   "phishguard_last_analysis.json", "application/json",
                                   use_container_width=True)

        st.divider()
        st.markdown("#### 📋 Compliance Report")
        col_c1, col_c2, col_c3 = st.columns([1, 1, 1])
        with col_c1:
            cr_standard = st.selectbox(
                "Standard", ["soc2", "gdpr", "hipaa"],
                format_func=lambda x: x.upper(), key="cr_standard_cust",
            )
        with col_c2:
            cr_days = st.slider("Period (days)", 7, 365, 90, key="cr_days_cust")
        with col_c3:
            whitelabel = st.checkbox("🔏 White-Label", key="whitelabel_cust")

        if st.button("📄 Generate Compliance Report", type="primary",
                     use_container_width=True):
            from src.compliance_reports import generate_report
            with st.spinner("Generating compliance report…"):
                pdf_bytes = generate_report(
                    standard=cr_standard, days=cr_days,
                    whitelabel=whitelabel,
                )
            st.download_button(
                f"💾 Download {cr_standard.upper()} Report",
                pdf_bytes, f"phishguard_{cr_standard}_report.pdf", "application/pdf",
                use_container_width=True,
            )
