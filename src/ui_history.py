import streamlit as st
import plotly.graph_objects as go
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def render_history_tab():
    st.markdown("#### 📊 Analysis History")
    st.markdown(
        "<p style='color:#64748b;margin-top:-8px'>Browse, filter, and export "
        "past email analyses. Narrow results by date range, severity, or keyword.</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    col_f1, col_f2, col_f3, col_f4 = st.columns([1, 1, 1, 1])
    with col_f1:
        filter_days = st.selectbox("Time range",
                                   ["Today", "7 days", "30 days", "90 days", "All time"],
                                   index=2, key="hist_days_ui")
        days_map = {"Today": 1, "7 days": 7, "30 days": 30, "90 days": 90, "All time": 9999}
        day_limit = days_map[filter_days]
    with col_f2:
        filter_severity = st.selectbox("Severity",
                                       ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"],
                                       index=0, key="hist_sev_ui")
    with col_f3:
        filter_keyword = st.text_input("Keyword search", placeholder="invoice, deadline...",
                                       key="hist_kw_ui", label_visibility="collapsed")
    with col_f4:
        hist_limit = st.number_input("Max results", 10, 500, 100, step=10, key="hist_limit_ui")

    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    params = []
    where_clauses = []
    if day_limit < 9999:
        where_clauses.append(f"timestamp > datetime('now', '-{day_limit} days')")
    if filter_severity != "All":
        where_clauses.append("severity = ?")
        params.append(filter_severity)
    where_str = " AND ".join(where_clauses) if where_clauses else "1=1"
    c.execute(
        f"SELECT id, timestamp, risk_score, severity, keyword_hits, suspicious_urls, email_preview "
        f"FROM analyses WHERE {where_str} ORDER BY id DESC LIMIT ?",
        (*params, hist_limit),
    )
    history = c.fetchall()
    conn.close()

    if filter_keyword:
        kw_lower = filter_keyword.lower()
        history = [r for r in history if kw_lower in (r[6] or "").lower()]

    if not history:
        st.info("No analyses match your filters. Try a broader search.")
        return

    st.caption(f"Showing {len(history)} result(s)")

    scores = [r[2] for r in history]
    labels = [f"#{i+1}" for i in range(len(history))]
    colors_bar = [
        "#ff4444" if s >= 75 else "#ff8800" if s >= 50 else "#ffaa00" if s >= 25 else "#44aa44"
        for s in scores
    ]
    fig_hist = go.Figure(go.Bar(
        x=labels, y=scores, marker_color=colors_bar,
        text=scores, textposition="outside",
    ))
    fig_hist.update_layout(
        title=f"Risk Scores — Last {len(history)} Analyses",
        yaxis_range=[0, 110],
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e2e8f0", height=250,
        margin=dict(t=30, b=10, l=10, r=10),
    )
    fig_hist.update_xaxes(showgrid=False)
    fig_hist.update_yaxes(gridcolor="#1e3a5f")
    st.plotly_chart(fig_hist, use_container_width=True)

    col_exp1, col_exp2 = st.columns([1, 3])
    with col_exp1:
        if st.button("📥 Export All as CSV", use_container_width=True):
            import csv, io
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(["ID", "Timestamp", "Risk Score", "Severity",
                         "Keyword Hits", "Suspicious URLs", "Email Preview"])
            for r in history:
                w.writerow(r)
            st.download_button("💾 Download CSV", out.getvalue(),
                               "phishguard_history.csv", "text/csv",
                               use_container_width=True)

    st.divider()

    page_size = 20
    total_pages = max(1, (len(history) + page_size - 1) // page_size)
    page = st.session_state.get("hist_page_ui", 1)
    col_p1, col_p2, col_p3 = st.columns([1, 2, 1])
    with col_p1:
        if st.button("← Previous", disabled=(page <= 1), use_container_width=True):
            st.session_state["hist_page_ui"] = max(1, page - 1)
            st.rerun()
    with col_p2:
        st.markdown(f"<p style='text-align:center;color:#94a3b8'>Page {page} / {total_pages}</p>",
                    unsafe_allow_html=True)
    with col_p3:
        if st.button("Next →", disabled=(page >= total_pages), use_container_width=True):
            st.session_state["hist_page_ui"] = min(total_pages, page + 1)
            st.rerun()

    start_idx = (page - 1) * page_size
    for row in history[start_idx:start_idx + page_size]:
        hid, hts, hscore, hsev, hkw, hsurls, hpreview = row
        with st.expander(f"**{hsev}** — Score {hscore}/100 — {hts[:16]}"):
            ca, cb, cc = st.columns(3)
            ca.metric("Risk Score", hscore)
            cb.metric("Keyword Hits", hkw)
            cc.metric("Suspicious URLs", hsurls)
            st.markdown(
                "<div class='url-box' style='color:#94a3b8'>📧 " +
                (hpreview or "")[:120] + "...</div>",
                unsafe_allow_html=True,
            )
