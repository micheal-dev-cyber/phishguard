import streamlit as st
import sqlite3
import time
from pathlib import Path
from datetime import datetime, timedelta

DB_PATH = Path(__file__).parent.parent / "data" / "phishguard.db"


def init_metrics():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS perf_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name TEXT,
            value REAL,
            unit TEXT,
            recorded_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def record_metric(name: str, value: float, unit: str = "ms"):
    init_metrics()
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute(
        "INSERT INTO perf_metrics (metric_name, value, unit) VALUES (?, ?, ?)",
        (name, value, unit),
    )
    conn.commit()
    conn.close()


def render_performance_tab():
    init_metrics()
    st.markdown("#### 📊 Performance Monitor")
    st.caption("System metrics, latency tracking, and cache health.")

    col_refresh = st.columns([1, 5])
    with col_refresh[0]:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Cache stats
    st.markdown("##### 🗃 Cache Health")
    col_c1, col_c2, col_c3, col_c4 = st.columns(4)
    try:
        from src.redis_cache import REDIS_ENABLED
        col_c1.metric("Redis", "Connected" if REDIS_ENABLED else "Disabled")
    except Exception:
        col_c1.metric("Redis", "Unavailable")

    col_c2.metric("Streamlit Cache", "Active")
    col_c3.metric("DB Cache TTL", "60s")
    col_c4.metric("Cache Entries", "In-memory")

    st.divider()

    # Recent metrics
    st.markdown("##### 📈 Recent Metrics")
    c.execute(
        "SELECT metric_name, value, unit, recorded_at FROM perf_metrics ORDER BY id DESC LIMIT 50",
    )
    metrics = c.fetchall()
    if metrics:
        data = [
            {"Name": m["metric_name"], "Value": f"{m['value']:.1f} {m['unit']}",
             "Recorded": m["recorded_at"][:19]}
            for m in metrics
        ]
        st.dataframe(data, use_container_width=True, hide_index=True)

        avg_data = {}
        for m in metrics:
            name = m["metric_name"]
            if name not in avg_data:
                avg_data[name] = []
            avg_data[name].append(m["value"])
        st.caption("Aggregated (avg/min/max)")
        agg_data = []
        for name, vals in avg_data.items():
            agg_data.append({
                "Metric": name,
                "Avg": f"{sum(vals) / len(vals):.1f}",
                "Min": f"{min(vals):.1f}",
                "Max": f"{max(vals):.1f}",
                "Samples": len(vals),
            })
        st.dataframe(agg_data, use_container_width=True, hide_index=True)
    else:
        st.info("No metrics recorded yet. They populate as scans run.")

    st.divider()

    # DB stats
    st.markdown("##### 🗄 Database Stats")
    c.execute("SELECT COUNT(*) FROM analyses")
    analysis_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM audit_log")
    audit_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM notifications")
    notif_count = c.fetchone()[0]

    cols_db = st.columns(4)
    cols_db[0].metric("Analyses", analysis_count)
    cols_db[1].metric("Users", user_count)
    cols_db[2].metric("Audit Entries", audit_count)
    cols_db[3].metric("Notifications", notif_count)

    conn.close()
