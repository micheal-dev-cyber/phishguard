"""
PhishGuard AI — Feedback Loop (FP/FN marking & adaptive tuning)

Usage:
    mark_feedback(analysis_id, user_label, user_notes)
    get_feedback_stats()
"""
import json
import logging
from datetime import datetime

from src.db import DB_PATH, get_connection

logger = logging.getLogger("feedback")


def _ensure_table():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS feedback_loop (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id     INTEGER,
            email_preview   TEXT,
            reported_severity TEXT,
            model_severity  TEXT,
            user_label      TEXT NOT NULL CHECK (user_label IN ('fp', 'fn', 'correct')),
            risk_score      INTEGER DEFAULT 0,
            user_notes      TEXT DEFAULT '',
            corrected_label TEXT,
            consumed        INTEGER DEFAULT 0,
            created_at      TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS feedback_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern     TEXT NOT NULL,
            weight_delta REAL DEFAULT 0,
            category    TEXT DEFAULT 'keyword',
            is_active   INTEGER DEFAULT 1,
            source      TEXT DEFAULT 'auto',
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def mark_feedback(analysis_id: int, user_label: str, user_notes: str = "",
                  email_preview: str = "", risk_score: int = 0,
                  model_severity: str = "", reported_severity: str = "") -> dict:
    _ensure_table()
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO feedback_loop (analysis_id, email_preview, reported_severity, "
            "model_severity, user_label, risk_score, user_notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (analysis_id, email_preview[:200], reported_severity,
             model_severity, user_label, risk_score, user_notes),
        )
        conn.commit()
        fid = c.lastrowid
        return {"status": "ok", "feedback_id": fid}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        conn.close()


def get_feedback_stats() -> dict:
    _ensure_table()
    conn = get_connection()
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM feedback_loop").fetchone()[0]
    fps = c.execute("SELECT COUNT(*) FROM feedback_loop WHERE user_label='fp'").fetchone()[0]
    fns = c.execute("SELECT COUNT(*) FROM feedback_loop WHERE user_label='fn'").fetchone()[0]
    correct = c.execute("SELECT COUNT(*) FROM feedback_loop WHERE user_label='correct'").fetchone()[0]
    conn.close()
    total_labeled = fps + fns + correct
    return {
        "total": total,
        "false_positives": fps,
        "false_negatives": fns,
        "correct": correct,
        "accuracy": round(correct / total_labeled * 100, 1) if total_labeled else 0,
        "fp_rate": round(fps / total_labeled * 100, 1) if total_labeled else 0,
        "fn_rate": round(fns / total_labeled * 100, 1) if total_labeled else 0,
    }


def get_feedback_history(limit: int = 100) -> list:
    _ensure_table()
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, analysis_id, email_preview, user_label, risk_score, "
        "user_notes, model_severity, reported_severity, created_at "
        "FROM feedback_loop ORDER BY id DESC LIMIT ?", (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "analysis_id": r[1], "email_preview": r[2],
            "user_label": r[3], "risk_score": r[4], "user_notes": r[5],
            "model_severity": r[6], "reported_severity": r[7], "created_at": r[8],
        }
        for r in rows
    ]
