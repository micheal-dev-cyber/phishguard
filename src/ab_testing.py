"""
A/B Testing Framework for Detection Rules.

Compares two rule sets (control vs. variant) side by side,
tracking false positive rates, detection rates, and average risk scores.

Usage:
    from src.ab_testing import ABTest, register_test, get_test_results
    test = ABTest("keyword_boost_v2", "user123")
    test.record_scan("control", risk_score=45, is_phishing=True, user_flagged=False)
    test.record_scan("variant", risk_score=62, is_phishing=True, user_flagged=True)
    results = test.get_results()
"""

import json
from datetime import datetime
from typing import Optional

from src.db import DB_PATH, get_connection


def init_ab_tests():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS ab_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_name TEXT NOT NULL,
            description TEXT,
            owner TEXT,
            status TEXT DEFAULT 'running',
            created_at TEXT DEFAULT (datetime('now')),
            control_config TEXT,
            variant_config TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ab_test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_id INTEGER,
            variant TEXT NOT NULL,
            risk_score INTEGER,
            is_phishing INTEGER,
            user_flagged INTEGER,
            matched_rules TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (test_id) REFERENCES ab_tests(id)
        )
    """)
    conn.commit()
    conn.close()


class ABTest:
    def __init__(self, test_name: str, owner: str = "",
                 description: str = "", control_config: Optional[dict] = None,
                 variant_config: Optional[dict] = None):
        init_ab_tests()
        self.test_name = test_name
        self.owner = owner
        self.description = description
        self.control_config = control_config or {}
        self.variant_config = variant_config or {}

        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "SELECT id FROM ab_tests WHERE test_name=? AND status='running'",
            (test_name,),
        )
        row = c.fetchone()
        if row:
            self.test_id = row[0]
        else:
            c.execute(
                "INSERT INTO ab_tests (test_name, description, owner, control_config, variant_config) VALUES (?, ?, ?, ?, ?)",
                (test_name, description, owner,
                 json.dumps(control_config or {}),
                 json.dumps(variant_config or {})),
            )
            conn.commit()
            self.test_id = c.lastrowid
        conn.close()

    def record_scan(self, variant: str, risk_score: int, is_phishing: bool,
                    user_flagged: bool = False, matched_rules: Optional[list] = None):
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO ab_test_results (test_id, variant, risk_score, is_phishing, user_flagged, matched_rules) VALUES (?, ?, ?, ?, ?, ?)",
            (self.test_id, variant, risk_score, int(is_phishing),
             int(user_flagged), json.dumps(matched_rules or [])),
        )
        conn.commit()
        conn.close()

    def get_results(self) -> dict:
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "SELECT * FROM ab_test_results WHERE test_id=? ORDER BY id",
            (self.test_id,),
        )
        rows = c.fetchall()
        conn.close()

        variants = {}
        for r in rows:
            var = r["variant"]
            if var not in variants:
                variants[var] = {
                    "count": 0, "total_score": 0, "phishing_count": 0,
                    "user_flagged_count": 0,
                }
            variants[var]["count"] += 1
            variants[var]["total_score"] += r["risk_score"]
            if r["is_phishing"]:
                variants[var]["phishing_count"] += 1
            if r["user_flagged"]:
                variants[var]["user_flagged_count"] += 1

        for var, stats in variants.items():
            stats["avg_score"] = round(stats["total_score"] / stats["count"], 1)
            stats["detection_rate"] = round(stats["phishing_count"] / stats["count"] * 100, 1)
            stats["false_positive_rate"] = round(
                stats["user_flagged_count"] / stats["count"] * 100, 1)

        return {
            "test_name": self.test_name,
            "total_scans": len(rows),
            "variants": variants,
        }


def list_active_tests() -> list:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM ab_tests WHERE status='running' ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def stop_test(test_name: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE ab_tests SET status='completed' WHERE test_name=?", (test_name,))
    conn.commit()
    conn.close()


def promote_variant(test_name: str, variant: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT control_config, variant_config FROM ab_tests WHERE test_name=?", (test_name,))
    row = c.fetchone()
    if not row:
        conn.close()
        return
    control, variant_cfg = json.loads(row[0]), json.loads(row[1])
    winner = variant_cfg if variant == "variant" else control
    from src.custom_rules import add_rule
    for rule in winner.get("rules", []):
        add_rule(rule["name"], rule.get("type", "keyword"), rule.get("pattern", ""),
                 rule.get("boost", 10), username="ab_test_promotion")
    conn.close()
