import re
from typing import Any, Dict

TRIGGER_DEFINITIONS = {
    "urgency": {
        "label": "Urgency",
        "icon": "⏰",
        "description": "Creates artificial time pressure to bypass rational decision-making",
        "severity_weight": 0.25,
        "patterns": [
            (r"\b(immediately?|urgent|asap|right away|right now|promptly)\b", "Time-sensitive directive"),
            (r"\b(\d+\s*(hours?|minutes?|days?))\b", "Specific time constraint"),
            (r"\b(expir(e|es|ed|ing)|deadline|due (today|soon))\b", "Impending deadline"),
            (r"\b(last chance|final (notice|warning)|one-time|limited (time|offer))\b", "Scarcity-framed ultimatum"),
            (r"\b(act now|respond (now|immediately)|click now|reply now)\b", "Demand for immediate action"),
            (r"\b(before it'?s (too late|gone)|don'?t (miss|wait)|hurry)\b", "Loss aversion trigger"),
        ],
    },
    "authority": {
        "label": "Authority Impersonation",
        "icon": "👑",
        "description": "Assumes a position of power or institutional legitimacy to compel compliance",
        "severity_weight": 0.25,
        "patterns": [
            (r"\b(CEO|CFO|CTO|president|director|executive|management)\b", "Executive title invocation"),
            (r"\b(legal (department|team|action)|compliance|regulatory|law enforcement)\b", "Legal/institutional authority"),
            (r"\b(IT (security|department|team)|security (team|department)|technical support)\b", "Technical authority claim"),
            (r"\b(official (notice|document|communication)|formal (complaint|notice))\b", "Official communication framing"),
            (r"\b(authorized|mandatory|required|policy (requires|mandates))\b", "Obligatory language"),
            (r"\b(on behalf of|directed by|instructed by)\b", "Delegated authority claim"),
        ],
    },
    "fear": {
        "label": "Fear & Intimidation",
        "icon": "😨",
        "description": "Triggers anxiety by threatening negative consequences or security risks",
        "severity_weight": 0.20,
        "patterns": [
            (r"\b(suspended|terminated|deactivated|disabled|blocked)\b", "Account/service threat"),
            (r"\b(unauthorized|fraudulent|suspicious (activity|transaction)|security breach)\b", "Security compromise warning"),
            (r"\b(legal action|lawsuit|court|penalty|fine|financial loss)\b", "Legal/financial threat"),
            (r"\b(compromised|hacked|breached|violated|stolen|data leak)\b", "Data compromise fear"),
            (r"\b(identity theft|fraud|financial crime|criminal investigation)\b", "Crime accusation implication"),
            (r"\b(irreversible|permanent (loss|damage)|cannot be (undone|recovered))\b", "Irreversible harm framing"),
        ],
    },
    "scarcity": {
        "label": "Scarcity",
        "icon": "💎",
        "description": "Creates perceived shortage or exclusivity to drive impulsive action",
        "severity_weight": 0.15,
        "patterns": [
            (r"\b(limited (time|offer|availability|spots|quantity))\b", "Limited availability claim"),
            (r"\b(exclusive|only (today|now)|while (supplies last|stock lasts))\b", "Exclusivity framing"),
            (r"\b((only|just) \d+ (left|remaining|available))\b", "Low inventory/availability"),
            (r"\b(high demand|selling (fast|quickly)|going (fast|quickly))\b", "High demand pressure"),
            (r"\b(one (time|chance|opportunity)|never (again|before))\b", "Singular opportunity framing"),
        ],
    },
    "social_proof": {
        "label": "Social Proof",
        "icon": "👥",
        "description": "Leverages perceived group behaviour to normalise the requested action",
        "severity_weight": 0.10,
        "patterns": [
            (r"\b(thousands of|millions of|many (users|customers|people))\b", "Mass adoption claim"),
            (r"\b(recommended|trusted by|used by|chosen by)\b", "Endorsement claim"),
            (r"\b(your (colleagues|coworkers|peers|team) (have|are|already))\b", "Peer pressure"),
            (r"\b(jointhe|join now|community of)\b", "Community belonging pressure"),
            (r"\b(industry (standard|practice)|best practice|widely (used|adopted))\b", "Industry norm claim"),
        ],
    },
    "reciprocity": {
        "label": "Reciprocity",
        "icon": "🔄",
        "description": "Offers a perceived benefit to create obligation for a return action",
        "severity_weight": 0.05,
        "patterns": [
            (r"\b(free (gift|trial|access|download|consultation))\b", "Free offering"),
            (r"\b(exclusive (bonus|benefit|discount|offer|access))\b", "Exclusive benefit claim"),
            (r"\b(you have been (selected|chosen|awarded))\b", "Personal selection framing"),
            (r"\b(as a (valued|loyal|premium) (customer|member|client))\b", "Valued customer framing"),
            (r"\b(claim your|get your|receive your)\b", "Entitlement activation"),
        ],
    },
}

SEVERITY_LABELS = {
    "critical": {"label": "Critical", "color": "#ff4444", "threshold": 75},
    "high": {"label": "High", "color": "#ff8800", "threshold": 50},
    "medium": {"label": "Medium", "color": "#ffaa00", "threshold": 25},
    "low": {"label": "Low", "color": "#44aa44", "threshold": 0},
}


def analyze_psychological_triggers(text: str) -> Dict[str, Any]:
    """
    Analyse text for psychological manipulation tactics.
    Returns structured output with trigger scores, evidence, and explanations.
    """
    if not text or not text.strip():
        return {"error": "No text provided", "triggers": [], "total_manipulation_score": 0}

    text_lower = text.lower()
    triggers_detected = []
    total_weighted_score = 0.0

    for trigger_id, definition in TRIGGER_DEFINITIONS.items():
        evidence = []
        pattern_hits = 0

        for pattern, explanation in definition["patterns"]:
            try:
                matches = re.findall(pattern, text_lower)
                if matches:
                    unique_matches = list(set(m if isinstance(m, str) else m[0] for m in matches))
                    pattern_hits += len(unique_matches)
                    evidence.append({
                        "pattern": pattern,
                        "explanation": explanation,
                        "examples": unique_matches[:3],
                    })
            except re.error:
                continue

        if evidence:
            raw_score = min(pattern_hits * 12, 100)
            weighted_score = raw_score * definition["severity_weight"]
            total_weighted_score += weighted_score

            if raw_score >= 75:
                    severity_key = "critical"
            elif raw_score >= 50:
                    severity_key = "high"
            elif raw_score >= 25:
                    severity_key = "medium"
            else:
                    severity_key = "low"

            triggers_detected.append({
                "id": trigger_id,
                "label": definition["label"],
                "icon": definition["icon"],
                "description": definition["description"],
                "raw_score": raw_score,
                "weighted_score": round(weighted_score, 1),
                "severity": SEVERITY_LABELS[severity_key]["label"],
                "severity_color": SEVERITY_LABELS[severity_key]["color"],
                "evidence_count": pattern_hits,
                "evidence": evidence,
                "key_phrases": list(set(
                    e for ev in evidence for e in ev["examples"]
                )),
            })

    total_manipulation_score = min(round(total_weighted_score), 100)

    if total_manipulation_score >= 75:
        overall_severity = "CRITICAL"
        overall_color = "#ff4444"
    elif total_manipulation_score >= 50:
        overall_severity = "HIGH"
        overall_color = "#ff8800"
    elif total_manipulation_score >= 25:
        overall_severity = "MEDIUM"
        overall_color = "#ffaa00"
    else:
        overall_severity = "LOW"
        overall_color = "#44aa44"

    return {
        "triggers": triggers_detected,
        "total_manipulation_score": total_manipulation_score,
        "overall_severity": overall_severity,
        "overall_color": overall_color,
        "trigger_count": len(triggers_detected),
        "has_manipulation": total_manipulation_score >= 25,
    }


def format_xai_report(xai_result: Dict[str, Any]) -> str:
    """Generate a human-readable markdown report from XAI analysis."""
    if not xai_result or "triggers" not in xai_result:
        return "No psychological analysis available."

    lines = [
        "### 🧠 Psychological Manipulation Analysis",
        "",
        f"**Overall Manipulation Score:** {xai_result['total_manipulation_score']}/100 "
        f"({xai_result['overall_severity']})",
        "",
        f"**Tactics Detected:** {xai_result['trigger_count']} of "
        f"{len(TRIGGER_DEFINITIONS)} categories",
        "",
    ]

    for t in xai_result["triggers"]:
        lines.append(f"**{t['icon']} {t['label']}** — Score {t['raw_score']}/100")
        lines.append(f"> {t['description']}")
        lines.append(f"> Key phrases: `{'`, `'.join(t['key_phrases'][:5])}`")
        lines.append("")

    if xai_result["has_manipulation"]:
        lines.append("**⚠️ Recommendation:** This email uses psychological manipulation "
                     "tactics consistent with social engineering attacks. "
                     "Treat with heightened suspicion.")
    else:
        lines.append("**✅ No significant psychological manipulation detected.**")

    return "\n".join(lines)
