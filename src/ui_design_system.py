import streamlit as st

# ── Design Tokens ──────────────────────────────────────────────────────────────
TOKENS = {
    "dark": {
        "bg_page":        "#0b0f1a",
        "bg_card":        "#111827",
        "bg_card_hover":  "#1a2236",
        "bg_input":       "#0f172a",
        "bg_elevated":    "#1a2236",
        "bg_accent":      "#1e293b",
        "border":         "#1e293b",
        "border_focus":   "#3b82f6",
        "border_muted":   "#1e3a5f",
        "text_primary":   "#f1f5f9",
        "text_secondary": "#94a3b8",
        "text_muted":     "#64748b",
        "accent_blue":    "#3b82f6",
        "accent_indigo":  "#6366f1",
        "accent_cyan":    "#06b6d4",
        "accent_emerald": "#22c55e",
        "accent_amber":   "#f59e0b",
        "accent_red":     "#ef4444",
        "accent_rose":    "#f43f5e",
        "gradient_primary":"linear-gradient(135deg, #3b82f6, #6366f1)",
        "gradient_danger": "linear-gradient(135deg, #ef4444, #f43f5e)",
        "gradient_success":"linear-gradient(135deg, #22c55e, #10b981)",
        "shadow_sm":      "0 1px 2px rgba(0,0,0,0.3)",
        "shadow_md":      "0 4px 12px rgba(0,0,0,0.4)",
        "shadow_lg":      "0 8px 32px rgba(0,0,0,0.5)",
        "blur_bg":        "rgba(11,15,26,0.85)",
        "font_sans":      "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        "font_mono":      "'JetBrains Mono', 'Fira Code', monospace",
    },
    "light": {
        "bg_page":        "#f8fafc",
        "bg_card":        "#ffffff",
        "bg_card_hover":  "#f1f5f9",
        "bg_input":       "#ffffff",
        "bg_elevated":    "#ffffff",
        "bg_accent":      "#e2e8f0",
        "border":         "#e2e8f0",
        "border_focus":   "#3b82f6",
        "border_muted":   "#cbd5e1",
        "text_primary":   "#0f172a",
        "text_secondary": "#475569",
        "text_muted":     "#94a3b8",
        "accent_blue":    "#2563eb",
        "accent_indigo":  "#4f46e5",
        "accent_cyan":    "#0891b2",
        "accent_emerald": "#16a34a",
        "accent_amber":   "#d97706",
        "accent_red":     "#dc2626",
        "accent_rose":    "#e11d48",
        "gradient_primary":"linear-gradient(135deg, #2563eb, #4f46e5)",
        "gradient_danger": "linear-gradient(135deg, #dc2626, #e11d48)",
        "gradient_success":"linear-gradient(135deg, #16a34a, #059669)",
        "shadow_sm":      "0 1px 2px rgba(0,0,0,0.05)",
        "shadow_md":      "0 4px 12px rgba(0,0,0,0.08)",
        "shadow_lg":      "0 8px 32px rgba(0,0,0,0.12)",
        "blur_bg":        "rgba(255,255,255,0.85)",
        "font_sans":      "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        "font_mono":      "'JetBrains Mono', 'Fira Code', monospace",
    },
}

def t(token: str, theme: str = "dark") -> str:
    """Get a design token value."""
    return TOKENS.get(theme, TOKENS["dark"]).get(token, "")

def get_css(theme: str = "dark") -> str:
    T = TOKENS.get(theme, TOKENS["dark"])

    return f"""
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    * {{ font-family: {T['font_sans']}; }}

    .stApp {{
        background-color: {T['bg_page']};
    }}

    .block-container {{
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
        max-width: 1200px;
    }}

    /* ── Typography ─────────────────────────────── */
    h1, h2, h3, h4, h5, h6 {{
        font-family: {T['font_sans']} !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
        color: {T['text_primary']} !important;
    }}
    h1 {{ font-size: 1.75rem !important; }}
    h2 {{ font-size: 1.35rem !important; }}
    h3 {{ font-size: 1.1rem !important; }}
    h4 {{ font-size: 1rem !important; }}
    p, li, span, div {{ color: {T['text_secondary']}; }}
    code {{ font-family: {T['font_mono']} !important; font-size: 0.85em; }}
    .stMarkdown p {{ font-size: 0.9rem; line-height: 1.6; }}

    /* ── Cards ──────────────────────────────────── */
    .pg-card {{
        background: {T['bg_card']};
        border: 1px solid {T['border']};
        border-radius: 12px;
        padding: 20px;
        transition: all 0.2s ease;
    }}
    .pg-card:hover {{ border-color: {T['border_muted']}; }}
    .pg-card-elevated {{
        background: {T['bg_elevated']};
        border: 1px solid {T['border']};
        border-radius: 16px;
        padding: 24px;
        box-shadow: {T['shadow_md']};
    }}
    .pg-card-danger {{
        background: linear-gradient(135deg, rgba(239,68,68,0.08), rgba(244,63,94,0.05));
        border: 1px solid rgba(239,68,68,0.3);
        border-radius: 12px;
        padding: 20px;
    }}
    .pg-card-success {{
        background: linear-gradient(135deg, rgba(34,197,94,0.08), rgba(16,185,129,0.05));
        border: 1px solid rgba(34,197,94,0.3);
        border-radius: 12px;
        padding: 20px;
    }}

    /* ── Stat Cards ─────────────────────────────── */
    .pg-stat {{
        background: {T['bg_card']};
        border: 1px solid {T['border']};
        border-radius: 12px;
        padding: 16px;
        text-align: center;
    }}
    .pg-stat-value {{
        font-size: 1.75rem;
        font-weight: 800;
        color: {T['text_primary']};
        letter-spacing: -0.03em;
    }}
    .pg-stat-label {{
        font-size: 0.75rem;
        color: {T['text_muted']};
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 600;
        margin-top: 4px;
    }}

    /* ── Badges / Tags ──────────────────────────── */
    .pg-badge {{
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 10px;
        border-radius: 100px;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.03em;
    }}
    .pg-badge-critical {{ background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }}
    .pg-badge-high     {{ background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }}
    .pg-badge-medium   {{ background: rgba(234,179,8,0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.3); }}
    .pg-badge-low      {{ background: rgba(59,130,246,0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3); }}
    .pg-badge-safe     {{ background: rgba(34,197,94,0.15); color: #22c55e; border: 1px solid rgba(34,197,94,0.3); }}
    .pg-badge-info     {{ background: rgba(99,102,241,0.15); color: #6366f1; border: 1px solid rgba(99,102,241,0.3); }}

    .pg-tag {{
        display: inline-block;
        background: {T['bg_accent']};
        color: {T['text_primary']};
        border-radius: 6px;
        padding: 2px 8px;
        margin: 2px;
        font-size: 0.75rem;
        font-family: {T['font_mono']};
    }}

    /* ── Input Fields ───────────────────────────── */
    .stTextInput input, .stSelectbox, .stNumberInput input,
    .stTextArea textarea, .stDateInput input, .stTimeInput input {{
        background-color: {T['bg_input']} !important;
        color: {T['text_primary']} !important;
        border: 1px solid {T['border']} !important;
        border-radius: 8px !important;
        font-size: 0.875rem !important;
        transition: border-color 0.15s ease !important;
    }}
    .stTextInput input:focus, .stSelectbox:focus, .stNumberInput input:focus,
    .stTextArea textarea:focus {{
        border-color: {T['border_focus']} !important;
        box-shadow: 0 0 0 3px rgba(59,130,246,0.15) !important;
    }}

    /* ── Buttons ────────────────────────────────── */
    .stButton button {{
        font-family: {T['font_sans']} !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        border-radius: 8px !important;
        padding: 0.5rem 1rem !important;
        background: {T['bg_card']} !important;
        color: {T['text_primary']} !important;
        border: 1px solid {T['border']} !important;
        transition: all 0.15s ease !important;
    }}
    .stButton button:hover {{
        background: {T['bg_card_hover']} !important;
        border-color: {T['border_muted']} !important;
    }}
    .stButton button[kind="primary"] {{
        background: {T['gradient_primary']} !important;
        color: #fff !important;
        border: none !important;
    }}
    .stButton button[kind="primary"]:hover {{
        opacity: 0.9;
        box-shadow: 0 4px 14px rgba(59,130,246,0.4) !important;
    }}

    /* ── Metrics ────────────────────────────────── */
    div[data-testid="stMetric"] {{
        background: {T['bg_card']};
        border: 1px solid {T['border']};
        border-radius: 10px;
        padding: 12px 16px;
    }}
    div[data-testid="stMetric"] > div:first-child {{
        font-size: 0.75rem !important;
        color: {T['text_muted']} !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
    }}
    div[data-testid="stMetric"] > div:nth-child(2) {{
        font-size: 1.5rem !important;
        font-weight: 800 !important;
        color: {T['text_primary']} !important;
        letter-spacing: -0.02em;
    }}

    /* ── Dividers ───────────────────────────────── */
    hr, .stDivider {{
        border-color: {T['border']} !important;
        margin: 1.5rem 0 !important;
    }}

    /* ── Tabs ───────────────────────────────────── */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 4px;
        background: {T['bg_card']};
        padding: 4px;
        border-radius: 10px;
        border: 1px solid {T['border']};
        overflow-x: auto;
        flex-wrap: nowrap;
    }}
    .stTabs [data-baseweb="tab"] {{
        font-size: 0.78rem !important;
        font-weight: 500 !important;
        color: {T['text_muted']} !important;
        padding: 6px 12px !important;
        border-radius: 6px !important;
        white-space: nowrap;
        transition: all 0.15s ease;
    }}
    .stTabs [data-baseweb="tab"]:hover {{
        color: {T['text_primary']} !important;
        background: {T['bg_accent']};
    }}
    .stTabs [aria-selected="true"] {{
        background: {T['gradient_primary']} !important;
        color: #fff !important;
        font-weight: 600 !important;
    }}

    /* ── DataFrames / Tables ────────────────────── */
    div[data-testid="stDataFrame"] {{
        background: {T['bg_card']} !important;
        border: 1px solid {T['border']} !important;
        border-radius: 10px !important;
    }}
    div[data-testid="stDataFrame"] th {{
        font-size: 0.75rem !important;
        color: {T['text_muted']} !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
    }}

    /* ── Expander ───────────────────────────────── */
    .streamlit-expanderHeader {{
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        color: {T['text_primary']} !important;
        background: {T['bg_card']} !important;
        border: 1px solid {T['border']} !important;
        border-radius: 8px !important;
        padding: 8px 12px !important;
        margin: 4px 0 !important;
    }}
    .streamlit-expanderContent {{
        border: 1px solid {T['border']} !important;
        border-top: none !important;
        border-radius: 0 0 8px 8px !important;
        padding: 12px !important;
        background: {T['bg_page']} !important;
    }}

    /* ── Progress / Progress Bars ───────────────── */
    .stProgress > div > div {{
        background: {T['gradient_primary']} !important;
        border-radius: 100px !important;
    }}
    .stProgress > div {{
        background: {T['bg_accent']} !important;
        border-radius: 100px !important;
    }}

    /* ── Alerts / Info / Warning / Error ────────── */
    div[data-testid="stAlert"] {{
        border-radius: 10px !important;
        font-size: 0.85rem !important;
    }}
    .stAlert {{
        border-radius: 10px !important;
        padding: 12px 16px !important;
    }}
    div[data-testid="stAlert"] svg {{ display: inline !important; }}
    .stAlert p {{ font-size: 0.85rem !important; }}
    div[data-testid="stNotification"] {{ border-radius: 12px !important; }}

    /* ── Sidebar ────────────────────────────────── */
    section[data-testid="stSidebar"] {{
        background: {T['bg_page']} !important;
        border-right: 1px solid {T['border']} !important;
    }}
    section[data-testid="stSidebar"] .stButton button {{
        width: 100%;
        justify-content: flex-start;
        text-align: left;
    }}

    /* ── Section Title ──────────────────────────── */
    .pg-section-title {{
        color: {T['accent_blue']} !important;
        font-size: 0.85rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin: 24px 0 12px 0;
        padding-left: 12px;
        border-left: 3px solid {T['accent_blue']};
    }}

    /* ── Quota Bar ──────────────────────────────── */
    .pg-quota-bg {{
        background: {T['bg_accent']};
        border-radius: 6px;
        height: 8px;
        overflow: hidden;
    }}
    .pg-quota-fill {{
        height: 100%;
        border-radius: 6px;
        transition: width 0.3s ease;
    }}

    /* ── Quarantine Badge ───────────────────────── */
    .pg-quarantine {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(244,63,94,0.1));
        color: #ef4444;
        border: 1px solid rgba(239,68,68,0.3);
        border-radius: 100px;
        padding: 4px 14px;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }}

    /* ── URL Boxes ──────────────────────────────── */
    .pg-url {{
        font-family: {T['font_mono']};
        font-size: 0.8rem;
        padding: 8px 12px;
        border-radius: 8px;
        margin: 4px 0;
        word-break: break-all;
    }}
    .pg-url-danger {{
        background: rgba(239,68,68,0.08);
        border: 1px solid rgba(239,68,68,0.3);
        color: #fca5a5;
    }}
    .pg-url-safe {{
        background: rgba(34,197,94,0.08);
        border: 1px solid rgba(34,197,94,0.3);
        color: #86efac;
    }}

    /* ── Responsive ─────────────────────────────── */
    @media (max-width: 768px) {{
        .block-container {{ padding: 0.75rem 0.5rem !important; }}
        h1 {{ font-size: 1.4rem !important; }}
        h2 {{ font-size: 1.15rem !important; }}

        .stTabs [data-baseweb="tab"] {{
            font-size: 0.7rem !important;
            padding: 4px 8px !important;
        }}
        div[data-testid="column"] {{ min-width: 100% !important; }}
        .pg-stat {{ padding: 10px !important; }}
        .pg-card {{ padding: 14px !important; }}
        .pg-stat-value {{ font-size: 1.3rem !important; }}
    }}

    /* ── Misc ───────────────────────────────────── */
    div[data-testid="stImage"] img {{ border-radius: 8px; }}
    .stToast {{ border-radius: 10px; }}
    .stSpinner {{ font-size: 0.85rem; color: {T['text_secondary']}; }}
    """

def inject_design_system(theme: str = "dark"):
    st.markdown(f"<style>{get_css(theme)}</style>", unsafe_allow_html=True)

def card(html_content: str, elevated: bool = False, css_class: str = "") -> str:
    cls = "pg-card-elevated" if elevated else "pg-card"
    if css_class:
        cls += f" {css_class}"
    return f'<div class="{cls}">{html_content}</div>'

def stat_card(value: str, label: str, color: str = "") -> str:
    style = f"color:{color};" if color else ""
    return (
        '<div class="pg-stat">'
        f'<div class="pg-stat-value" style="{style}">{value}</div>'
        f'<div class="pg-stat-label">{label}</div>'
        '</div>'
    )

def badge(label: str, severity: str = "info") -> str:
    return f'<span class="pg-badge pg-badge-{severity.lower()}">{label}</span>'

def section_title(label: str) -> str:
    return f'<div class="pg-section-title">{label}</div>'

def url_box(url: str, is_danger: bool = True) -> str:
    cls = "pg-url pg-url-danger" if is_danger else "pg-url pg-url-safe"
    return f'<div class="{cls}">{"🚨" if is_danger else "🔗"} {url}</div>'

def empty_state(icon: str, title: str, description: str, action_label: str = "", action_key: str = "") -> str:
    action = ""
    if action_label:
        action = f'<div style="margin-top:16px"><button onclick="alert(\'redirect\')" style="background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff;border:none;border-radius:8px;padding:8px 20px;font-weight:600;font-size:0.85rem;cursor:pointer">{action_label}</button></div>'
    return (
        f'<div style="text-align:center;padding:60px 20px;background:#111827;border:1px solid #1e293b;'
        f'border-radius:16px;margin:20px 0">'
        f'<div style="font-size:3rem;margin-bottom:12px">{icon}</div>'
        f'<div style="font-size:1.1rem;font-weight:700;color:#f1f5f9;margin-bottom:6px">{title}</div>'
        f'<div style="font-size:0.85rem;color:#64748b;max-width:360px;margin:0 auto 8px;line-height:1.5">{description}</div>'
        f'{action}</div>'
    )

def feature_gate(feature: str, plan: str, plans: dict, upgrade_callback: str = "") -> str:
    """Render an upgrade CTA if the plan doesn't include the requested feature."""
    if feature in plans.get(plan, {}).get("features", []):
        return ""
    next_tier = None
    tier_order = ["free", "trial", "starter", "professional", "business", "enterprise", "consultant"]
    for t in tier_order:
        if feature in plans.get(t, {}).get("features", []):
            next_tier = plans[t]["label"]
            break
    upgrade_link = ' <a href="#" style="color:#a855f7">Upgrade now →</a>' if upgrade_callback else ""
    return (
        f'<div style="background:linear-gradient(135deg,#1a0a1a,#2a0f2a);border:2px solid #a855f7;'
        f'border-radius:16px;padding:24px 20px;text-align:center;margin:12px 0">'
        f'<div style="font-size:2rem;margin-bottom:6px">🔒</div>'
        f'<div style="color:#f0f6ff;font-size:1rem;font-weight:700;margin-bottom:4px">'
        f'Upgrade Required</div>'
        f'<div style="color:#94a3b8;font-size:0.85rem">This feature requires the '
        f'<strong>{next_tier or "Enterprise"}</strong> plan or higher.'
        f'{upgrade_link}</div>'
        f'</div>'
    )

def progress_bar(pct: int, color: str = "#3b82f6", height: int = 6) -> str:
    return (
        f'<div style="background:#1e293b;border-radius:6px;height:{height}px;overflow:hidden">'
        f'<div style="background:{color};width:{min(pct,100)}%;height:100%;'
        f'border-radius:6px;transition:width 0.3s ease"></div></div>'
    )

def metric_row(metrics: list) -> str:
    """Render a row of stat cards. metrics = [(value, label, color?), ...]"""
    cols = "".join(
        f'<div style="flex:1;background:#111827;border:1px solid #1e293b;border-radius:10px;'
        f'padding:12px 8px;text-align:center">'
        f'<div style="font-size:1.3rem;font-weight:800;color:{c or "#f1f5f9"};letter-spacing:-0.02em">{v}</div>'
        f'<div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;'
        f'font-weight:600;margin-top:2px">{lb}</div></div>'
        for v, lb, *rest in metrics
        for c in (rest[0] if rest else [None])
    )
    return f'<div style="display:flex;gap:8px;margin:12px 0">{cols}</div>'
