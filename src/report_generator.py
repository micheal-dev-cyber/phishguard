import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fpdf import FPDF

logger = logging.getLogger(__name__)


class PhishGuardReport(FPDF):
    def __init__(self, white_label: bool = False, custom_logo_path: Optional[str] = None):
        super().__init__()
        self.white_label = white_label
        self.custom_logo_path = custom_logo_path
        self.brand_name = "Confidential Security Report" if white_label else "SecOpsNode AI  |  PhishGuard"
        self.brand_subtitle = "" if white_label else "Enterprise Threat Intelligence & Defense Platform"

    def header(self):
        self.set_fill_color(8, 12, 24)
        self.rect(0, 0, 210, 32, "F")
        if self.custom_logo_path:
            try:
                self.image(self.custom_logo_path, x=12, y=4, w=30)
            except Exception as e:
                logger.warning("report_generator: Failed to load custom logo: %s", e)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(56, 132, 255)
        self.set_xy(12, 6)
        self.cell(0, 8, self.brand_name, ln=False)
        if self.brand_subtitle:
            self.set_font("Helvetica", "", 8)
            self.set_text_color(100, 116, 139)
            self.set_xy(12, 16)
            self.cell(0, 6, self.brand_subtitle, ln=False)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(56, 132, 255)
        self.set_xy(160, 8)
        self.cell(40, 6, "CONFIDENTIAL", align="R")
        self.set_xy(160, 15)
        self.set_text_color(148, 163, 184)
        self.cell(40, 5, f"Page {self.page_no()}", align="R")
        self.ln(28)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(71, 85, 105)
        brand_footer = "Confidential Security Report" if self.white_label else "SecOpsNode AI | PhishGuard"
        self.cell(0, 8,
                  f"{brand_footer}  |  Confidential Security Report  |  Page {self.page_no()}",
                  align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(56, 132, 255)
        self.set_fill_color(15, 20, 35)
        self.cell(0, 8, "  " + title, ln=True, fill=True)
        self.ln(2)

    def info_row(self, label: str, value: str):
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(148, 163, 184)
        self.cell(50, 6, label)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(226, 232, 240)
        self.cell(0, 6, str(value), ln=True)

    def bullet(self, text: str, indent: int = 8):
        self.set_font("Helvetica", "", 8)
        self.set_text_color(226, 232, 240)
        x0 = self.get_x()
        self.cell(indent, 5, "-")
        self.multi_cell(0, 5, text)
        self.set_x(x0)


def clean_text(text: str) -> str:
    """Remove characters that fpdf cannot encode (Latin-1 safe)."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _draw_risk_gauge(pdf: FPDF, score: int, severity: str, sev_color: tuple):
    """Draw a visual risk gauge bar."""
    y_start = pdf.get_y()
    pdf.set_fill_color(17, 24, 39)
    pdf.set_draw_color(*sev_color)
    pdf.set_line_width(0.6)
    # Outer border box
    pdf.rect(12, y_start, 186, 36, "DF")
    # Score number
    pdf.set_xy(20, y_start + 4)
    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(*sev_color)
    pdf.cell(42, 16, str(score))
    # Severity label
    pdf.set_xy(62, y_start + 4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(60, 12, f"/ 100 - {severity} THREAT")
    # Stats line
    pdf.set_xy(20, y_start + 22)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(148, 163, 184)
    # Fill gauge bar
    bar_x = 132
    bar_w = 60
    bar_y = y_start + 8
    bar_h = 8
    pdf.set_fill_color(30, 41, 59)
    pdf.rect(bar_x, bar_y, bar_w, bar_h, "F")
    fill_w = max(int(bar_w * score / 100), 4)
    pdf.set_fill_color(*sev_color)
    pdf.rect(bar_x, bar_y, fill_w, bar_h, "F")
    pdf.ln(40)


def _add_risk_matrix(pdf: FPDF, score: int):
    """Draw a semantic risk matrix table."""
    pdf.section_title("SEMANTIC RISK MATRIX")
    levels = [
        ("0-24", "LOW", "Routine communication. Standard vigilance advised.", (22, 163, 74)),
        ("25-49", "MEDIUM", "Suspicious elements present. Verify before acting.", (202, 138, 4)),
        ("50-74", "HIGH", "Multiple phishing indicators. Treat with extreme caution.", (234, 88, 12)),
        ("75-100", "CRITICAL", "Strong phishing indicators. Do not interact. Escalate immediately.", (220, 38, 38)),
    ]
    col_w = [18, 18, 108, 36]
    headers = ["Score", "Level", "Assessment", "Action"]
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(148, 163, 184)
    for i, h in enumerate(headers):
        pdf.cell(col_w[i], 7, h, border=0, fill=True)
    pdf.ln()
    for low_high, label, desc, color in levels:
        low, high = low_high.split("-")
        is_current = int(low) <= score <= int(high)
        if is_current:
            pdf.set_fill_color(*color)
            pdf.set_text_color(255, 255, 255)
        else:
            pdf.set_fill_color(15, 20, 35)
            pdf.set_text_color(100, 116, 139)
        pdf.set_font("Helvetica", "B" if is_current else "", 7)
        pdf.cell(col_w[0], 6, f"{low}-{high}", fill=True)
        pdf.cell(col_w[1], 6, label, fill=True)
        pdf.cell(col_w[2], 6, clean_text(desc), fill=True)
        pdf.cell(col_w[3], 6, "IMMEDIATE" if is_current and label in ("HIGH", "CRITICAL") else "REVIEW" if is_current else "NONE", fill=True)
        pdf.ln()
    pdf.ln(3)


def _add_linguistic_breakdown(pdf: FPDF, results: Dict[str, Any]):
    """Add detailed linguistic analysis breakdown."""
    lang = results.get("language_analysis", {})
    findings = lang.get("findings", [])
    if not findings:
        findings = []
        if results.get("keyword_matches"):
            for cat in results["keyword_matches"]:
                findings.append(f"Keyword category triggered: {cat}")
    if findings:
        pdf.section_title("LINGUISTIC ANALYSIS BREAKDOWN")
        for f in findings:
            pdf.bullet(clean_text(f))
        pdf.ln(2)

    urgency = lang.get("urgency_count", 0)
    fear = lang.get("fear_count", 0)
    caps_ratio = lang.get("caps_ratio", 0)
    if urgency or fear or caps_ratio:
        if not findings:
            pdf.section_title("LINGUISTIC METRICS")
        metrics = []
        if urgency:
            metrics.append(f"Urgency triggers: {urgency}")
        if fear:
            metrics.append(f"Fear/intimidation triggers: {fear}")
        if caps_ratio:
            metrics.append(f"Excessive capitalization ratio: {caps_ratio*100:.0f}%")
        for m in metrics:
            pdf.info_row("", m)
        pdf.ln(2)


def _add_recommendations(pdf: FPDF, severity: str):
    """Add contextual, severity-tailored mitigation steps."""
    pdf.section_title("MITIGATION & REMEDIATION STEPS")
    core = [
        "Do not click any links contained in this email",
        "Do not download or open any attachments",
        "Do not reply to this email or contact the sender",
    ]
    if severity in ("CRITICAL", "HIGH"):
        core.extend([
            "Report this email to your IT/Security team immediately",
            "Quarantine the sender domain at the gateway level",
            "If you clicked any links, initiate password reset and enable MFA",
            "Scan affected endpoints for malware or unauthorised access",
        ])
    else:
        core.extend([
            "Report this email to your IT or security team",
            "Delete the email from your inbox and trash after reporting",
            "Verify any claims directly through official channels",
        ])
    core.extend([
        "Forward the email to reportphishing@apwg.org",
        "Monitor your accounts for any unauthorised activity",
    ])
    for rec in core:
        pdf.bullet(rec)
    pdf.ln(3)


def _add_email_preview(pdf: FPDF, email_text: str):
    """Add the full email content preview."""
    pdf.section_title("FULL SCANNED EMAIL TEXT")
    pdf.set_font("Courier", "", 7)
    pdf.set_text_color(148, 163, 184)
    # Use full text, split into manageable chunks
    full = clean_text(email_text.replace("\r", ""))
    if len(full) > 2000:
        pdf.multi_cell(0, 4, full[:2000])
        pdf.set_text_color(56, 132, 255)
        pdf.cell(0, 4, "... [report truncated at 2000 characters]", ln=True)
    else:
        pdf.multi_cell(0, 4, full)
    pdf.ln(3)


def _add_header_analysis(pdf: FPDF, results: Dict[str, Any]):
    """Add header and sender analysis section."""
    header = results.get("header_analysis", {})
    findings = header.get("findings", [])
    if findings:
        pdf.section_title("HEADER & SENDER ANALYSIS")
        for f in findings:
            pdf.bullet(clean_text(f))
        pdf.ln(2)


def generate_pdf_report(results: dict, email_text: str,
                         ai_report: str = "",
                         white_label: bool = False,
                         custom_logo_path: Optional[str] = None) -> bytes:
    """Generate a comprehensive, branded PDF security report.

    Features:
    - Full threat summary with visual risk gauge
    - Semantic risk matrix table
    - Linguistic analysis breakdown
    - Header and sender analysis
    - Suspicious URLs and keyword matches
    - Mitigation steps tailored to severity
    - Full scanned email text
    - AI analysis (if provided)
    - Disclaimer and compliance footer
    - White-label mode strips branding (Consultant tier)
    - Custom logo support for white-label reports
    """
    pdf = PhishGuardReport(white_label=white_label, custom_logo_path=custom_logo_path)
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.add_page()
    pdf.set_margins(12, 38, 12)

    score = results.get("risk_score", 0)
    severity = results.get("severity", "LOW")

    if score >= 75:
        sev_color = (220, 38, 38)
    elif score >= 50:
        sev_color = (234, 88, 12)
    elif score >= 25:
        sev_color = (202, 138, 4)
    else:
        sev_color = (22, 163, 74)

    # Report information
    pdf.section_title("REPORT INFORMATION")
    pdf.info_row("Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    if not pdf.white_label:
        pdf.info_row("Platform:", "SecOpsNode AI | PhishGuard")
        pdf.info_row("Engine:", "v3.5 Enterprise Detection Engine")
    pdf.info_row("Threat Level:", severity)
    pdf.ln(3)

    # Threat assessment summary with visual gauge
    pdf.section_title("THREAT ASSESSMENT SUMMARY")
    _draw_risk_gauge(pdf, score, severity, sev_color)

    # Stats line below gauge
    pdf.info_row("Total Keywords Hit:", str(results.get("total_keyword_hits", 0)))
    pdf.info_row("URLs Found:", str(results.get("url_count", 0)))
    pdf.info_row("Suspicious URLs:", str(results.get("suspicious_url_count", 0)))
    pdf.info_row("Attachments Detected:", "Yes" if results.get("has_attachments") else "No")
    pdf.ln(3)

    # Security verdict explanation (Threat Explanation Engine)
    pdf.section_title("SECURITY VERDICT")
    try:
        from src.threat_explainer import build_explanation
        explanation = build_explanation(results)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(226, 232, 240)
        pdf.multi_cell(0, 5, clean_text(explanation["verdict"]["detail"]))
        pdf.ln(2)
        if explanation.get("triggers"):
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(56, 132, 255)
            pdf.cell(0, 6, "  WHAT TRIGGERED THIS DETECTION:", ln=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(226, 232, 240)
            for trigger in explanation["triggers"][:6]:
                clean_trig = clean_text(trigger.replace("**", "").replace("—", "-"))
                pdf.bullet(clean_trig[:120])
            pdf.ln(2)
    except Exception:
        verdicts = {
            "CRITICAL": "Strong phishing indicators. Do not interact.",
            "HIGH": "Multiple suspicious elements. Exercise extreme caution.",
            "MEDIUM": "Some suspicious elements. Verify before acting.",
            "LOW": "No major indicators. Standard vigilance advised.",
        }
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(226, 232, 240)
        pdf.multi_cell(0, 5, verdicts.get(severity, ""))
    pdf.ln(4)

    # Risk matrix
    _add_risk_matrix(pdf, score)

    # Header analysis
    _add_header_analysis(pdf, results)

    # Linguistic breakdown
    _add_linguistic_breakdown(pdf, results)

    # BEC Detection (add to PDF)
    try:
        from src.bec_detector import detect_bec
        bec_result = detect_bec("", results)
        if bec_result.get("bec_detected"):
            pdf.section_title("BUSINESS EMAIL COMPROMISE ANALYSIS")
            pdf.info_row("BEC Type:", bec_result.get("bec_type", "").replace("_", " ").title())
            pdf.info_row("Confidence:", f"{bec_result.get('confidence',0)}%")
            for detail in bec_result.get("details", []):
                pdf.bullet(clean_text(detail.replace("**", "")))
            pdf.ln(2)
    except Exception:
        pass

    # Red Flags Section
    try:
        from src.red_flags import detect_red_flags
        red_flags = detect_red_flags(results)
        if red_flags:
            pdf.section_title("EMAIL RED FLAGS IDENTIFIED")
            for flag in red_flags[:6]:
                sev = flag.get("severity", "low")
                label = f"{flag['icon']} {flag['label']} ({sev.upper()})"
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color({"critical": (220,38,38), "high": (249,115,22), "medium": (234,179,8), "low": (148,163,184)}.get(sev, (148,163,184)))
                pdf.cell(0, 6, clean_text(label), ln=True)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(226, 232, 240)
                pdf.set_x(20)
                pdf.multi_cell(0, 5, clean_text(flag.get("description", "")))
                pdf.ln(1)
            pdf.ln(2)
    except Exception:
        pass

    # Tactic Classification
    try:
        from src.tactic_classifier import classify_tactics, get_primary_tactic
        tactics = classify_tactics("", results)
        if tactics:
            primary = get_primary_tactic(tactics)
            pdf.section_title("PHISHING TACTIC CLASSIFICATION")
            if primary:
                pdf.info_row("Primary Tactic:", f"{primary.get('icon','')} {primary.get('label','')} ({primary.get('confidence',0)}% match)")
                pdf.info_row("Description:", primary.get("description", ""))
            if len(tactics) > 1:
                others = [f"{t.get('label','')} ({t.get('confidence',0)}%)" for t in tactics[1:4]]
                pdf.info_row("Other Tactics:", ", ".join(others))
            pdf.ln(2)
    except Exception:
        pass

    # Phishing indicators (keywords)
    if results.get("keyword_matches"):
        pdf.section_title("PHISHING INDICATORS DETECTED")
        for category, keywords in results["keyword_matches"].items():
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(56, 132, 255)
            pdf.cell(0, 6, f"  {category.upper()} ({len(keywords)} matches)", ln=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(226, 232, 240)
            pdf.set_x(20)
            pdf.multi_cell(0, 5, clean_text(",  ".join(keywords)))
            pdf.ln(1)
        pdf.ln(2)

    # Suspicious URLs
    if results.get("suspicious_urls"):
        pdf.section_title("SUSPICIOUS URLS DETECTED")
        for item in results["suspicious_urls"]:
            pdf.bullet(clean_text(item["url"][:100]))
        pdf.ln(2)
    elif results.get("urls_found"):
        pdf.section_title("URLS FOUND (NO THREATS DETECTED)")
        for url in results["urls_found"]:
            pdf.bullet(clean_text(url[:100]))
        pdf.ln(2)

    # Attachment warning
    if results.get("has_attachments"):
        pdf.section_title("ATTACHMENT WARNING")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(226, 232, 240)
        pdf.multi_cell(0, 5,
            "This email references attachments or file downloads. "
            "Do NOT open any attachments from this sender. "
            "Malicious attachments are a primary vector for malware delivery.")
        pdf.ln(2)

    # Mitigation & remediation
    _add_recommendations(pdf, severity)

    # Security Action Center
    try:
        from src.security_action_center import get_security_actions, get_action_summary
        sac_actions = get_security_actions(results)
        if sac_actions:
            pdf.add_page()
            pdf.section_title("SECURITY ACTION CENTER")
            summary = get_action_summary(sac_actions)
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(148, 163, 184)
            pdf.multi_cell(0, 4, clean_text(summary))
            pdf.ln(2)
            cat_order = ["immediate", "containment", "investigation", "prevention", "reporting"]
            cat_labels = {"immediate": "IMMEDIATE ACTIONS", "containment": "CONTAINMENT",
                          "investigation": "INVESTIGATION", "prevention": "PREVENTION",
                          "reporting": "REPORTING"}
            for cat in cat_order:
                cat_actions = [a for a in sac_actions if a.get("category") == cat]
                if not cat_actions:
                    continue
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(56, 132, 255)
                pdf.cell(0, 6, f"  {cat_labels.get(cat, cat)}", ln=True)
                for a in cat_actions[:4]:
                    pdf.set_font("Helvetica", "", 7)
                    pdf.set_text_color(226, 232, 240)
                    pdf.set_x(14)
                    pdf.multi_cell(176, 4, f"{a.get('icon','')} [{a.get('priority','').upper()}] {clean_text(a.get('title',''))}")
                    pdf.set_font("Helvetica", "I", 6)
                    pdf.set_text_color(148, 163, 184)
                    pdf.set_x(14)
                    pdf.multi_cell(176, 3, clean_text(a.get('instructions', ''))[:200])
                    pdf.ln(1)
    except Exception:
        pass

    # Educational content
    try:
        from src.educational_content import get_educational_content
        edu_modules = get_educational_content(results, [])
        if edu_modules:
            pdf.add_page()
            pdf.section_title("EDUCATIONAL: HOW TO SPOT THIS ATTACK")
            for mod in edu_modules[:3]:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(56, 132, 255)
                pdf.cell(0, 6, f"  {mod['icon']} {mod['title']}", ln=True)
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(226, 232, 240)
                content_clean = clean_text(mod['content'].replace("**", "").replace("###", "").replace("##", ""))
                pdf.set_x(14)
                pdf.multi_cell(176, 4, content_clean[:600])
                pdf.ln(3)
    except Exception:
        pass

    # Full email content
    _add_email_preview(pdf, email_text)

    # AI analysis
    if ai_report:
        pdf.add_page()
        pdf.section_title("AI SECURITY ANALYSIS")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(226, 232, 240)
        clean = clean_text(
            ai_report.replace("**", "").replace("###", "").replace("##", "")
        )
        pdf.multi_cell(0, 5, clean)
        pdf.ln(3)

    # Disclaimer
    pdf.section_title("DISCLAIMER")
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(71, 85, 105)
    disclaimer = (
        "This report was generated automatically by a security analysis engine. "
        if pdf.white_label else
        "This report was generated automatically by PhishGuard AI (SecOpsNode AI). "
    )
    pdf.multi_cell(0, 4,
        disclaimer +
        "It is intended for informational and educational purposes only. "
        "Always consult a qualified cybersecurity professional for critical security decisions. "
        "This report does not constitute a formal security audit or guarantee of threat detection.")

    return bytes(pdf.output())
