from fpdf import FPDF
from datetime import datetime


class PhishGuardReport(FPDF):
    def header(self):
        self.set_fill_color(10, 14, 26)
        self.rect(0, 0, 210, 30, "F")
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(96, 165, 250)
        self.set_xy(10, 8)
        self.cell(0, 10, "PHISHGUARD AI", ln=False)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(148, 163, 184)
        self.set_xy(10, 18)
        self.cell(0, 6, "AI-Powered Phishing & Threat Detection Report")
        self.ln(25)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10,
                  f"PhishGuard AI | Confidential Security Report | Page {self.page_no()}",
                  align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(96, 165, 250)
        self.set_fill_color(17, 24, 39)
        self.cell(0, 9, f"  {title}", ln=True, fill=True)
        self.ln(2)

    def info_row(self, label, value):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(148, 163, 184)
        self.cell(55, 7, label)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(226, 232, 240)
        self.cell(0, 7, str(value), ln=True)

    def bullet(self, text):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(226, 232, 240)
        self.cell(8, 6, "-")
        self.cell(0, 6, text, ln=True)


def clean_text(text: str) -> str:
    """Remove characters that fpdf cannot encode."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_report(results: dict, email_text: str,
                         ai_report: str = "") -> bytes:

    pdf = PhishGuardReport()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()
    pdf.set_margins(12, 35, 12)

    score    = results["risk_score"]
    severity = results["severity"]

    if score >= 75:
        sev_color = (220, 38, 38)
    elif score >= 50:
        sev_color = (234, 88, 12)
    elif score >= 25:
        sev_color = (202, 138, 4)
    else:
        sev_color = (22, 163, 74)

    # Report info
    pdf.section_title("REPORT INFORMATION")
    pdf.info_row("Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    pdf.info_row("Report Type:", "Phishing Email Analysis")
    pdf.info_row("Analyzed By:", "PhishGuard AI Detection Engine")
    pdf.ln(4)

    # Risk summary box
    pdf.section_title("THREAT ASSESSMENT SUMMARY")
    pdf.set_fill_color(17, 24, 39)
    pdf.set_draw_color(*sev_color)
    pdf.set_line_width(0.8)
    pdf.rect(12, pdf.get_y(), 186, 28, "DF")

    y = pdf.get_y() + 4
    pdf.set_xy(20, y)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*sev_color)
    pdf.cell(40, 12, str(score))

    pdf.set_xy(60, y)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(40, 12, f"/ 100 - {severity} THREAT")

    pdf.set_xy(20, y + 13)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 6,
             f"URLs: {results['url_count']}  |  "
             f"Suspicious URLs: {results['suspicious_url_count']}  |  "
             f"Keywords: {results['total_keyword_hits']}  |  "
             f"Attachments: {'Yes' if results['has_attachments'] else 'No'}")
    pdf.ln(32)

    # Verdict
    pdf.section_title("SECURITY VERDICT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(226, 232, 240)
    verdicts = {
        "CRITICAL": (
            "This email exhibits strong indicators of a phishing attack. "
            "Do not click any links, do not download attachments, and do not reply. "
            "Report immediately to your IT security team and delete the email."
        ),
        "HIGH": (
            "This email contains several suspicious elements consistent with phishing. "
            "Exercise extreme caution. Verify the sender through official channels "
            "before taking any action."
        ),
        "MEDIUM": (
            "This email contains some suspicious elements. Verify the sender identity "
            "before clicking any links or providing any information."
        ),
        "LOW": (
            "No major phishing indicators detected. However, always remain vigilant "
            "and verify unexpected emails."
        ),
    }
    pdf.multi_cell(0, 6, verdicts.get(severity, ""))
    pdf.ln(4)

    # Keywords
    if results["keyword_matches"]:
        pdf.section_title("PHISHING INDICATORS DETECTED")
        for category, keywords in results["keyword_matches"].items():
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(96, 165, 250)
            pdf.cell(0, 7, f"  {category.upper()} ({len(keywords)} matches)", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(226, 232, 240)
            pdf.set_x(20)
            pdf.cell(0, 6, clean_text(",  ".join(keywords)), ln=True)
            pdf.ln(1)
        pdf.ln(3)

    # URLs
    if results["suspicious_urls"]:
        pdf.section_title("SUSPICIOUS URLS DETECTED")
        for item in results["suspicious_urls"]:
            pdf.bullet(clean_text(item["url"][:90]))
        pdf.ln(3)
    elif results["urls_found"]:
        pdf.section_title("URLS FOUND (NO THREATS DETECTED)")
        for url in results["urls_found"]:
            pdf.bullet(clean_text(url[:90]))
        pdf.ln(3)

    # Attachments
    if results["has_attachments"]:
        pdf.section_title("ATTACHMENT WARNING")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(226, 232, 240)
        pdf.multi_cell(0, 6,
            "This email references attachments or file downloads. "
            "Do NOT open any attachments from this sender. "
            "Malicious attachments are a primary vector for malware delivery.")
        pdf.ln(3)

    # Recommendations
    pdf.section_title("RECOMMENDED ACTIONS")
    recs = [
        "Do not click any links contained in this email",
        "Do not download or open any attachments",
        "Do not reply to this email or contact the sender",
        "Report this email to your IT or security team immediately",
        "Delete the email from your inbox and trash",
        "If you clicked a link, change your passwords immediately",
        "Monitor your accounts for unauthorized activity",
        "Report phishing to: reportphishing@apwg.org",
    ]
    for rec in recs:
        pdf.bullet(rec)
    pdf.ln(4)

    # Email preview
    pdf.section_title("EMAIL CONTENT PREVIEW")
    pdf.set_font("Courier", "", 8)
    pdf.set_text_color(148, 163, 184)
    preview = clean_text(email_text[:600].replace("\r", ""))
    pdf.multi_cell(0, 5, preview)
    if len(email_text) > 600:
        pdf.set_text_color(96, 165, 250)
        pdf.cell(0, 5, "... [truncated for report]", ln=True)
    pdf.ln(4)

    # AI report
    if ai_report:
        pdf.add_page()
        pdf.section_title("AI SECURITY ANALYSIS")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(226, 232, 240)
        clean = clean_text(
            ai_report.replace("**", "").replace("###", "").replace("##", "")
        )
        pdf.multi_cell(0, 6, clean)
        pdf.ln(4)

    # Disclaimer
    pdf.section_title("DISCLAIMER")
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(0, 5,
        "This report was generated automatically by PhishGuard AI. "
        "It is intended for informational purposes only. "
        "Always consult a qualified cybersecurity professional for critical decisions.")

    return bytes(pdf.output())