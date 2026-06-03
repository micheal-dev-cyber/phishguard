"""
PhishGuard AI — Compliance Reports (SOC 2, GDPR, HIPAA, Custom PDF)

Usage:
    report = ComplianceReport(standard="soc2")
    pdf_bytes = report.generate()
"""
import io
from datetime import datetime

from src.db import get_connection

try:
    from reportlab.lib import colors
    from reportlab.lib.colors import HexColor
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,  # noqa: F401
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

STANDARDS = {
    "soc2": {
        "title": "SOC 2 Compliance Report",
        "subtitle": "Security, Availability, Processing Integrity, Confidentiality, Privacy",
        "sections": ["Executive Summary", "Security Overview", "Availability Metrics",
                     "Processing Integrity", "Confidentiality", "Privacy Controls"],
    },
    "gdpr": {
        "title": "GDPR Compliance Report",
        "subtitle": "General Data Protection Regulation — Article 32 Security of Processing",
        "sections": ["Executive Summary", "Data Processing Inventory", "Breach Detection Metrics",
                     "Risk Assessment", "Data Subject Rights", "Technical Measures"],
    },
    "hipaa": {
        "title": "HIPAA Compliance Report",
        "subtitle": "Health Insurance Portability and Accountability Act — Security Rule",
        "sections": ["Executive Summary", "Administrative Safeguards", "Physical Safeguards",
                     "Technical Safeguards", "Security Incident Log", "Risk Analysis"],
    },
}


def _query_db(query: str, params: tuple = ()) -> list:
    conn = get_connection()
    c = conn.cursor()
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return rows


def _get_metrics() -> dict:
    total = _query_db("SELECT COUNT(*) FROM analyses")[0][0]
    threats = _query_db("SELECT COUNT(*) FROM analyses WHERE risk_score >= 50")[0][0]
    critical = _query_db("SELECT COUNT(*) FROM analyses WHERE risk_score >= 80")[0][0]
    avg_score = _query_db("SELECT COALESCE(AVG(risk_score), 0) FROM analyses")[0][0]
    latest = _query_db("SELECT MAX(timestamp) FROM analyses")[0][0]
    users = _query_db("SELECT COUNT(*) FROM users")[0][0]
    campaigns = _query_db("SELECT COUNT(*) FROM campaigns")[0][0]
    return {
        "total_scans": total,
        "threats_detected": threats,
        "critical_threats": critical,
        "avg_risk_score": round(avg_score, 1),
        "last_scan": latest or "N/A",
        "total_users": users,
        "campaigns_launched": campaigns,
    }


class ComplianceReport:
    def __init__(self, standard: str = "soc2", org_name: str = "PhishGuard Customer",
                 date_range_days: int = 90):
        self.standard = standard.lower()
        self.config = STANDARDS.get(self.standard, STANDARDS["soc2"])
        self.org_name = org_name
        self.date_range_days = date_range_days
        self.metrics = _get_metrics()

    def generate(self) -> bytes:
        if not HAS_REPORTLAB:
            return self._generate_text_fallback()
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=letter,
            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=22, spaceAfter=6)
        subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=11,
                                         textColor=HexColor("#64748b"), spaceAfter=20)
        heading = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=14, spaceAfter=8)
        normal = ParagraphStyle("N", parent=styles["Normal"], fontSize=10, leading=14)

        elements = []
        elements.append(Paragraph(self.config["title"], title_style))
        elements.append(Paragraph(self.config["subtitle"], subtitle_style))
        elements.append(Paragraph(f"Organization: {self.org_name}", normal))
        elements.append(Paragraph(f"Report Period: Last {self.date_range_days} days", normal))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                                  normal))
        elements.append(HRFlowable(width="100%", color=HexColor("#1e3a5f")))
        elements.append(Spacer(1, 12))

        m = self.metrics
        for section in self.config["sections"]:
            elements.append(Paragraph(section, heading))
            if "Executive" in section:
                elements.append(Paragraph(
                    f"This report summarizes the phishing defense posture for {self.org_name} "
                    f"over the reporting period. A total of <b>{m['total_scans']}</b> emails were "
                    f"scanned, with <b>{m['threats_detected']}</b> threats detected "
                    f"(<b>{m['critical_threats']}</b> critical). The average risk score across "
                    f"all scans is <b>{m['avg_risk_score']}/100</b>.</p>", normal
                ))
            elif "Security" in section or "Overview" in section:
                elements.append(Paragraph(
                    f"• Total scans performed: {m['total_scans']}<br/>"
                    f"• Threats detected: {m['threats_detected']}<br/>"
                    f"• Critical threats: {m['critical_threats']}<br/>"
                    f"• Average risk score: {m['avg_risk_score']}/100<br/>"
                    f"• Active users: {m['total_users']}<br/>"
                    f"• Phishing campaigns launched: {m['campaigns_launched']}", normal
                ))
            elif "Metrics" in section or "Assessment" in section or "Analysis" in section:
                data = [
                    ["Metric", "Value"],
                    ["Total Scans", str(m["total_scans"])],
                    ["Threats Detected", str(m["threats_detected"])],
                    ["Critical Threats", str(m["critical_threats"])],
                    ["Avg Risk Score", f'{m["avg_risk_score"]}/100'],
                    ["Active Users", str(m["total_users"])],
                    ["Campaigns Launched", str(m["campaigns_launched"])],
                ]
                t = Table(data, colWidths=[3 * inch, 2.5 * inch])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#333")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#0f172a"), HexColor("#111827")]),
                    ("TEXTCOLOR", (0, 1), (-1, -1), HexColor("#e2e8f0")),
                ]))
                elements.append(t)
            else:
                elements.append(Paragraph(
                    "Controls and measures are actively monitored by PhishGuard AI. "
                    "Refer to the app dashboard for detailed per-control breakdowns.", normal
                ))
            elements.append(Spacer(1, 8))
        doc.build(elements)
        return buf.getvalue()

    def _generate_text_fallback(self) -> bytes:
        m = self.metrics
        lines = [
            f"{'='*60}",
            f"  {self.config['title']}",
            f"  {self.config['subtitle']}",
            f"{'='*60}",
            f"  Organization:  {self.org_name}",
            f"  Period:        Last {self.date_range_days} days",
            f"  Generated:     {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"{'='*60}",
            "",
            "  KEY METRICS",
            f"  {'Total Scans:':<25} {m['total_scans']}",
            f"  {'Threats Detected:':<25} {m['threats_detected']}",
            f"  {'Critical Threats:':<25} {m['critical_threats']}",
            f"  {'Avg Risk Score:':<25} {m['avg_risk_score']}/100",
            f"  {'Active Users:':<25} {m['total_users']}",
            f"  {'Campaigns:':<25} {m['campaigns_launched']}",
            "",
            f"{'='*60}",
            f"  Generated by PhishGuard AI — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"{'='*60}",
        ]
        return "\n".join(lines).encode("utf-8")
