#!/usr/bin/env python3
"""Apex CLI — PDF Report Generator
Converts a JSON scan report into a professional client-ready PDF.
Usage: python3 scripts/pdf-report.py <report.json> [output.pdf]
"""
import json
import sys
import os
from datetime import datetime

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
except ImportError:
    print("Error: reportlab not installed. Run: pip3 install reportlab")
    sys.exit(1)


SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#CA8A04"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#6B7280"),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def load_report(path):
    with open(path) as f:
        return json.load(f)


def build_pdf(report, output_path):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="Title2", parent=styles["Title"],
        fontSize=24, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="Subtitle", parent=styles["Normal"],
        fontSize=12, textColor=colors.HexColor("#6B7280"),
        alignment=TA_CENTER, spaceAfter=20
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader", parent=styles["Heading1"],
        fontSize=16, spaceBefore=20, spaceAfter=10,
        textColor=colors.HexColor("#1F2937")
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle", parent=styles["Heading2"],
        fontSize=12, spaceBefore=12, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        name="Detail", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#4B5563"),
        leftIndent=10
    ))

    elements = []

    # Title page
    elements.append(Spacer(1, 40*mm))
    elements.append(Paragraph("Security Assessment Report", styles["Title2"]))
    elements.append(Paragraph(
        f"Target: {report.get('target', 'Unknown')}", styles["Subtitle"]
    ))
    elements.append(Paragraph(
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Subtitle"]
    ))
    elements.append(Paragraph(
        f"Duration: {report.get('duration_seconds', 0)}s", styles["Subtitle"]
    ))
    elements.append(Spacer(1, 20*mm))
    elements.append(Paragraph(
        "Prepared by ROZ Security", styles["Subtitle"]
    ))
    elements.append(Paragraph(
        "https://republicofzani.com", styles["Subtitle"]
    ))
    elements.append(PageBreak())

    # Executive Summary
    findings = report.get("findings", [])
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    elements.append(Paragraph("Executive Summary", styles["SectionHeader"]))
    elements.append(Paragraph(
        f"A total of <b>{len(findings)}</b> security issues were identified "
        f"during the assessment of <b>{report.get('target', 'the target')}</b>.",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 10*mm))

    # Summary table
    summary_data = [["Severity", "Count", "Risk Level"]]
    risk_desc = {
        "critical": "Immediate exploitation possible",
        "high": "Significant risk, fix within 7 days",
        "medium": "Moderate risk, fix within 30 days",
        "low": "Minor risk, fix when convenient",
        "info": "Informational, no immediate risk",
    }
    for sev in SEVERITY_ORDER:
        if counts[sev] > 0:
            summary_data.append([
                sev.upper(), str(counts[sev]), risk_desc.get(sev, "")
            ])

    if len(summary_data) > 1:
        t = Table(summary_data, colWidths=[30*mm, 20*mm, 100*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F9FAFB")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)

    elements.append(PageBreak())

    # Detailed Findings
    elements.append(Paragraph("Detailed Findings", styles["SectionHeader"]))
    elements.append(HRFlowable(
        width="100%", thickness=1, color=colors.HexColor("#E5E7EB")
    ))

    # Sort by severity
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info"))
    )

    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, colors.gray)

        elements.append(Paragraph(
            f'<font color="{color.hexval()}">[{sev.upper()}]</font> '
            f'#{i}: {f.get("type", "Unknown")}',
            styles["FindingTitle"]
        ))
        elements.append(Paragraph(
            f'<b>URL:</b> {f.get("url", "N/A")}', styles["Detail"]
        ))
        if f.get("detail"):
            elements.append(Paragraph(
                f'<b>Description:</b> {f["detail"]}', styles["Detail"]
            ))
        if f.get("param"):
            elements.append(Paragraph(
                f'<b>Parameter:</b> {f["param"]}', styles["Detail"]
            ))
        if f.get("evidence"):
            elements.append(Paragraph(
                f'<b>Evidence:</b> {f["evidence"][:200]}', styles["Detail"]
            ))

        # Recommendation
        recs = {
            "IDOR": "Implement proper authorization checks. Verify the requesting user owns the resource.",
            "Mass Assignment": "Use allowlists for accepted fields. Never bind user input directly to models.",
            "Auth Bypass": "Enforce authentication on all sensitive endpoints. Add middleware checks.",
            "XSS": "Sanitize and encode all user input before rendering. Use Content-Security-Policy headers.",
            "SQLi": "Use parameterized queries. Never concatenate user input into SQL statements.",
            "SSRF": "Validate and whitelist allowed URLs. Block internal IP ranges.",
            "CORS": "Restrict Access-Control-Allow-Origin to trusted domains only.",
        }
        rec = None
        for key, val in recs.items():
            if key.lower() in f.get("type", "").lower():
                rec = val
                break
        if rec:
            elements.append(Paragraph(
                f'<b>Recommendation:</b> {rec}', styles["Detail"]
            ))

        elements.append(Spacer(1, 5*mm))
        elements.append(HRFlowable(
            width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")
        ))

    # Footer
    elements.append(PageBreak())
    elements.append(Paragraph("Disclaimer", styles["SectionHeader"]))
    elements.append(Paragraph(
        "This report is provided as-is based on automated and semi-automated "
        "security testing. It does not guarantee the absence of other "
        "vulnerabilities. The findings should be validated and remediated by "
        "qualified security professionals. ROZ Security is not liable for any "
        "damages resulting from the use of this report.",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 10*mm))
    elements.append(Paragraph(
        "© 2026 ROZ Security — Republic of Zani. All rights reserved.",
        styles["Subtitle"]
    ))

    doc.build(elements)
    print(f"  -> PDF report: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/pdf-report.py <report.json> [output.pdf]")
        sys.exit(1)

    report_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else report_path.replace(".json", ".pdf")

    if not os.path.exists(report_path):
        print(f"Error: {report_path} not found")
        sys.exit(1)

    report = load_report(report_path)
    build_pdf(report, output_path)


if __name__ == "__main__":
    main()
