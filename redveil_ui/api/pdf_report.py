"""PDF report generation for scans (0.3.0)."""
from __future__ import annotations

from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def generate_pdf(scan, findings: list, output_path: Path):
    """Generate a PDF report for a scan."""
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"RedVeil Scan {scan.id} Report",
        author="redveil-ui",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#991b1b"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#1f2937"))
    normal = styles["Normal"]
    normal.fontSize = 8
    normal.leading = 10
    mono = ParagraphStyle("Mono", parent=styles["Code"], fontSize=7, textColor=colors.HexColor("#374151"))

    story = []
    story.append(Paragraph(f"RedVeil Scan Report — #{scan.id}", title_style))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Target ID: {scan.target_id} &nbsp;|&nbsp; Profile: {scan.profile} &nbsp;|&nbsp; Status: {scan.status} &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')}", normal))
    story.append(Spacer(1, 4 * mm))

    # Summary table by severity
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    if sev_counts:
        data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_counts:
                data.append([sev.capitalize(), str(sev_counts[sev])])
        t = Table(data, colWidths=[40 * mm, 30 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 4 * mm))

    if not findings:
        story.append(Paragraph("No findings recorded for this scan.", normal))
    else:
        story.append(Paragraph(f"Findings ({len(findings)})", h2))
        story.append(Spacer(1, 2 * mm))
        for f in findings:
            # Finding header
            sev_color = {"critical": "#991b1b", "high": "#c2410c", "medium": "#a16207", "low": "#15803d", "info": "#1d4ed8"}.get(f.severity, "#6b7280")
            story.append(Paragraph(f'<font color="{sev_color}"><b>[{f.severity.upper()}]</b></font> {f.title} <font size=7 color="#6b7280">({f.wpoc_id})</font>', normal))
            story.append(Paragraph(f'<font size=7 color="#6b7280">{f.endpoint or "—"} &nbsp;|&nbsp; {f.check_id or "—"} &nbsp;|&nbsp; {f.confidence}</font>', mono))
            if getattr(f, "notes", None):
                story.append(Paragraph(f'<b>Operator notes:</b> {f.notes}', normal))
            # finding_data excerpt
            data = f.finding_data or {}
            if data.get("summary"):
                story.append(Paragraph(f"<b>Summary:</b> {data['summary'][:500]}", normal))
            story.append(Spacer(1, 2 * mm))

    doc.build(story)
