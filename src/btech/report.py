"""
Module 3b: PDF Report Generation Service.
Compiles a professional, client-facing security profile report using ReportLab.
Hides all raw metadata, feature vectors, thresholds, and developer metrics.
"""

import io
from datetime import datetime
from typing import Any, Dict, List

import matplotlib

# Use non-interactive backend to prevent GUI thread warnings in web apps
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_trust_donut_chart(trust_score: float) -> io.BytesIO:
    """
    Generate a clean Matplotlib donut chart representing the Trust Score.
    """
    fig, ax = plt.subplots(figsize=(3, 3))

    # Outer ring: trust score vs remaining
    ax.pie(
        [trust_score, 100.0 - trust_score],
        colors=["#0f172a", "#e2e8f0"],
        startangle=90,
        wedgeprops=dict(width=0.25, edgecolor="white"),
    )

    # Text in center
    ax.text(
        0,
        0,
        f"{trust_score:.1f}%",
        ha="center",
        va="center",
        fontname="sans-serif",
        fontsize=18,
        fontweight="bold",
        color="#0f172a",
    )

    ax.axis("equal")
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=180, bbox_inches="tight", transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


def generate_pdf_report(
    filename: str,
    metadata: Dict[str, Any],
    result: Dict[str, Any],
    explanation_data: Dict[str, Any],
) -> bytes:
    """
    Compile a professionally formatted PDF security profile report.
    Returns raw PDF bytes.
    """
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer, pagesize=letter, leftMargin=50, rightMargin=50, topMargin=50, bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=15,
    )

    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=15,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        leading=14,
        spaceAfter=6,
    )

    meta_label_style = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        textColor=colors.HexColor("#475569"),
    )

    meta_val_style = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # 1. Header Line
    header_data = [[Paragraph("🛡️ TRUSTLENS AI — FILE SAFETY PROFILE", title_style)]]
    header_table = Table(header_data, colWidths=[512])
    header_table.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, -1), 2, colors.HexColor("#0f172a")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(header_table)
    story.append(Spacer(1, 15))

    # 2. File Information Table
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_ext = filename.split(".")[-1].upper() if "." in filename else "Binary"

    meta_data = [
        [
            Paragraph("Target File:", meta_label_style),
            Paragraph(filename, meta_val_style),
            Paragraph("Scan Timestamp:", meta_label_style),
            Paragraph(timestamp_str, meta_val_style),
        ],
        [
            Paragraph("File Type:", meta_label_style),
            Paragraph(f"Windows {file_ext} Object", meta_val_style),
            Paragraph("System Status:", meta_label_style),
            Paragraph("Inspection Complete", meta_val_style),
        ],
    ]

    meta_table = Table(meta_data, colWidths=[90, 166, 100, 156])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#f1f5f9")),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # 3. Assessment Banner
    risk_level = result["risk_level"]
    trust_score = result["trust_score"]

    if risk_level == "Low Risk":
        bg_hex, border_hex, text_hex = "#f0fdf4", "#10b981", "#047857"
        short_explanation = (
            "The binary shows structural compliance with standard Windows compiler configurations. "
            "No indicators of section packing, abnormal entropy, header tampering, or security bypass methods "
            "were identified."
        )
        recommendations = [
            "✓ No significant static indicators detected; further organizational security controls are recommended: This binary matches standard benign compile signatures.",
            "✓ Verification: Standard security mitigations (ASLR & DEP) are active.",
            "✓ Best Practice: Proceed with normal execution pathways.",
        ]
    elif risk_level == "Medium Risk":
        bg_hex, border_hex, text_hex = "#fffbeb", "#f59e0b", "#b45309"
        short_explanation = (
            "The file exhibits minor security anomalies, such as missing compile-time memory protections "
            "(ASLR or DEP). While not containing packed malicious payloads, it lacks standard defenses "
            "against exploitation."
        )
        recommendations = [
            "⚠ Verify Source: Check the vendor credentials of this binary before execution.",
            "⚠ Mitigations Warning: Run this file with caution as it lacks active exploit mitigation flags (ASLR/DEP).",
            "⚠ Audit: Review security compliance logs for legacy systems mapping.",
        ]
    else:
        bg_hex, border_hex, text_hex = "#fef2f2", "#ef4444", "#b91c1c"
        short_explanation = (
            "The binary exhibits critical anomalies, including high section entropy indicating encryption "
            "or software packing, and a sparse import table structure. These attributes suggest an obfuscated "
            "loader payload."
        )
        recommendations = [
            "🚨 Do Not Execute: Block this binary from running on production host endpoints.",
            "🚨 Isolate Asset: Quarantine the file and route it to a dynamic sandbox environment for behavioral trace logs.",
            "🚨 Remediation: Run a complete vulnerability scan on the originating host.",
        ]

    banner_style = ParagraphStyle(
        "BannerText",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=colors.HexColor(text_hex),
        leading=16,
    )

    banner_content = (
        f"TRUST SCORE: {trust_score}%  |  "
        f"RISK ASSESSMENT: {risk_level.upper()}  |  "
        f"STATUS: COMPLETED"
    )

    banner_table = Table([[Paragraph(banner_content, banner_style)]], colWidths=[512])
    banner_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_hex)),
                ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor(border_hex)),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(banner_table)
    story.append(Spacer(1, 15))

    # 4. Content Layout: Side-by-side Chart and Explanation
    story.append(Paragraph("📊 Safety Metrics Visualization", section_style))

    chart_stream = generate_trust_donut_chart(trust_score)
    chart_img = Image(chart_stream, width=140, height=140)

    exp_intro_style = ParagraphStyle(
        "ExpIntro",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#0f172a"),
        leading=15,
    )

    content_data = [[chart_img, Paragraph(short_explanation, exp_intro_style)]]

    content_table = Table(content_data, colWidths=[160, 352])
    content_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(content_table)
    story.append(Spacer(1, 15))

    # 5. Recommendations Checklist
    story.append(Paragraph("🛡️ Security Recommendations", section_style))

    rec_item_style = ParagraphStyle(
        "RecItem",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        textColor=colors.HexColor("#1e293b"),
        leading=13,
    )

    rec_rows = []
    for rec in recommendations:
        rec_rows.append([Paragraph("•", meta_label_style), Paragraph(rec, rec_item_style)])

    rec_table = Table(rec_rows, colWidths=[15, 497])
    rec_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(rec_table)

    # Build Document
    doc.build(story)
    pdf_bytes = pdf_buffer.getvalue()
    pdf_buffer.close()
    return pdf_bytes
