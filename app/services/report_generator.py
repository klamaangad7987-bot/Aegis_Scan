"""Génération de rapports PDF avec ReportLab."""
import os
from datetime import datetime
from app import db
from app.models.scan import Scan, Report


def generate_pdf_report(scan: Scan) -> Report:
    """Génère un rapport PDF pour un scan donné."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        raise RuntimeError("reportlab non installé. Lancez: pip install reportlab")

    from flask import current_app
    reports_dir = current_app.config.get('REPORTS_FOLDER', 'reports_output')
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"report_scan_{scan.id}_{timestamp}.pdf"
    filepath = os.path.join(reports_dir, filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm,
                             leftMargin=2*cm, rightMargin=2*cm)

    # ── Styles ──────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()
    DARK = colors.HexColor('#0f172a')
    ACCENT = colors.HexColor('#6366f1')
    CRITICAL = colors.HexColor('#ef4444')
    HIGH = colors.HexColor('#f97316')
    MEDIUM = colors.HexColor('#eab308')
    LOW = colors.HexColor('#22c55e')
    INFO_C = colors.HexColor('#3b82f6')
    LIGHT_BG = colors.HexColor('#f8fafc')

    title_style = ParagraphStyle('Title', parent=styles['Title'],
                                  fontSize=22, textColor=DARK, spaceAfter=6,
                                  fontName='Helvetica-Bold')
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'],
                               fontSize=14, textColor=ACCENT, spaceBefore=14,
                               spaceAfter=6, fontName='Helvetica-Bold')
    body_style = ParagraphStyle('Body', parent=styles['Normal'],
                                 fontSize=10, textColor=DARK, leading=14)
    small_style = ParagraphStyle('Small', parent=styles['Normal'],
                                  fontSize=9, textColor=colors.HexColor('#64748b'))

    SEV_COLORS = {
        'critical': CRITICAL, 'high': HIGH,
        'medium': MEDIUM, 'low': LOW, 'info': INFO_C,
    }

    # ── Contenu ─────────────────────────────────────────────────────────────
    story = []

    # En-tête
    story.append(Paragraph("SecureAudit — Rapport de Sécurité", title_style))
    story.append(Paragraph(f"Scan : <b>{scan.name}</b>", body_style))
    story.append(Paragraph(f"Type : {scan.scan_type.upper()} &nbsp;|&nbsp; "
                            f"Cible : {scan.target or 'N/A'} &nbsp;|&nbsp; "
                            f"Date : {scan.created_at.strftime('%d/%m/%Y %H:%M') if scan.created_at else 'N/A'}",
                            small_style))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=ACCENT, spaceAfter=10))

    # Résumé exécutif
    story.append(Paragraph("Résumé exécutif", h2_style))
    summary_data = [
        ['Métrique', 'Valeur'],
        ['Total vulnérabilités', str(scan.total_vulnerabilities)],
        ['Critiques', str(scan.critical_count)],
        ['Élevées', str(scan.high_count)],
        ['Moyennes', str(scan.medium_count)],
        ['Faibles', str(scan.low_count)],
        ['Score de risque global', f"{scan.risk_score}/100"],
        ['Durée du scan', scan.duration_str],
        ['Statut', scan.status.upper()],
    ]
    tbl = Table(summary_data, colWidths=[8*cm, 8*cm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), LIGHT_BG),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.5*cm))

    # Vulnérabilités détaillées
    story.append(Paragraph("Vulnérabilités détectées", h2_style))
    vulns = scan.vulnerabilities.order_by(
        db.case(
            (Scan.critical_count > 0, 0),
            else_=1
        )
    ).all() if False else scan.vulnerabilities.all()

    # Trier par sévérité
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    vulns_sorted = sorted(vulns, key=lambda v: sev_order.get(v.severity, 5))

    for i, vuln in enumerate(vulns_sorted[:50], 1):  # max 50 vulns
        sev_color = SEV_COLORS.get(vuln.severity, colors.gray)

        story.append(Paragraph(
            f"<b>{i}. {vuln.title}</b>",
            ParagraphStyle('VTitle', parent=body_style,
                           fontSize=11, textColor=DARK, spaceBefore=8)
        ))

        meta = (f"<font color='#{sev_color.hexval()[1:] if hasattr(sev_color,'hexval') else '888888'}'>"
                f"<b>{vuln.severity.upper()}</b></font>")
        info_parts = [f"Sévérité : <b>{vuln.severity.upper()}</b>",
                      f"Catégorie : {vuln.category or 'N/A'}"]
        if vuln.cwe_id:
            info_parts.append(f"CWE : {vuln.cwe_id}")
        if vuln.cvss_score:
            info_parts.append(f"CVSS : {vuln.cvss_score}")
        if vuln.file_path:
            info_parts.append(f"Fichier : {vuln.file_path}"
                              + (f" (ligne {vuln.line_number})" if vuln.line_number else ""))
        story.append(Paragraph(" &nbsp;|&nbsp; ".join(info_parts), small_style))

        if vuln.description:
            story.append(Paragraph(f"Description : {vuln.description}", body_style))
        if vuln.recommendation:
            story.append(Paragraph(
                f"<b>Recommandation :</b> {vuln.recommendation}",
                ParagraphStyle('Rec', parent=body_style,
                               backColor=colors.HexColor('#f0fdf4'),
                               borderPad=4, leading=14)
            ))
        if vuln.code_snippet:
            story.append(Paragraph(
                f"<font name='Courier' size='8'>{vuln.code_snippet[:200]}</font>",
                small_style
            ))

        story.append(HRFlowable(width="100%", thickness=0.3,
                                color=colors.HexColor('#e2e8f0'), spaceAfter=4))

    # Pied de page
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=ACCENT, spaceAfter=6))
    story.append(Paragraph(
        f"Rapport généré automatiquement par SecureAudit — "
        f"{datetime.utcnow().strftime('%d/%m/%Y à %H:%M')} UTC",
        small_style
    ))

    doc.build(story)

    # Enregistrer en base
    file_size = os.path.getsize(filepath)
    report = Report(
        filename=filename,
        file_path=filepath,
        file_size=file_size,
        report_type='pdf',
        scan_id=scan.id,
    )
    db.session.add(report)
    db.session.commit()

    return report
