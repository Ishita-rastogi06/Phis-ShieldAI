"""Executive Cybersecurity Audit Reports with structured ASCII sections and clear metrics."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def generate_canonical_report(scan_type: str, analysis: dict) -> str:
    """Generate a high-grade, professional executive cybersecurity audit report."""
    if not isinstance(analysis, dict):
        analysis = {}

    target = analysis.get("normalized_url") or analysis.get("url") or "N/A"
    verdict = str(analysis.get("verdict", "UNKNOWN")).upper().replace("_", " ")
    risk_score = analysis.get("risk", "N/A")
    raw_risk_level = analysis.get("risk_level")
    if not raw_risk_level:
        raw_risk_level = analysis.get("verdict", "N/A")
    risk_level = str(raw_risk_level).upper().replace("_", " ")
    confidence = str(analysis.get("confidence_strength", "N/A")).title()
    brand = analysis.get("brand") or "Unknown / Unclassified"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    reasons = analysis.get("reasons", [])
    
    # Provider evidence
    providers = analysis.get("providers", {})
    vt = providers.get("virustotal", {}) if isinstance(providers, dict) else {}
    op = providers.get("openphish", {}) if isinstance(providers, dict) else {}
    
    vt_reason = (vt.get("reason") if isinstance(vt, dict) else None) or "Not Queried / Unavailable"
    op_reason = (op.get("reason") if isinstance(op, dict) else None) or "Not Queried / Unavailable"
    
    # Infrastructure details
    tls = analysis.get("tls", {})
    tls_str = f"Valid: {tls.get('valid', 'N/A')} | Issuer: {tls.get('issuer', 'N/A')}" if isinstance(tls, dict) else "Unavailable"
    
    whois = analysis.get("whois", {})
    whois_str = f"Age: {whois.get('age_days', 'N/A')} days | Registrar: {whois.get('registrar', 'N/A')}" if isinstance(whois, dict) else "Unavailable"

    dns = analysis.get("dns", {})
    dns_str = f"A Records: {', '.join(dns.get('a_records', [])) if isinstance(dns, dict) and dns.get('a_records') else 'None'}"

    website = analysis.get("website", {})
    web_str = f"Status Code: {website.get('status_code', 'N/A')} | Title: {website.get('title', 'N/A')}" if isinstance(website, dict) else "Unavailable"

    mitre_list = analysis.get("mitre", [])
    mitre_lines = []
    if isinstance(mitre_list, list) and mitre_list:
        for m in mitre_list:
            if isinstance(m, dict):
                mitre_lines.append(f"  • [{m.get('id', 'T0000')}] {m.get('tactic', 'Tactic')}: {m.get('technique', 'Technique')} - {m.get('description', '')}")
    if not mitre_lines:
        mitre_lines = ["  • No specific MITRE ATT&CK techniques mapped for this asset."]

    reasons_formatted = "\n".join([f"  [!] {r}" for r in reasons]) if reasons else "  [i] No high-risk policy anomalies triggered."

    copilot = analysis.get("ai_copilot", {})
    explanation = (copilot.get("summary") or copilot.get("explanation") if isinstance(copilot, dict) else None) or analysis.get("recommendation") or "Exercise standard security hygiene when interacting with untrusted web links."

    ref_id = f"PS-REF-{abs(hash(str(target))) % 1000000:06d}"

    report = f"""================================================================================
                    PHISHSHIELD AI — EXECUTIVE THREAT REPORT
================================================================================
Generated Timestamp : {timestamp}
Scan Analysis Type  : {scan_type.upper()} SCAN
Target Asset / URL  : {target}
Report Reference ID : {ref_id}
--------------------------------------------------------------------------------

[1] EXECUTIVE SUMMARY & THREAT VERDICT
--------------------------------------------------------------------------------
Final Assessment Verdict : {verdict}
Calculated Risk Score    : {risk_score} / 100 ({risk_level})
Evidence Confidence      : {confidence} Confidence
Identified Brand Impact  : {brand}

[2] KEY THREAT FINDINGS & POLICY INDICATORS
--------------------------------------------------------------------------------
{reasons_formatted}

[3] CLOUD THREAT INTELLIGENCE FEED EVIDENCE
--------------------------------------------------------------------------------
  • VirusTotal Engine Scanner : {vt_reason}
  • OpenPhish Threat Feed     : {op_reason}

[4] TECHNICAL INFRASTRUCTURE & ENRICHMENT
--------------------------------------------------------------------------------
  • Website Inspection : {web_str}
  • SSL / TLS Security : {tls_str}
  • WHOIS & Domain Age : {whois_str}
  • DNS Resolution     : {dns_str}

[5] MITRE ATT&CK FRAMEWORK MAPPING
--------------------------------------------------------------------------------
{chr(10).join(mitre_lines)}

[6] COPILOT REMEDIATION & ACTION PLAN
--------------------------------------------------------------------------------
  {explanation}

================================================================================
          End of PhishShield AI Threat Report — Strictly Confidential
================================================================================
"""
    return report


def generate_report(target, result, risk, details, *, confidence=None, risk_level=None, brand=None,
                    ssl=None, whois=None, virustotal=None, scan_type="URL", dns=None, mitre=None,
                    website=None, extracted_urls=None, recommendation=None, source_errors=None, providers=None):
    analysis = {
        "url": target, "verdict": result, "risk": risk, "reasons": details.split("\n") if isinstance(details, str) else details,
        "confidence_strength": confidence, "risk_level": risk_level, "brand": brand, "tls": ssl, "whois": whois,
        "dns": dns, "virustotal": virustotal, "providers": providers, "mitre": mitre, "website": website,
        "recommendation": recommendation
    }
    return generate_canonical_report(scan_type, analysis)


def generate_input_report(scan_type: str, target: str, context: dict, url_analyses: list[dict]) -> str:
    """Report OCR/Email scan context in professional executive format."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ref_id = f"PS-REF-{abs(hash(str(target))) % 1000000:06d}"
    
    sections = [
        "================================================================================",
        "                    PHISHSHIELD AI — MULTI-ASSET AUDIT REPORT",
        "================================================================================",
        f"Generated Timestamp : {timestamp}",
        f"Scan Analysis Type  : {scan_type.upper()} SCAN",
        f"Target Document/Text: {target}",
        f"Report Reference ID : {ref_id}",
        "--------------------------------------------------------------------------------",
        "",
        "[1] CONTEXTUAL EVIDENCE SUMMARY",
        "--------------------------------------------------------------------------------",
    ]
    if isinstance(context, dict):
        for k, v in context.items():
            sections.append(f"  • {k}: {v}")
    else:
        sections.append(f"  • Context: {context}")
        
    sections.extend([
        "",
        f"[2] EXTRACTED CANONICAL ASSET ANALYSES ({len(url_analyses)} URLs Evaluated)",
        "--------------------------------------------------------------------------------"
    ])
    
    if not url_analyses:
        sections.append("  [i] No external URLs extracted from input asset.")
    else:
        for idx, analysis in enumerate(url_analyses, 1):
            sections.append(f"\n--- [Asset #{idx}] ----------------------------------------------------")
            sections.append(generate_canonical_report("URL", analysis))
            
    sections.extend([
        "================================================================================",
        "          End of PhishShield AI Threat Report — Strictly Confidential",
        "================================================================================"
    ])
    return "\n".join(sections)


def generate_pdf_report(scan_type: str, analysis: dict) -> bytes:
    """Generate a formal executive PDF threat audit report using ReportLab."""
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch

    if not isinstance(analysis, dict):
        analysis = {}

    target = str(analysis.get("normalized_url") or analysis.get("url") or "N/A")
    verdict = str(analysis.get("verdict", "UNKNOWN")).upper().replace("_", " ")
    risk_score = str(analysis.get("risk", "N/A"))
    risk_level = str(analysis.get("risk_level", "N/A")).upper()
    confidence = str(analysis.get("confidence_strength", "N/A")).title()
    brand = str(analysis.get("brand") or "Unknown / Unclassified")
    timestamp = datetime.now(timezone.utc).strftime("%b %d, %Y %H:%M:%S UTC")
    reasons = analysis.get("reasons", [])
    ref_id = f"PS-REF-{abs(hash(str(target))) % 1000000:06d}"

    # Determine theme colors based on verdict
    if "PHISHING" in verdict or "MALICIOUS" in verdict:
        verdict_color = colors.HexColor("#DC2626")  # Red
        verdict_bg = colors.HexColor("#FEF2F2")     # Light Red
    elif "LEGITIMATE" in verdict or "CLEAN" in verdict:
        verdict_color = colors.HexColor("#16A34A")  # Green
        verdict_bg = colors.HexColor("#F0FDF4")     # Light Green
    else:
        verdict_color = colors.HexColor("#D97706")  # Amber
        verdict_bg = colors.HexColor("#FFFBEB")     # Light Amber

    navy_header = colors.HexColor("#0F172A")
    slate_border = colors.HexColor("#CBD5E1")
    card_bg = colors.HexColor("#F8FAFC")
    dark_text = colors.HexColor("#1E293B")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, rightMargin=0.5 * inch, leftMargin=0.5 * inch,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch
    )

    styles = getSampleStyleSheet()

    header_title_style = ParagraphStyle(
        'DocHeaderTitle', parent=styles['Normal'], fontName='Helvetica-Bold',
        fontSize=18, leading=22, textColor=colors.white
    )
    header_sub_style = ParagraphStyle(
        'DocHeaderSub', parent=styles['Normal'], fontName='Helvetica',
        fontSize=9.5, leading=13, textColor=colors.HexColor("#94A3B8")
    )
    section_title_style = ParagraphStyle(
        'SectionTitle', parent=styles['Normal'], fontName='Helvetica-Bold',
        fontSize=11.5, leading=15, textColor=navy_header, spaceBefore=8, spaceAfter=4
    )
    body_style = ParagraphStyle(
        'BodyTextCustom', parent=styles['Normal'], fontName='Helvetica',
        fontSize=9, leading=12, textColor=dark_text
    )
    bold_body_style = ParagraphStyle(
        'BoldBodyCustom', parent=body_style, fontName='Helvetica-Bold'
    )
    verdict_style = ParagraphStyle(
        'VerdictText', parent=styles['Normal'], fontName='Helvetica-Bold',
        fontSize=14, leading=17, textColor=verdict_color
    )

    story = []

    # 1. Header Banner Table
    header_data = [
        [
            Paragraph("PHISHSHIELD AI", header_title_style),
            Paragraph(f"<b>REPORT ID:</b> {ref_id}<br/><b>DATE:</b> {timestamp}", header_sub_style)
        ],
        [
            Paragraph("EXECUTIVE CYBERSECURITY THREAT AUDIT REPORT", header_sub_style),
            Paragraph(f"<b>ASSET TYPE:</b> {scan_type.upper()}", header_sub_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[4.5 * inch, 3.0 * inch])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), navy_header),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))

    # 2. Executive Summary Callout Box
    summary_data = [
        [Paragraph("TARGET ASSET:", bold_body_style), Paragraph(f"<b>{target}</b>", body_style)],
        [Paragraph("ASSESSMENT VERDICT:", bold_body_style), Paragraph(f"{verdict}", verdict_style)],
        [Paragraph("RISK SCORE / LEVEL:", bold_body_style), Paragraph(f"<b>{risk_score} / 100</b> ({risk_level})", body_style)],
        [Paragraph("EVIDENCE CONFIDENCE:", bold_body_style), Paragraph(f"{confidence} Confidence", body_style)],
        [Paragraph("BRAND INTELLIGENCE:", bold_body_style), Paragraph(f"{brand}", body_style)]
    ]
    summary_table = Table(summary_data, colWidths=[2.2 * inch, 5.3 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_bg),
        ('BOX', (0, 0), (-1, -1), 1.5, verdict_color),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # 3. Key Threat Findings & Policy Indicators
    story.append(Paragraph("1. KEY THREAT FINDINGS & POLICY INDICATORS", section_title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=navy_header, spaceAfter=6))
    
    reasons_list = []
    if reasons:
        for r in reasons:
            reasons_list.append([Paragraph("<font color='#DC2626'><b>[!]</b></font>", body_style), Paragraph(str(r), body_style)])
    else:
        reasons_list.append([Paragraph("<font color='#16A34A'><b>[i]</b></font>", body_style), Paragraph("No high-risk policy anomalies or phishing indicators triggered for this target.", body_style)])
        
    reasons_table = Table(reasons_list, colWidths=[0.3 * inch, 7.2 * inch])
    reasons_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), card_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, slate_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(reasons_table)
    story.append(Spacer(1, 10))

    # 4. Cloud Threat Intelligence Evidence
    story.append(Paragraph("2. CLOUD THREAT INTELLIGENCE FEED EVIDENCE", section_title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=navy_header, spaceAfter=6))

    providers = analysis.get("providers", {})
    vt = providers.get("virustotal", {}) if isinstance(providers, dict) else {}
    op = providers.get("openphish", {}) if isinstance(providers, dict) else {}

    vt_reason = (vt.get("reason") if isinstance(vt, dict) else None) or "Not Queried / Unavailable"
    op_reason = (op.get("reason") if isinstance(op, dict) else None) or "Not Queried / Unavailable"

    intel_data = [
        [Paragraph("<b>VirusTotal Security Vendors</b>", bold_body_style), Paragraph(str(vt_reason), body_style)],
        [Paragraph("<b>OpenPhish Threat Feed</b>", bold_body_style), Paragraph(str(op_reason), body_style)]
    ]
    intel_table = Table(intel_data, colWidths=[2.3 * inch, 5.2 * inch])
    intel_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), card_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, slate_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(intel_table)
    story.append(Spacer(1, 10))

    # 5. Technical Infrastructure Enrichment
    story.append(Paragraph("3. TECHNICAL INFRASTRUCTURE ENRICHMENT", section_title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=navy_header, spaceAfter=6))

    tls = analysis.get("tls", {})
    tls_str = f"Valid Certificate: {tls.get('valid', 'N/A')} | Issuer: {tls.get('issuer', 'N/A')}" if isinstance(tls, dict) else "Unavailable"
    
    whois = analysis.get("whois", {})
    whois_str = f"Domain Age: {whois.get('age_days', 'N/A')} days | Registrar: {whois.get('registrar', 'N/A')}" if isinstance(whois, dict) else "Unavailable"

    dns = analysis.get("dns", {})
    dns_str = f"A Records: {', '.join(dns.get('a_records', [])) if isinstance(dns, dict) and dns.get('a_records') else 'None'}"

    website = analysis.get("website", {})
    web_str = f"Status Code: {website.get('status_code', 'N/A')} | Title: {website.get('title', 'N/A')}" if isinstance(website, dict) else "Unavailable"

    infra_data = [
        [Paragraph("<b>Website Inspection</b>", bold_body_style), Paragraph(web_str, body_style)],
        [Paragraph("<b>SSL / TLS Security</b>", bold_body_style), Paragraph(tls_str, body_style)],
        [Paragraph("<b>WHOIS Domain Age</b>", bold_body_style), Paragraph(whois_str, body_style)],
        [Paragraph("<b>DNS Resolution</b>", bold_body_style), Paragraph(dns_str, body_style)],
    ]
    infra_table = Table(infra_data, colWidths=[2.3 * inch, 5.2 * inch])
    infra_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), card_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, slate_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(infra_table)
    story.append(Spacer(1, 10))

    # 6. MITRE ATT&CK Framework & Copilot Action Plan
    story.append(Paragraph("4. MITRE ATT&CK MAPPING & COPILOT REMEDIATION", section_title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=navy_header, spaceAfter=6))

    mitre_list = analysis.get("mitre", [])
    mitre_rows = []
    if isinstance(mitre_list, list) and mitre_list:
        for m in mitre_list:
            if isinstance(m, dict):
                mitre_rows.append([
                    Paragraph(f"<b>[{m.get('id', 'T0000')}]</b>", bold_body_style),
                    Paragraph(f"<b>{m.get('tactic', 'Tactic')}</b>: {m.get('technique', 'Technique')}<br/>{m.get('description', '')}", body_style)
                ])
    if not mitre_rows:
        mitre_rows.append([Paragraph("<b>N/A</b>", bold_body_style), Paragraph("No specific MITRE ATT&CK tactics mapped for this asset.", body_style)])

    mitre_table = Table(mitre_rows, colWidths=[1.2 * inch, 6.3 * inch])
    mitre_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), card_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, slate_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(mitre_table)
    story.append(Spacer(1, 8))

    copilot = analysis.get("ai_copilot", {})
    explanation = (copilot.get("summary") or copilot.get("explanation") if isinstance(copilot, dict) else None) or analysis.get("recommendation") or "Exercise standard security hygiene when interacting with untrusted web links."

    copilot_data = [
        [Paragraph("<b>SOC ACTION PLAN & REMEDIATION</b>", ParagraphStyle('CopilotTitle', parent=bold_body_style, textColor=navy_header))],
        [Paragraph(str(explanation), body_style)]
    ]
    copilot_table = Table(copilot_data, colWidths=[7.5 * inch])
    copilot_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#3B82F6")),
        ('PADDING', (0, 0), (-1, -1), 7),
    ]))
    story.append(copilot_table)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
