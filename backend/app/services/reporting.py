import io
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from backend.app.schemas.canonical import FullEmailInvestigationBundle


def generate_forensic_pdf_report(bundle: FullEmailInvestigationBundle) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569')
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )
    mono_style = ParagraphStyle(
        'MonoText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )

    story = []

    # 1. Header Banner & Cover Meta
    story.append(Paragraph("TRACEGUARD AI — DIGITAL FORENSIC INTELLIGENCE REPORT", title_style))
    story.append(Paragraph("EVIDENTIARY AUDIT & THREAT RECONSTRUCTION DOSSIER", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563eb'), spaceBefore=8, spaceAfter=12))

    # Meta Table
    risk = bundle.risk_score
    verdict_color = colors.HexColor('#ef4444') if risk.threat_score > 0.70 else (colors.HexColor('#f59e0b') if risk.threat_score > 0.30 else colors.HexColor('#10b981'))
    
    meta_data = [
        [Paragraph("<b>Case Reference:</b>", body_style), Paragraph(bundle.case_id, body_style),
         Paragraph("<b>Classification:</b>", body_style), Paragraph(f"<font color='{verdict_color.hexval()}'><b>{risk.classification}</b></font>", body_style)],
        [Paragraph("<b>Evidence SHA-256:</b>", body_style), Paragraph(bundle.email.sha256[:24] + "...", mono_style),
         Paragraph("<b>Threat Score:</b>", body_style), Paragraph(f"<b>{int(risk.threat_score * 100)}%</b>", body_style)],
        [Paragraph("<b>Generated At:</b>", body_style), Paragraph(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), body_style),
         Paragraph("<b>Model Version:</b>", body_style), Paragraph(risk.model_version, body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[1.3*inch, 2.3*inch, 1.3*inch, 1.8*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 2. Executive Summary
    story.append(Paragraph("1. Executive Threat Summary", section_heading))
    reasons_text = " ".join([r.human_readable for r in risk.top_reasons[:4]])
    summary_text = (
        f"This digital forensic artifact was inspected and identified as <b>{risk.classification}</b> with a calibrated "
        f"threat probability of <b>{int(risk.threat_score * 100)}%</b>. Primary contributing indicators: {reasons_text}."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # 3. Three-Axis Score Breakdown
    story.append(Paragraph("2. Calibrated 3-Axis Risk & Confidence Assessment", section_heading))
    scores_data = [
        ["Evaluation Axis", "Score", "Epistemic Definition", "Calibrated Interpretation"],
        ["Threat Score", f"{int(risk.threat_score * 100)}%", "Maliciousness of intent and payload", "High-severity fraud / credential harvest" if risk.threat_score > 0.7 else "Low / Normal"],
        ["Infrastructure Confidence", f"{int(risk.infrastructure_confidence * 100)}%", "Reliability of technical relay trace", "Cryptographically & chronologically verified hops"],
        ["Attribution Confidence", f"{int(risk.attribution_confidence * 100)}%", "Association with known actor/campaign", "Correlated across multiple documented cases" if risk.attribution_confidence > 0.5 else "Hosting / VPN proxy node (not direct actor)"]
    ]
    scores_table = Table(scores_data, colWidths=[1.8*inch, 0.8*inch, 2.2*inch, 2.0*inch])
    scores_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(scores_table)
    story.append(Spacer(1, 10))

    # 4. Authentication Results
    story.append(Paragraph("3. Authentication Protocol Verification (SPF / DKIM / DMARC / ARC)", section_heading))
    auth = bundle.auth
    auth_data = [
        ["Protocol", "Status", "Policy / Selector", "Forensic Result Details"],
        ["SPF", auth.spf.result.upper(), auth.spf.domain_checked or "N/A", auth.spf.explanation or ""],
        ["DKIM", "ALIGNED" if any(d.aligned for d in auth.dkim) else ("PASS" if any(d.valid for d in auth.dkim) else "FAIL"), (auth.dkim[0].selector if auth.dkim else "N/A"), (auth.dkim[0].details if auth.dkim else "No DKIM signature")],
        ["DMARC", auth.dmarc.result.upper(), f"p={auth.dmarc.policy}", auth.dmarc.explanation or ""],
        ["ARC", "VALID" if auth.arc.chain_valid else "NONE", f"hops={auth.arc.hop_count}", auth.arc.details or ""]
    ]
    auth_table = Table(auth_data, colWidths=[1.0*inch, 1.0*inch, 1.6*inch, 3.2*inch])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 10))

    # 5. Relay Hop Reconstruction
    story.append(Paragraph("4. SMTP Relay Path Reconstruction & Trust Frontier", section_heading))
    relay_rows = [["Hop", "Claimed From", "Claimed By", "Extracted IP", "Trust Level", "Reasoning"]]
    for hop in bundle.relay_hops[:6]:
        relay_rows.append([
            str(hop.hop_number),
            (hop.from_host_claimed or "")[:18],
            (hop.by_host_claimed or "")[:18],
            hop.ip_extracted or "N/A",
            hop.trust_level,
            (hop.trust_reasoning[0] if hop.trust_reasoning else "")[:30]
        ])
    relay_table = Table(relay_rows, colWidths=[0.5*inch, 1.4*inch, 1.4*inch, 1.1*inch, 1.1*inch, 1.3*inch])
    relay_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7.5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(relay_table)
    story.append(Spacer(1, 10))

    # 6. Indicators of Compromise (Domains, URLs, Hashes)
    story.append(Paragraph("5. Extracted Threat Indicators (IOCs)", section_heading))
    ioc_rows = [["Type", "Value / Destination", "Risk Score", "Observed Threat Attributes"]]
    for d in bundle.domains[:3]:
        ioc_rows.append(["DOMAIN", d.domain, f"{int(d.age_risk_score * 100)}%", (d.risk_reasons[0] if d.risk_reasons else "Normal domain")[:40]])
    for u in bundle.urls[:3]:
        ioc_rows.append(["URL", u.actual_href[:32] + "...", f"{int(u.url_risk_score * 100)}%", (u.risk_reasons[0] if u.risk_reasons else "Clean URL")[:40]])
    for a in bundle.attachments[:3]:
        ioc_rows.append(["ATTACHMENT", a.filename, f"{int(a.risk_score * 100)}%", f"SHA256: {a.sha256[:16]}..."])
    
    if len(ioc_rows) > 1:
        ioc_table = Table(ioc_rows, colWidths=[1.1*inch, 2.5*inch, 0.9*inch, 2.3*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        story.append(ioc_table)
    story.append(Spacer(1, 10))

    # 7. Cryptographic Chain of Custody
    story.append(Paragraph("6. Tamper-Evident Chain of Custody Log", section_heading))
    custody_rows = [["Timestamp (UTC)", "Action", "Actor", "Chained Cryptographic Hash"]]
    for c in bundle.chain_of_custody[:5]:
        custody_rows.append([
            c.timestamp[:19].replace("T", " "),
            c.action,
            c.actor,
            c.current_hash[:28] + "..." if c.current_hash else "GENESIS"
        ])
    custody_table = Table(custody_rows, colWidths=[1.6*inch, 1.2*inch, 1.2*inch, 2.8*inch])
    custody_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7.5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(custody_table)

    # Build Document
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def generate_stix_bundle(bundle: FullEmailInvestigationBundle) -> Dict[str, Any]:
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle_id = f"bundle--{bundle.email.email_id}"
    
    stix_objects = []

    # 1. Observed Data Object
    observed_id = f"observed-data--{bundle.email.email_id}"
    stix_objects.append({
        "type": "observed-data",
        "spec_version": "2.1",
        "id": observed_id,
        "created": timestamp,
        "modified": timestamp,
        "first_observed": timestamp,
        "last_observed": timestamp,
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "email-message",
                "is_multipart": len(bundle.email.mime_structure) > 1,
                "subject": bundle.email.headers_normalized.subject,
                "from_ref": "1"
            },
            "1": {
                "type": "email-addr",
                "value": bundle.email.headers_normalized.from_address.address if bundle.email.headers_normalized.from_address else "unknown@domain.com"
            }
        }
    })

    # 2. Indicator Objects for Suspicious IPs / Domains / Hashes
    for geo in bundle.geo_locations:
        if geo.reputation in ("MALICIOUS", "SUSPICIOUS") or geo.is_tor or geo.is_vpn:
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--ip-{hashlib.md5(geo.ip.encode()).hexdigest()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"Malicious Originating Relay IP: {geo.ip}",
                "description": f"Observed in email threat investigation {bundle.case_id}. ASN: {geo.asn_org}",
                "pattern": f"[ipv4-addr:value = '{geo.ip}']",
                "pattern_type": "stix",
                "valid_from": timestamp
            })

    for d in bundle.domains:
        if d.is_lookalike or d.age_risk_score > 0.5:
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--domain-{hashlib.md5(d.domain.encode()).hexdigest()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"Lookalike/Typosquat Domain: {d.domain}",
                "pattern": f"[domain-name:value = '{d.domain}']",
                "pattern_type": "stix",
                "valid_from": timestamp
            })

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects
    }
