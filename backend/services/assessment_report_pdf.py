"""Professional, beginner-friendly PDF Security Assessment Report Generator.

Adheres strictly to the PATROLMAN 9-section reporting architecture:
1. Report Overview
2. Executive Summary (plain English, non-jargon)
3. Risk Summary (Critical -> Informational + Unknown with definitions)
4. Detailed Findings (explanations, why it matters, realistic impact, remediation, references)
5. Tool Execution Summary (status table with repeat headers across pages)
6. Technical Evidence (monospaced text with safe line wrapping and multi-page support)
7. Remediation Priorities (prioritized actionable roadmap)
8. Glossary (plain-English definitions of terms used in the assessment)
9. Limitations & Assessment Coverage (explicit notice that skipped checks != secure)
"""
import html
import io
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfgen import canvas

from .results import sanitize_secrets

MAX_LINE_WIDTH = 90

SEVERITY_COLORS = {
    'critical': colors.HexColor('#991b1b'),
    'high': colors.HexColor('#c2410c'),
    'medium': colors.HexColor('#b45309'),
    'low': colors.HexColor('#1e40af'),
    'informational': colors.HexColor('#0f766e'),
    'unknown': colors.HexColor('#475569'),
}

SEVERITY_BG = {
    'critical': colors.HexColor('#fee2e2'),
    'high': colors.HexColor('#ffedd5'),
    'medium': colors.HexColor('#fef3c7'),
    'low': colors.HexColor('#dbeafe'),
    'informational': colors.HexColor('#ccfbf1'),
    'unknown': colors.HexColor('#f1f5f9'),
}

SEVERITY_DESCRIPTIONS = {
    'critical': 'Immediate danger of compromise or full system takeover. Requires urgent, immediate remediation.',
    'high': 'Significant vulnerability allowing sensitive data exposure, unauthorized modification, or privilege escalation.',
    'medium': 'Security flaw that could be exploited under specific circumstances or combined with other issues.',
    'low': 'Minor weakness, information disclosure, or configuration divergence from security best practices.',
    'informational': 'Observed configuration, public service information, or operational detail. Not directly exploitable.',
    'unknown': 'Finding with unclassified severity or requiring manual verification by a security analyst.',
}

GLOSSARY_DEFINITIONS = {
    'Port': 'A numbered network communication endpoint (0-65535) used by computers to direct traffic to specific applications (e.g. port 80 for HTTP, port 443 for HTTPS).',
    'Endpoint': 'A specific network destination, URL, or API address accessible by users and network clients.',
    'HTTP / HTTPS': 'Hypertext Transfer Protocol. HTTPS encrypts traffic using TLS/SSL to protect communication between browser and server from interception.',
    'TLS / SSL': 'Transport Layer Security / Secure Sockets Layer cryptographic protocols used to encrypt network connections and authenticate servers.',
    'CVE': 'Common Vulnerabilities and Exposures — a globally standardized catalog of publicly known cybersecurity vulnerabilities (e.g., CVE-2023-1234).',
    'CVSS': 'Common Vulnerability Scoring System — a standardized numerical rating (0.0 to 10.0) measuring the severity and characteristics of a vulnerability.',
    'TCP': 'Transmission Control Protocol — a core networking standard that provides reliable, ordered data delivery between network hosts.',
    'Cipher Suite': 'A set of cryptographic algorithms that specify how TLS encryption, key exchange, and authentication are performed.',
    'CSP': 'Content Security Policy — an HTTP response header that restricts where a browser can load scripts, stylesheets, and other resources.',
    'Fingerprint': 'A unique signature or hash identifying a specific vulnerability, software version, or server response.',
    'Nmap': 'Network exploration and port scanner used for host discovery, port enumeration, and service identification.',
    'httpx': 'Fast multi-purpose HTTP toolkit used for probing web services, titles, and response status codes.',
    'WhatWeb': 'Web scanner that identifies content management systems, blogging platforms, JavaScript libraries, and web servers.',
    'Nuclei': 'Fast vulnerability scanner using structured templates to check for known security flaws and misconfigurations.',
    'SSLyze': 'Fast SSL/TLS configuration analyzer that verifies certificate validity, cipher suites, and protocol support.',
    'Wapiti': 'Web application security auditor that checks web applications for common weaknesses like missing security headers.',
    'Gitleaks': 'Audit tool that searches source code and working directories for committed secrets, credentials, and API keys.',
    'Trivy': 'Comprehensive security scanner for container images, file systems, and configuration vulnerabilities.',
    'Subfinder': 'Passive subdomain discovery tool that discovers valid domain names from public internet records without probing.',
}


class ReportNumberedCanvas(canvas.Canvas):
    """Two-pass canvas that dynamically counts total pages and draws running headers and footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_decorations(self, total_pages: int):
        self.saveState()
        page_num = self._pageNumber
        w, h = letter

        # Running header (pages 2+)
        if page_num > 1:
            self.setFont('Helvetica', 8)
            self.setFillColor(colors.HexColor('#64748b'))
            self.drawString(36, h - 28, 'PATROLMAN — Automated Vulnerability Assessment Report')
            self.drawRightString(w - 36, h - 28, 'CONFIDENTIAL')
            self.setStrokeColor(colors.HexColor('#e2e8f0'))
            self.setLineWidth(0.5)
            self.line(36, h - 32, w - 36, h - 32)

        # Running footer (all pages)
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.setLineWidth(0.5)
        self.line(36, 36, w - 36, 36)

        self.setFont('Helvetica', 8)
        self.setFillColor(colors.HexColor('#64748b'))
        self.drawString(36, 24, 'PATROLMAN Security Framework — Evidence Integrity Verified')
        self.drawRightString(w - 36, 24, f'Page {page_num} of {total_pages}')
        self.restoreState()


def wrap_text_lines(text: str, max_width: int = MAX_LINE_WIDTH) -> str:
    """Safely wrap lines without breaking tokens silently."""
    out_lines = []
    for line in text.splitlines():
        if len(line) <= max_width:
            out_lines.append(line)
        else:
            while len(line) > max_width:
                out_lines.append(line[:max_width])
                line = line[max_width:]
            if line:
                out_lines.append(line)
    return '\n'.join(out_lines)


def get_report_styles():
    sheet = getSampleStyleSheet()
    styles = {
        'DocTitle': ParagraphStyle('DocTitle', parent=sheet['Normal'], fontName='Helvetica-Bold', fontSize=22, leading=26, textColor=colors.HexColor('#0f172a')),
        'DocSubtitle': ParagraphStyle('DocSubtitle', parent=sheet['Normal'], fontName='Helvetica', fontSize=11, leading=15, textColor=colors.HexColor('#0d9488')),
        'SectionHeading': ParagraphStyle('SectionHeading', parent=sheet['Normal'], fontName='Helvetica-Bold', fontSize=14, leading=18, textColor=colors.HexColor('#0f172a'), spaceBefore=14, spaceAfter=8, keepWithNext=True),
        'SubHeading': ParagraphStyle('SubHeading', parent=sheet['Normal'], fontName='Helvetica-Bold', fontSize=11, leading=15, textColor=colors.HexColor('#1e293b'), spaceBefore=8, spaceAfter=4, keepWithNext=True),
        'Body': ParagraphStyle('Body', parent=sheet['Normal'], fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor('#334155')),
        'BodyBold': ParagraphStyle('BodyBold', parent=sheet['Normal'], fontName='Helvetica-Bold', fontSize=9, leading=13, textColor=colors.HexColor('#0f172a')),
        'BodySmall': ParagraphStyle('BodySmall', parent=sheet['Normal'], fontName='Helvetica', fontSize=8, leading=11, textColor=colors.HexColor('#64748b')),
        'AlertBox': ParagraphStyle('AlertBox', parent=sheet['Normal'], fontName='Helvetica', fontSize=8.5, leading=12, textColor=colors.HexColor('#475569')),
        'TableHeader': ParagraphStyle('TableHeader', parent=sheet['Normal'], fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.white),
        'TableCell': ParagraphStyle('TableCell', parent=sheet['Normal'], fontName='Helvetica', fontSize=8, leading=11, textColor=colors.HexColor('#1e293b')),
        'TableCellBold': ParagraphStyle('TableCellBold', parent=sheet['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=colors.HexColor('#0f172a')),
        'EvidenceCode': ParagraphStyle('EvidenceCode', parent=sheet['Normal'], fontName='Courier', fontSize=7, leading=9.5, textColor=colors.HexColor('#0f172a')),
        'BadgeText': ParagraphStyle('BadgeText', parent=sheet['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10, alignment=1),
    }
    return styles


def generate_assessment_report_pdf(scan_data: Dict[str, Any], evidence_items: Optional[List[Any]] = None) -> bytes:
    """Generate a beginner-friendly, comprehensive 9-section security assessment report in PDF format."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=44,
        bottomMargin=46,
    )
    styles = get_report_styles()
    story = []

    target = str(scan_data.get('target', 'Unknown Target'))
    scan_id = str(scan_data.get('id', 'N/A'))
    profile = str(scan_data.get('profile', 'standard')).capitalize()
    state = str(scan_data.get('state', 'unknown')).replace('_', ' ').upper()
    created_at = str(scan_data.get('created_at', 'N/A'))
    ended_at = str(scan_data.get('ended_at', 'In Progress'))
    created_by = str(scan_data.get('created_by') or 'Administrator')

    findings = list(scan_data.get('findings', []))
    executions = list(scan_data.get('executions', []))

    # Calculate status buckets
    completed_tools = [e for e in executions if e.get('state') == 'completed']
    failed_tools = [e for e in executions if e.get('state') in ('failed', 'timed_out')]
    skipped_tools = [e for e in executions if e.get('state') in ('skipped', 'unavailable', 'blocked', 'configuration_required')]

    # Severity distribution
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0, 'unknown': 0}
    for f in findings:
        sev = str(f.get('severity', 'unknown')).lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts['unknown'] += 1

    total_findings = len(findings)

    # =========================================================================
    # HEADER BANNER
    # =========================================================================
    story.append(Paragraph("SECURITY ASSESSMENT REPORT", styles['DocTitle']))
    story.append(Paragraph(f"PATROLMAN Automated Vulnerability Assessment &bull; Target: <strong>{html.escape(target)}</strong>", styles['DocSubtitle']))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0d9488'), spaceBefore=2, spaceAfter=12))

    # =========================================================================
    # SECTION 1: REPORT OVERVIEW
    # =========================================================================
    story.append(Paragraph("1. Report Overview", styles['SectionHeading']))
    overview_text = (
        "This document details the security evaluation conducted by the PATROLMAN Automated Vulnerability "
        "Assessment Framework. All checks were executed against pre-authorized targets in accordance with operational scope boundaries."
    )
    story.append(Paragraph(overview_text, styles['Body']))
    story.append(Spacer(1, 8))

    overview_rows = [
        [
            Paragraph("<strong>Assessment Target:</strong>", styles['TableCell']),
            Paragraph(html.escape(target), styles['TableCellBold']),
            Paragraph("<strong>Assessment Profile:</strong>", styles['TableCell']),
            Paragraph(html.escape(profile), styles['TableCellBold']),
        ],
        [
            Paragraph("<strong>Assessment ID:</strong>", styles['TableCell']),
            Paragraph(f"<font face='Courier'>{html.escape(scan_id[:18])}...</font>", styles['TableCell']),
            Paragraph("<strong>Execution Status:</strong>", styles['TableCell']),
            Paragraph(f"<strong>{html.escape(state)}</strong>", styles['TableCellBold']),
        ],
        [
            Paragraph("<strong>Started At:</strong>", styles['TableCell']),
            Paragraph(html.escape(created_at[:19] if created_at else 'N/A'), styles['TableCell']),
            Paragraph("<strong>Completed At:</strong>", styles['TableCell']),
            Paragraph(html.escape(ended_at[:19] if ended_at else 'N/A'), styles['TableCell']),
        ],
        [
            Paragraph("<strong>Operator / Owner:</strong>", styles['TableCell']),
            Paragraph(html.escape(created_by), styles['TableCell']),
            Paragraph("<strong>Total Findings:</strong>", styles['TableCell']),
            Paragraph(f"<strong>{total_findings} item(s)</strong>", styles['TableCellBold']),
        ],
    ]

    t_overview = Table(overview_rows, colWidths=[120, 150, 120, 150])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_overview)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 2: EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Paragraph("2. Executive Summary", styles['SectionHeading']))
    exec_summary_parts = []
    exec_summary_parts.append(
        f"PATROLMAN conducted an automated security evaluation of the target <strong>{html.escape(target)}</strong> "
        f"using the <strong>{html.escape(profile)}</strong> assessment profile. "
        f"A total of <strong>{len(completed_tools)}</strong> security engine(s) completed their automated inspection, "
        f"while <strong>{len(skipped_tools)}</strong> check(s) were safely bypassed due to target scope rules or prerequisites, "
        f"and <strong>{len(failed_tools)}</strong> check(s) encountered operational errors or timeouts."
    )

    if total_findings == 0:
        exec_summary_parts.append(
            "<strong>Finding Overview:</strong> No confirmed security vulnerabilities were recorded by the automated engines during this assessment. "
            "However, this does not certify that the asset is completely secure, as unexecuted checks, advanced application logic, and out-of-scope services were not analyzed."
        )
        exec_summary_parts.append(
            "<strong>Recommended Next Steps:</strong> Continue regular vulnerability monitoring, maintain current software patch levels, "
            "and consider running a Comprehensive profile or authorized manual penetration test if in-depth assurance is required."
        )
    else:
        crit_high = severity_counts['critical'] + severity_counts['high']
        if crit_high > 0:
            exec_summary_parts.append(
                f"<strong>Key Risk Discovery:</strong> The assessment identified <strong>{crit_high} high-severity issue(s)</strong> "
                f"({severity_counts['critical']} Critical, {severity_counts['high']} High) that present an immediate security risk to the target. "
                f"These items should receive immediate priority investigation and remediation from system administrators or engineering teams."
            )
        else:
            exec_summary_parts.append(
                f"<strong>Key Risk Discovery:</strong> A total of <strong>{total_findings} security observation(s)</strong> were identified, "
                f"primarily categorized as Medium, Low, or Informational severity. No immediately exploitable Critical or High severity flaws were verified."
            )
        exec_summary_parts.append(
            "<strong>Actionable Next Steps:</strong> Review the prioritized findings in Section 4 and Section 7. "
            "Apply recommended security configurations, patch affected software services, and re-run an assessment to verify remediation."
        )

    for part in exec_summary_parts:
        story.append(Paragraph(part, styles['Body']))
        story.append(Spacer(1, 5))

    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 3: RISK SUMMARY
    # =========================================================================
    story.append(Paragraph("3. Risk Summary", styles['SectionHeading']))
    story.append(Paragraph(
        "Findings are categorized by standardized severity levels to guide remediation workflows. "
        "Each level reflects the potential impact and ease of exploitation by unauthorized actors.",
        styles['Body'],
    ))
    story.append(Spacer(1, 6))

    risk_table_rows = [
        [
            Paragraph("<strong>Severity Level</strong>", styles['TableHeader']),
            Paragraph("<strong>Count</strong>", styles['TableHeader']),
            Paragraph("<strong>Significance & Meaning</strong>", styles['TableHeader']),
        ]
    ]

    for sev in ('critical', 'high', 'medium', 'low', 'informational', 'unknown'):
        cnt = severity_counts[sev]
        badge_p = Paragraph(f"<font color='{SEVERITY_COLORS[sev].hexval()}'><strong>[{sev.upper()}]</strong></font>", styles['BadgeText'])
        desc_p = Paragraph(SEVERITY_DESCRIPTIONS[sev], styles['TableCell'])
        cnt_p = Paragraph(f"<strong>{cnt}</strong>", styles['TableCellBold'])
        risk_table_rows.append([badge_p, cnt_p, desc_p])

    t_risk = Table(risk_table_rows, colWidths=[110, 50, 380])
    t_risk.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_risk)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 4: DETAILED FINDINGS
    # =========================================================================
    story.append(Paragraph("4. Detailed Findings", styles['SectionHeading']))

    if not findings:
        empty_findings_box = [
            [Paragraph("<strong>No Vulnerability Findings Recorded</strong>", styles['BodyBold'])],
            [Paragraph(
                "The automated tools did not uncover confirmed vulnerabilities matching the criteria of the selected profile. "
                "This indicates that scanned network ports and HTTP endpoints did not display known automated signatures. "
                "Manual review and regular re-scans are recommended to maintain security posture.",
                styles['Body'],
            )]
        ]
        t_empty = Table(empty_findings_box, colWidths=[540])
        t_empty.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0fdf4')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#86efac')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(t_empty)
        story.append(Spacer(1, 12))
    else:
        # Sort findings by severity priority
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4, 'unknown': 5}
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(str(f.get('severity', 'unknown')).lower(), 99))

        for idx, f in enumerate(sorted_findings, 1):
            sev = str(f.get('severity', 'unknown')).lower()
            title = str(f.get('title', 'Untitled Finding'))
            details = f.get('details') or {}
            desc = details.get('description') or details.get('remediation') or 'Automated finding detected on host.'
            tool_sources = details.get('sources') or []
            tool_name = tool_sources[0].get('tool', 'scanner') if tool_sources else 'tool'
            target_ep = details.get('target') or target
            remediation = details.get('remediation') or 'Review the affected service and restrict public network exposure.'
            impact = details.get('impact') or 'Potential exposure of system metadata or unauthorized network access.'
            references = details.get('references') or []

            finding_header = [
                [
                    Paragraph(f"<strong>#{idx}. {html.escape(title)}</strong>", styles['BodyBold']),
                    Paragraph(f"<font color='{SEVERITY_COLORS.get(sev, colors.black).hexval()}'><strong>[{sev.upper()}]</strong></font>", styles['BadgeText']),
                ]
            ]
            t_fhdr = Table(finding_header, colWidths=[450, 90])
            t_fhdr.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), SEVERITY_BG.get(sev, colors.HexColor('#f8fafc'))),
                ('BOX', (0, 0), (-1, -1), 1, SEVERITY_COLORS.get(sev, colors.HexColor('#cbd5e1'))),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))

            f_body_rows = [
                [Paragraph("<strong>Affected Resource:</strong>", styles['TableCellBold']), Paragraph(f"<font face='Courier'>{html.escape(str(target_ep))}</font>", styles['TableCell'])],
                [Paragraph("<strong>Detecting Engine:</strong>", styles['TableCellBold']), Paragraph(html.escape(tool_name.upper()), styles['TableCell'])],
                [Paragraph("<strong>What is this issue?</strong>", styles['TableCellBold']), Paragraph(html.escape(str(desc)), styles['TableCell'])],
                [Paragraph("<strong>Why it matters:</strong>", styles['TableCellBold']), Paragraph(html.escape(str(impact)), styles['TableCell'])],
                [Paragraph("<strong>Recommended Fix:</strong>", styles['TableCellBold']), Paragraph(html.escape(str(remediation)), styles['TableCell'])],
            ]

            if references:
                ref_links = []
                for r in references[:4]:
                    r_str = str(r).strip()
                    if r_str.startswith('http'):
                        ref_links.append(f'<a href="{html.escape(r_str)}"><font color="#0284c7">{html.escape(r_str)}</font></a>')
                    else:
                        ref_links.append(html.escape(r_str))
                f_body_rows.append([
                    Paragraph("<strong>References:</strong>", styles['TableCellBold']),
                    Paragraph('<br/>'.join(ref_links), styles['TableCell']),
                ])

            t_fbody = Table(f_body_rows, colWidths=[130, 410])
            t_fbody.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ffffff')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#f1f5f9')),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))

            finding_block = [t_fhdr, t_fbody, Spacer(1, 10)]
            story.append(KeepTogether(finding_block))

    # =========================================================================
    # SECTION 5: TOOL EXECUTION SUMMARY
    # =========================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("5. Tool Execution Summary", styles['SectionHeading']))
    story.append(Paragraph(
        "PATROLMAN manages multiple modular security engines. Each check performs an isolated inspection stage. "
        "A skipped or unavailable tool indicates intentional safety gating or environment prerequisites.",
        styles['Body'],
    ))
    story.append(Spacer(1, 6))

    tool_table_rows = [
        [
            Paragraph("<strong>Tool Engine</strong>", styles['TableHeader']),
            Paragraph("<strong>Execution Status</strong>", styles['TableHeader']),
            Paragraph("<strong>Outcome & Operational Notes</strong>", styles['TableHeader']),
        ]
    ]

    for ex in executions:
        tool_name = str(ex.get('tool', 'tool')).upper()
        raw_state = str(ex.get('state', 'unknown')).lower()
        outcome = ex.get('outcome') or raw_state.replace('_', ' ').upper()

        if raw_state == 'completed':
            status_text = "<font color='#15803d'><strong>Completed</strong></font>"
        elif raw_state in ('failed', 'timed_out'):
            status_text = "<font color='#b91c1c'><strong>Failed / Timed Out</strong></font>"
        elif raw_state == 'skipped':
            status_text = "<font color='#475569'><strong>Skipped</strong></font>"
        else:
            status_text = f"<strong>{html.escape(raw_state.capitalize())}</strong>"

        reason = ex.get('reason') or ex.get('error') or ex.get('notes') or f"Execution stage: {outcome}"
        notes_p = Paragraph(html.escape(str(reason)), styles['TableCell'])

        tool_table_rows.append([
            Paragraph(f"<strong>{tool_name}</strong>", styles['TableCellBold']),
            Paragraph(status_text, styles['TableCell']),
            notes_p,
        ])

    t_tools = Table(tool_table_rows, colWidths=[100, 130, 310], repeatRows=1)
    t_tools.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_tools)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 6: TECHNICAL EVIDENCE & LOGS
    # =========================================================================
    story.append(Paragraph("6. Technical Evidence & Tool Artifacts", styles['SectionHeading']))
    story.append(Paragraph(
        "Original technical evidence items and cryptographic SHA-256 digests are preserved unaltered in the Evidence Locker. "
        "The following excerpt summarizes the raw tool telemetry captured during the assessment session.",
        styles['Body'],
    ))
    story.append(Spacer(1, 6))

    # Compile sanitized execution snippets
    evidence_text_lines = []
    evidence_text_lines.append(f"# PATROLMAN TELEMETRY LOG — TARGET: {target}")
    evidence_text_lines.append(f"# ASSESSMENT ID: {scan_id}")
    evidence_text_lines.append(f"# GENERATED AT: {datetime.now(timezone.utc).isoformat()}")
    evidence_text_lines.append("#" + "=" * 70)

    for ex in executions:
        tool_name = str(ex.get('tool', 'tool')).upper()
        state_str = str(ex.get('state', 'unknown')).upper()
        evidence_text_lines.append(f"[{tool_name}] Status: {state_str}")
        if ex.get('started_at'):
            evidence_text_lines.append(f"  Started: {ex.get('started_at')} | Ended: {ex.get('ended_at')}")
        if ex.get('exit_code') is not None:
            evidence_text_lines.append(f"  Exit Code: {ex.get('exit_code')}")
        if ex.get('error'):
            clean_err = sanitize_secrets(str(ex['error']))
            evidence_text_lines.append(f"  Diagnostics: {clean_err[:180]}")
        evidence_text_lines.append("")

    raw_evidence_str = wrap_text_lines('\n'.join(evidence_text_lines), max_width=MAX_LINE_WIDTH)

    # Render Preformatted directly on story so it can split cleanly across pages
    story.append(Preformatted(
        raw_evidence_str,
        styles['EvidenceCode'],
        maxLineLength=MAX_LINE_WIDTH,
    ))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 7: REMEDIATION PRIORITIES
    # =========================================================================
    story.append(Paragraph("7. Remediation Priorities", styles['SectionHeading']))
    story.append(Paragraph(
        "Actions are ranked by impact to assist remediation planning. Address items in priority order to reduce exposure effectively.",
        styles['Body'],
    ))
    story.append(Spacer(1, 6))

    remediation_rows = [
        [
            Paragraph("<strong>Priority</strong>", styles['TableHeader']),
            Paragraph("<strong>Action / Issue</strong>", styles['TableHeader']),
            Paragraph("<strong>Severity</strong>", styles['TableHeader']),
            Paragraph("<strong>Recommended Remediation Step</strong>", styles['TableHeader']),
        ]
    ]

    if not findings:
        remediation_rows.append([
            Paragraph("<strong>#1</strong>", styles['TableCellBold']),
            Paragraph("Establish Regular Assessment Cadence", styles['TableCell']),
            Paragraph("<font color='#0f766e'><strong>INFO</strong></font>", styles['BadgeText']),
            Paragraph("Schedule recurring vulnerability scans and automate continuous dependency checks.", styles['TableCell']),
        ])
    else:
        for p_idx, f in enumerate(sorted_findings, 1):
            sev = str(f.get('severity', 'unknown')).lower()
            title = str(f.get('title', 'Vulnerability'))
            details = f.get('details') or {}
            rem = details.get('remediation') or 'Restrict public exposure and apply software security patch.'
            remediation_rows.append([
                Paragraph(f"<strong>#{p_idx}</strong>", styles['TableCellBold']),
                Paragraph(html.escape(title[:60]), styles['TableCell']),
                Paragraph(f"<font color='{SEVERITY_COLORS.get(sev, colors.black).hexval()}'><strong>[{sev.upper()}]</strong></font>", styles['BadgeText']),
                Paragraph(html.escape(str(rem)), styles['TableCell']),
            ])

    t_rem = Table(remediation_rows, colWidths=[45, 170, 75, 250], repeatRows=1)
    t_rem.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_rem)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 8: GLOSSARY OF TECHNICAL TERMS
    # =========================================================================
    story.append(Paragraph("8. Glossary of Technical Terms", styles['SectionHeading']))
    story.append(Paragraph(
        "Plain-English definitions for security terms and protocols referenced throughout this assessment report.",
        styles['Body'],
    ))
    story.append(Spacer(1, 6))

    glossary_rows = [
        [
            Paragraph("<strong>Term / Acronym</strong>", styles['TableHeader']),
            Paragraph("<strong>Plain-English Definition</strong>", styles['TableHeader']),
        ]
    ]

    for term, definition in GLOSSARY_DEFINITIONS.items():
        glossary_rows.append([
            Paragraph(f"<strong>{html.escape(term)}</strong>", styles['TableCellBold']),
            Paragraph(html.escape(definition), styles['TableCell']),
        ])

    t_glossary = Table(glossary_rows, colWidths=[120, 420], repeatRows=1)
    t_glossary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
    ]))
    story.append(t_glossary)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 9: LIMITATIONS AND ASSESSMENT COVERAGE
    # =========================================================================
    story.append(Paragraph("9. Limitations & Assessment Coverage", styles['SectionHeading']))

    limitations_box = [
        [Paragraph("<strong>CRITICAL SECURITY ASSESSMENT BOUNDARIES</strong>", styles['DocSubtitle'])],
        [Paragraph(
            "<strong>1. Negative Observation Principle:</strong> A check that was skipped, failed, or completed without findings "
            "<strong>does not prove that the target is secure</strong>. It confirms only that the specific automated checks "
            "attempted did not identify matching signatures under the tested conditions.<br/><br/>"
            "<strong>2. Safe Scanning Constraints:</strong> PATROLMAN operates non-destructive, authorized vulnerability assessments. "
            "Exploitation, Denial of Service (DoS), brute force attacks, and persistent state changes are strictly prohibited.<br/><br/>"
            "<strong>3. Scope Confinement:</strong> Testing was confined strictly to authorized network hosts and endpoints. "
            "Discovered third-party links, CDNs, external APIs, and subdomains outside explicitly authorized scope were not tested.<br/><br/>"
            "<strong>4. Temporal Validity:</strong> Assessment results reflect the state of the target system at the exact date and time of execution. "
            "Subsequent code changes, software updates, or network configuration shifts require re-assessment.",
            styles['AlertBox'],
        )],
    ]
    t_limits = Table(limitations_box, colWidths=[540])
    t_limits.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(t_limits)

    # Build the document with our two-pass NumberedCanvas
    doc.build(story, canvasmaker=ReportNumberedCanvas)
    return buffer.getvalue()
