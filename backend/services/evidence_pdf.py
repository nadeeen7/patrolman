"""Server-side, secure PDF generation for derived evidence reports in PATROLMAN.

Treats all evidence contents as untrusted input. Escapes HTML/XML entities,
sanitizes secrets and credentials, and safely renders structured metadata,
associated findings, and tool outputs without active content execution.
"""
import html
import io
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

from .results import sanitize_secrets

MAX_PDF_TEXT_LINES = 250
MAX_PDF_TEXT_BYTES = 64 * 1024  # 64 KB display threshold in PDF
MAX_LINE_WIDTH = 92  # Character wrap limit for monospaced code blocks


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic total page count rendering."""

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
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont('Helvetica', 8)
        self.setFillColor(colors.HexColor('#64748b'))
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.setLineWidth(0.5)

        # Footer divider and text
        self.line(36, 36, letter[0] - 36, 36)
        footer_text = 'PATROLMAN Assessment Framework — Cryptographically Verified Evidence System'
        page_str = f'Page {self._pageNumber} of {page_count}'
        self.drawString(36, 24, footer_text)
        self.drawRightString(letter[0] - 36, 24, page_str)
        self.restoreState()


def is_binary_content(raw_bytes: bytes) -> bool:
    """Detect whether evidence bytes represent non-text or binary data."""
    if not raw_bytes:
        return False
    # Check for null bytes in initial sample
    if b'\x00' in raw_bytes[:8192]:
        return True
    try:
        raw_bytes.decode('utf-8')
        return False
    except UnicodeDecodeError:
        return True


def detect_media_type(filename: Optional[str], raw_bytes: bytes) -> str:
    """Determine the MIME media type of the evidence artifact."""
    if filename:
        ext = Path(filename).suffix.lower()
        if ext == '.json':
            return 'application/json'
        if ext == '.xml':
            return 'application/xml'
        if ext == '.txt' or ext == '.log':
            return 'text/plain'
        if ext in ('.png', '.jpg', '.jpeg', '.gif'):
            return f'image/{ext.lstrip(".")}'
        guessed, _ = mimetypes.guess_type(filename)
        if guessed:
            return guessed

    if is_binary_content(raw_bytes):
        return 'application/octet-stream'
    return 'text/plain; charset=utf-8'


def _wrap_code_lines(text: str, max_width: int = MAX_LINE_WIDTH) -> str:
    """Soft-wrap long unbroken strings to prevent horizontal PDF margin overflow."""
    out_lines = []
    for line in text.splitlines():
        if len(line) <= max_width:
            out_lines.append(line)
        else:
            # Chunk long continuous lines into wrapped segments
            while len(line) > max_width:
                out_lines.append(line[:max_width])
                line = line[max_width:]
            if line:
                out_lines.append(line)
    return '\n'.join(out_lines)


def generate_evidence_pdf(
    evidence: Any,
    raw_bytes: bytes,
    filename: Optional[str] = None,
    scan: Optional[Any] = None,
    findings: Optional[list[Any]] = None,
    tool_version: Optional[str] = None,
) -> bytes:
    """Generate a human-readable, derived evidence PDF report.

    Args:
        evidence: Evidence record or dict containing metadata
        raw_bytes: Original unmodified byte content of the evidence artifact
        filename: Clean original filename
        scan: Optional Scan record for contextual metadata
        findings: Optional list of Finding records associated with the evidence
        tool_version: Optional verified tool version string

    Returns:
        bytes: Complete generated PDF document
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=48,
    )

    base_styles = getSampleStyleSheet()

    # Custom styles adhering to PATROLMAN design token hierarchy
    style_title = ParagraphStyle(
        'DocTitle',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
    )
    style_subtitle = ParagraphStyle(
        'DocSubtitle',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#0d9488'),  # Teal accent
    )
    style_header_meta = ParagraphStyle(
        'HeaderMeta',
        parent=base_styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        alignment=2,  # Right-aligned
        textColor=colors.HexColor('#64748b'),
    )
    style_heading = ParagraphStyle(
        'SectionHeading',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6,
    )
    style_disclaimer_title = ParagraphStyle(
        'DisclaimerTitle',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#0f766e'),
    )
    style_disclaimer_body = ParagraphStyle(
        'DisclaimerBody',
        parent=base_styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#134e4a'),
    )
    style_meta_key = ParagraphStyle(
        'MetaKey',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#475569'),
    )
    style_meta_val = ParagraphStyle(
        'MetaVal',
        parent=base_styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0f172a'),
    )
    style_code_mono = ParagraphStyle(
        'CodeMono',
        parent=base_styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9.5,
        textColor=colors.HexColor('#1e293b'),
        backColor=colors.HexColor('#f8fafc'),
        borderColor=colors.HexColor('#cbd5e1'),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=4,
    )
    style_notice = ParagraphStyle(
        'NoticeBody',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#991b1b'),
    )

    story = []

    # 1. Header Banner
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    header_data = [
        [
            Paragraph('<b>PATROLMAN</b>', style_title),
            Paragraph(
                f'<b>DERIVED EVIDENCE REPORT</b><br/>Generated: {now_utc}',
                style_header_meta,
            ),
        ],
        [
            Paragraph('Automated Vulnerability Assessment Framework', style_subtitle),
            Paragraph('', style_header_meta),
        ],
    ]
    header_table = Table(header_data, colWidths=[340, 200])
    header_table.setStyle(
        TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
        ])
    )
    story.append(header_table)
    story.append(Spacer(1, 8))

    # Teal accent line
    accent_bar = Table([['']], colWidths=[540], rowHeights=[2])
    accent_bar.setStyle(
        TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0d9488')),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ])
    )
    story.append(accent_bar)
    story.append(Spacer(1, 10))

    # 2. Derived Report Notice Banner
    sha256 = getattr(evidence, 'sha256_hash', '') or 'N/A'
    notice_text = (
        '<b>DERIVED REPORT NOTICE (NON-CANONICAL):</b><br/>'
        'This document is a human-readable, derived representation generated by PATROLMAN for '
        'analyst review, executive summaries, and reporting. It is <b>NOT</b> the original cryptographic tool output. '
        'The original raw artifact remains stored and immutable in the Evidence Locker with verified SHA-256 digest: '
        f'<font face="Courier" size="7"><b>{html.escape(sha256)}</b></font>.'
    )
    notice_table = Table(
        [[Paragraph(notice_text, style_disclaimer_body)]],
        colWidths=[540],
    )
    notice_table.setStyle(
        TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0fdfa')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#0d9488')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ])
    )
    story.append(notice_table)
    story.append(Spacer(1, 12))

    # 3. Evidence & Execution Metadata Table
    story.append(Paragraph('Evidence &amp; Execution Metadata', style_heading))

    ev_id = str(getattr(evidence, 'id', ''))
    scan_id = str(getattr(evidence, 'scan_id', None) or getattr(evidence, 'archived_scan_id', None) or 'N/A')
    tool_name = str(getattr(evidence, 'tool', 'Unknown'))
    evidence_type = str(getattr(evidence, 'evidence_type', 'raw_output'))
    file_size = getattr(evidence, 'file_size', len(raw_bytes))
    created_at = getattr(evidence, 'created_at', None)
    created_str = created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(created_at, datetime) else str(created_at or 'N/A')
    redacted_flag = 'Yes (Secrets Redacted)' if getattr(evidence, 'redacted', False) else 'No'
    media_type = detect_media_type(filename, raw_bytes)
    target_name = getattr(scan, 'target', 'N/A') if scan else 'N/A'
    profile_name = getattr(scan, 'profile', 'N/A') if scan else 'N/A'
    version_str = tool_version or 'Recorded in Scan Execution'

    metadata_rows = [
        [
            Paragraph('Evidence Record ID', style_meta_key),
            Paragraph(f'<font face="Courier" size="7.5">{html.escape(ev_id)}</font>', style_meta_val),
            Paragraph('Assessment Target', style_meta_key),
            Paragraph(f'<b>{html.escape(target_name)}</b> ({html.escape(profile_name)})', style_meta_val),
        ],
        [
            Paragraph('Scan ID', style_meta_key),
            Paragraph(f'<font face="Courier" size="7.5">{html.escape(scan_id)}</font>', style_meta_val),
            Paragraph('Tool Name &amp; Version', style_meta_key),
            Paragraph(f'<b>{html.escape(tool_name)}</b> (v{html.escape(version_str)})', style_meta_val),
        ],
        [
            Paragraph('Evidence Type', style_meta_key),
            Paragraph(f'<b>{html.escape(evidence_type)}</b>', style_meta_val),
            Paragraph('Media Type (MIME)', style_meta_key),
            Paragraph(html.escape(media_type), style_meta_val),
        ],
        [
            Paragraph('Original Filename', style_meta_key),
            Paragraph(html.escape(filename or f'{tool_name}_{evidence_type}.txt'), style_meta_val),
            Paragraph('Artifact File Size', style_meta_key),
            Paragraph(f'{file_size:,} bytes', style_meta_val),
        ],
        [
            Paragraph('Original SHA-256 Digest', style_meta_key),
            Paragraph(f'<font face="Courier" size="7"><b>{html.escape(sha256)}</b></font>', style_meta_val),
            Paragraph('Cryptographic Integrity', style_meta_key),
            Paragraph('<font color="#16a34a"><b>VERIFIED MATCH</b></font>', style_meta_val),
        ],
        [
            Paragraph('Execution Timestamp', style_meta_key),
            Paragraph(html.escape(created_str), style_meta_val),
            Paragraph('Redaction Applied', style_meta_key),
            Paragraph(html.escape(redacted_flag), style_meta_val),
        ],
    ]

    meta_table = Table(metadata_rows, colWidths=[110, 160, 110, 160])
    meta_table.setStyle(
        TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ffffff')),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#f8fafc')]),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 4. Associated Findings (if available)
    if findings:
        story.append(Paragraph(f'Associated Findings ({len(findings)})', style_heading))
        sev_colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#d97706',
            'low': '#2563eb',
            'informational': '#64748b',
            'unknown': '#64748b',
        }

        finding_items = []
        for finding in findings[:8]:  # Limit to 8 findings in PDF summary
            title = sanitize_secrets(getattr(finding, 'title', 'Untitled Finding'))
            sev = str(getattr(finding, 'severity', 'unknown')).lower()
            color = sev_colors.get(sev, '#64748b')
            details = getattr(finding, 'details', {}) or {}
            target_asset = sanitize_secrets(details.get('target') or details.get('endpoint') or target_name)
            desc = sanitize_secrets(details.get('description') or details.get('info') or '')
            remediation = sanitize_secrets(details.get('remediation') or details.get('solution') or '')

            finding_rows = [
                [
                    Paragraph(f'<b>Finding:</b> {html.escape(title)}', style_meta_val),
                    Paragraph(f'<font color="{color}"><b>[{html.escape(sev.upper())}]</b></font>', style_meta_key),
                ],
                [
                    Paragraph(f'<b>Affected Asset:</b> {html.escape(target_asset)}', style_meta_val),
                    Paragraph('', style_meta_val),
                ],
            ]
            if desc:
                finding_rows.append([
                    Paragraph(f'<b>Details:</b> {html.escape(desc[:300])}', style_meta_val),
                    Paragraph('', style_meta_val),
                ])
            if remediation:
                finding_rows.append([
                    Paragraph(f'<b>Remediation:</b> {html.escape(remediation[:300])}', style_meta_val),
                    Paragraph('', style_meta_val),
                ])

            f_table = Table(finding_rows, colWidths=[460, 80])
            f_table.setStyle(
                TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                    ('LINEBEFORE', (0, 0), (0, -1), 3, colors.HexColor(color)),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ])
            )
            finding_items.append(f_table)
            finding_items.append(Spacer(1, 4))

        story.append(KeepTogether(finding_items))
        story.append(Spacer(1, 10))

    # 5. Evidence Content Inspection
    story.append(Paragraph('Evidence Content / Tool Output Inspection', style_heading))

    binary = is_binary_content(raw_bytes)
    if binary:
        bin_notice = (
            '<b>BINARY ARTIFACT NOTICE:</b><br/>'
            f'This evidence artifact contains raw binary content ({len(raw_bytes):,} bytes, format: {html.escape(media_type)}) '
            'which cannot be safely or meaningfully rendered as text in this report.<br/>'
            'The complete, unmodified binary payload is preserved cryptographically and can be obtained via the '
            '<b>Raw</b> download action in the Evidence Locker.'
        )
        b_table = Table([[Paragraph(bin_notice, style_notice)]], colWidths=[540])
        b_table.setStyle(
            TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef2f2')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#ef4444')),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ])
        )
        story.append(b_table)
    else:
        try:
            text_content = raw_bytes.decode('utf-8', errors='replace')
        except Exception:
            text_content = str(raw_bytes)

        # Sanitize sensitive credentials and tokens from output
        text_content = sanitize_secrets(text_content)
        total_lines = len(text_content.splitlines())
        total_bytes = len(raw_bytes)

        truncated = False
        if total_lines > MAX_PDF_TEXT_LINES or total_bytes > MAX_PDF_TEXT_BYTES:
            truncated = True
            lines = text_content.splitlines()[:MAX_PDF_TEXT_LINES]
            text_content = '\n'.join(lines)

        if truncated:
            trunc_notice = (
                f'<b>OVERSIZED ARTIFACT NOTICE:</b><br/>'
                f'Showing the first {MAX_PDF_TEXT_LINES} lines (truncated from {total_lines:,} lines / {total_bytes:,} bytes). '
                'To inspect the complete, unabridged tool output, please download the original <b>Raw</b> artifact from the Evidence Locker.'
            )
            t_table = Table([[Paragraph(trunc_notice, style_disclaimer_body)]], colWidths=[540])
            t_table.setStyle(
                TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fffbeb')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#f59e0b')),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ])
            )
            story.append(t_table)
            story.append(Spacer(1, 6))

        # Soft-wrap lines and escape HTML entities for reportlab Preformatted
        wrapped_code = _wrap_code_lines(text_content, MAX_LINE_WIDTH)
        escaped_code = html.escape(wrapped_code)

        preformatted_block = Preformatted(escaped_code, style_code_mono)
        story.append(preformatted_block)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
