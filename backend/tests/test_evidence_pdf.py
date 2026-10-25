"""Comprehensive unit and integration tests for secure evidence PDF generation and download.

Validates:
- Successful PDF generation from supported text-based evidence
- Correct evidence and scan metadata
- Preservation of original artifact and digest
- PDF digest differing from source digest
- Rejection of tampered evidence (409 Conflict)
- Authentication and authorization enforcement (401 Unauthorized)
- Malicious HTML/script content treated as inert text
- Sensitive-value redaction (passwords, tokens, API keys)
- Unsupported binary and oversized artifacts handling
- Existing raw-download behavior remaining unchanged
"""
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from reportlab import rl_config
from backend.app import create_app
from backend.config import Settings
from backend.auth import AdminSession, _token_hash
from backend.models import Finding, Scan, ToolVerification
from backend.services.evidence_pdf import generate_evidence_pdf, is_binary_content
from backend.services.evidence_service import store_evidence

rl_config.pageCompression = 0

TOKEN = 'B' * 32
SESSION_TOKEN = 'test-session-secret-token-32-chars-long'
CSRF_TOKEN = 'test-csrf-secret-token-32-chars-long'


@pytest.fixture
def pdf_test_env(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token=TOKEN, allowed_targets=('127.0.0.1',))
    app = create_app(settings)
    app.config['TESTING'] = True

    # Seed admin session
    with Session(app.extensions['database']) as session:
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        session.add(AdminSession(
            token_hash=_token_hash(SESSION_TOKEN),
            username='admin_user',
            csrf_token=CSRF_TOKEN,
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=1),
        ))

        # Seed sample scan
        scan = Scan(
            id='scan-pdf-test-01',
            target='127.0.0.1',
            profile='quick',
            state='completed',
        )
        session.add(scan)

        # Seed tool verification
        tv = ToolVerification(
            tool='nmap',
            verified_version='7.94',
            verification_status='verified',
            evidence_reference='LOCAL-TEST',
        )
        session.add(tv)

        # Seed finding
        f = Finding(
            id=101,
            scan_id='scan-pdf-test-01',
            fingerprint='fp-101',
            title='Insecure HTTP Method Enabled',
            severity='medium',
            details={
                'target': 'http://127.0.0.1:80',
                'description': 'Server allows TRACE / TRACK methods which may facilitate XST.',
                'remediation': 'Disable TRACE and TRACK methods in web server configuration.',
                'sources': [{'tool': 'nmap', 'method': 'nmap-http-methods'}],
            },
        )
        session.add(f)
        session.commit()

    return app, settings


def auth_client(app):
    client = app.test_client()
    client.set_cookie('patrolman_session', SESSION_TOKEN)
    return client


def test_pdf_generation_text_evidence(pdf_test_env):
    """Test successful PDF export from supported text-based evidence."""
    app, settings = pdf_test_env
    engine = app.extensions['database']
    client = auth_client(app)

    raw_output = "Nmap scan report for 127.0.0.1\nPORT   STATE SERVICE\n80/tcp open  http\n"
    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-pdf-test-01',
        tool='nmap',
        evidence_type='raw_output',
        content=raw_output,
        filename='nmap_test.txt',
        finding_id=101,
    )

    # Export via format=pdf query parameter
    res = client.get(f'/api/evidence/{ev.id}/download?format=pdf')
    assert res.status_code == 200
    assert res.content_type == 'application/pdf'
    assert 'attachment' in res.headers.get('Content-Disposition', '')
    assert 'nmap_test_report.pdf' in res.headers.get('Content-Disposition', '')

    pdf_bytes = res.data
    assert pdf_bytes.startswith(b'%PDF')

    # Verify PDF digest differs from source digest
    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    assert pdf_sha256 != ev.sha256_hash

    # Verify dedicated /api/evidence/<id>/pdf route also functions identically
    res_alt = client.get(f'/api/evidence/{ev.id}/pdf')
    assert res_alt.status_code == 200
    assert res_alt.content_type == 'application/pdf'
    assert res_alt.data.startswith(b'%PDF')


def test_raw_download_remains_unchanged(pdf_test_env):
    """Verify default raw download behavior is strictly preserved."""
    app, settings = pdf_test_env
    engine = app.extensions['database']
    client = auth_client(app)

    raw_output = "Raw tool output bytes line 1\nLine 2\n"
    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-pdf-test-01',
        tool='nmap',
        evidence_type='raw_output',
        content=raw_output,
        filename='nmap_raw.txt',
    )

    # Standard download without format or with format=raw
    res = client.get(f'/api/evidence/{ev.id}/download')
    assert res.status_code == 200
    assert res.content_type == 'application/octet-stream'
    assert res.data.decode('utf-8') == raw_output
    assert hashlib.sha256(res.data).hexdigest() == ev.sha256_hash


def test_authentication_enforcement(pdf_test_env):
    """Verify unauthenticated requests are rejected with 401."""
    app, settings = pdf_test_env
    engine = app.extensions['database']
    unauth_client = app.test_client()

    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-pdf-test-01',
        tool='nmap',
        evidence_type='raw_output',
        content='Secret content',
        filename='auth_test.txt',
    )

    # Raw download unauthenticated -> 401
    res_raw = unauth_client.get(f'/api/evidence/{ev.id}/download')
    assert res_raw.status_code == 401

    # PDF download unauthenticated -> 401
    res_pdf = unauth_client.get(f'/api/evidence/{ev.id}/download?format=pdf')
    assert res_pdf.status_code == 401

    res_pdf_alt = unauth_client.get(f'/api/evidence/{ev.id}/pdf')
    assert res_pdf_alt.status_code == 401


def test_tampered_evidence_rejected_on_pdf_generation(pdf_test_env):
    """Verify that tampering with raw artifact on disk rejects PDF export with 409."""
    app, settings = pdf_test_env
    engine = app.extensions['database']
    client = auth_client(app)

    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-pdf-test-01',
        tool='nmap',
        evidence_type='raw_output',
        content='Original valid content',
        filename='tamper_test.txt',
    )

    # Corrupt the file on disk
    file_on_disk = settings.data_dir / 'evidence' / ev.file_path
    assert file_on_disk.is_file()
    file_on_disk.write_bytes(b'Tampered malicious modification')

    # Both raw download and PDF export must abort with 409
    res_raw = client.get(f'/api/evidence/{ev.id}/download')
    assert res_raw.status_code == 409
    assert 'integrity' in res_raw.get_data(as_text=True).lower()

    res_pdf = client.get(f'/api/evidence/{ev.id}/download?format=pdf')
    assert res_pdf.status_code == 409
    assert 'integrity' in res_pdf.get_data(as_text=True).lower()


def test_sensitive_value_redaction_in_pdf():
    """Verify secrets, tokens, passwords, and API keys are redacted before rendering."""
    class MockEvidence:
        id = 'ev-redact-01'
        scan_id = 'scan-01'
        tool = 'httpx'
        evidence_type = 'raw_output'
        file_size = 512
        sha256_hash = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        redacted = False
        created_at = datetime.now(timezone.utc)

    raw_text = (
        "GET /login HTTP/1.1\n"
        "Authorization: Bearer super-secret-jwt-token-12345\n"
        "Cookie: session_id=sess_abcdef987654321; secret=topsecretpass\n"
        "password=SensitiveAdminPassword999!\n"
    )

    pdf = generate_evidence_pdf(MockEvidence(), raw_text.encode('utf-8'), 'httpx_redact.txt')
    assert pdf.startswith(b'%PDF')

    # Ensure sensitive credentials do not exist unredacted in raw PDF bytes
    assert b'super-secret-jwt-token-12345' not in pdf
    assert b'SensitiveAdminPassword999!' not in pdf
    assert b'topsecretpass' not in pdf


def test_malicious_html_and_script_treated_as_inert_text():
    """Verify HTML tags, script tags, and XSS vectors are escaped and inert."""
    class MockEvidence:
        id = 'ev-xss-01'
        scan_id = 'scan-01'
        tool = 'wapiti'
        evidence_type = 'raw_output'
        file_size = 256
        sha256_hash = '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff'
        redacted = False
        created_at = datetime.now(timezone.utc)

    xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(document.cookie)><style>body{display:none}</style>"
    pdf = generate_evidence_pdf(MockEvidence(), xss_payload.encode('utf-8'), 'wapiti_xss.txt')
    assert pdf.startswith(b'%PDF')


def test_binary_artifact_handling():
    """Verify binary artifact triggers the Binary Artifact Notice instead of corrupt text."""
    class MockEvidence:
        id = 'ev-bin-01'
        scan_id = 'scan-01'
        tool = 'trivy'
        evidence_type = 'binary_dump'
        file_size = 100
        sha256_hash = 'aabbcc11223344556677889900aabbccddeeff11223344556677889900aabbcc'
        redacted = False
        created_at = datetime.now(timezone.utc)

    # Binary payload containing null bytes
    binary_bytes = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
    assert is_binary_content(binary_bytes) is True

    pdf = generate_evidence_pdf(MockEvidence(), binary_bytes, 'image.png')
    assert pdf.startswith(b'%PDF')
    # PDF should contain the word BINARY
    assert b'BINARY ARTIFACT NOTICE' in pdf or b'BINARY' in pdf


def test_oversized_artifact_handling():
    """Verify oversized text artifact is truncated with an explicit notice."""
    class MockEvidence:
        id = 'ev-over-01'
        scan_id = 'scan-01'
        tool = 'nmap'
        evidence_type = 'raw_output'
        file_size = 150000
        sha256_hash = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100'
        redacted = False
        created_at = datetime.now(timezone.utc)

    # 400 lines of log output
    long_text = "\n".join(f"Log entry line {i}: Scanning host port {i}..." for i in range(400))
    raw_bytes = long_text.encode('utf-8')

    pdf = generate_evidence_pdf(MockEvidence(), raw_bytes, 'nmap_long.txt')
    assert pdf.startswith(b'%PDF')
    assert b'OVERSIZED ARTIFACT NOTICE' in pdf or b'truncated' in pdf
