"""Tests for Phase 4 & Phase 5: Beginner-Friendly Assessment PDF Report Generator."""
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from backend.app import create_app
from backend.config import Settings
from backend.models import AdminAccount, AdminSession, Finding, Scan, ToolExecution
from backend.auth import SESSION_COOKIE, _token_hash
from backend.services.assessment_report_pdf import generate_assessment_report_pdf

SESSION_TOKEN = 'session-token-report-32-chars-long'


@pytest.fixture
def report_app(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token='R' * 32, allowed_targets=('127.0.0.1',))
    app = create_app(settings)
    app.config['TESTING'] = True

    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)

    with Session(engine) as session:
        session.add(AdminAccount(username='analyst', password_hash=generate_password_hash('Password123!')))
        session.add(AdminSession(
            token_hash=_token_hash(SESSION_TOKEN),
            username='analyst',
            csrf_token='csrf-token-secret-32-chars-long',
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=2),
        ))

        # Seed completed scan
        scan = Scan(
            id='scan-report-001',
            target='127.0.0.1',
            profile='standard',
            state='completed',
            created_by='analyst',
            created_at=now_dt - timedelta(minutes=10),
            started_at=now_dt - timedelta(minutes=9),
            ended_at=now_dt - timedelta(minutes=1),
            configuration={
                'tools': ['nmap', 'httpx', 'whatweb', 'nuclei'],
            },
        )
        scan.findings.append(Finding(
            fingerprint='fp-test-01',
            title='Insecure HTTP Headers Detected',
            severity='medium',
            details={
                'target': 'http://127.0.0.1:80',
                'description': 'Missing Strict-Transport-Security and Content-Security-Policy response headers.',
                'impact': 'Vulnerable to clickjacking and protocol downgrade attacks.',
                'remediation': 'Configure web server to emit Strict-Transport-Security and Content-Security-Policy headers.',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'],
                'sources': [{'tool': 'httpx'}],
            },
        ))
        scan.findings.append(Finding(
            fingerprint='fp-test-02',
            title='Open Remote Access Port (Telnet/SSH)',
            severity='high',
            details={
                'target': '127.0.0.1:22',
                'description': 'SSH port 22 open on public interface.',
                'impact': 'Potential brute force entry if weak credentials exist.',
                'remediation': 'Restrict SSH access via firewall allowlists or VPN.',
                'sources': [{'tool': 'nmap'}],
            },
        ))
        scan.executions.append(ToolExecution(tool='nmap', state='completed'))
        scan.executions.append(ToolExecution(tool='httpx', state='completed'))
        scan.executions.append(ToolExecution(tool='whatweb', state='completed'))
        scan.executions.append(ToolExecution(tool='nuclei', state='skipped', error='No eligible web endpoint discovered.'))
        session.add(scan)
        session.commit()

    return app, settings


def test_pdf_report_generator_direct_bytes():
    dummy_scan = {
        'id': 'scan-direct-999',
        'target': '127.0.0.1',
        'profile': 'standard',
        'state': 'completed',
        'created_by': 'analyst',
        'created_at': '2026-10-24T00:00:00Z',
        'ended_at': '2026-10-24T00:05:00Z',
        'executions': [
            {'tool': 'nmap', 'state': 'completed'},
            {'tool': 'httpx', 'state': 'completed'},
            {'tool': 'nuclei', 'state': 'skipped', 'reason': 'Scope restriction'},
        ],
        'findings': [
            {
                'title': 'Test Vulnerability',
                'severity': 'critical',
                'details': {
                    'description': 'Critical flaw detected',
                    'impact': 'High impact test',
                    'remediation': 'Apply patch immediately',
                    'target': '127.0.0.1:443',
                    'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-9999'],
                },
            }
        ],
    }

    pdf_bytes = generate_assessment_report_pdf(dummy_scan)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2048
    # Validate PDF signature
    assert pdf_bytes.startswith(b'%PDF-')
    # Validate PDF trailer/EOF
    assert b'%%EOF' in pdf_bytes[-1024:]


def test_pdf_report_generator_empty_findings():
    dummy_scan = {
        'id': 'scan-empty-111',
        'target': '127.0.0.1',
        'profile': 'quick',
        'state': 'completed',
        'created_by': 'analyst',
        'created_at': '2026-10-24T00:00:00Z',
        'ended_at': '2026-10-24T00:01:00Z',
        'executions': [{'tool': 'nmap', 'state': 'completed'}],
        'findings': [],
    }

    pdf_bytes = generate_assessment_report_pdf(dummy_scan)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b'%PDF-')
    assert b'%%EOF' in pdf_bytes[-1024:]


def test_pdf_report_download_endpoint(report_app):
    app, _ = report_app
    client = app.test_client()
    client.set_cookie(SESSION_COOKIE, SESSION_TOKEN)

    res = client.get('/api/scans/scan-report-001/report?format=pdf')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert 'attachment' in res.headers['Content-Disposition']
    assert 'PATROLMAN_127.0.0.1_scan-rep_report.pdf' in res.headers['Content-Disposition']
    assert res.data.startswith(b'%PDF-')
    assert len(res.data) > 5000
