"""Security tests for Phase 2: Complete User Data Isolation."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from backend.app import create_app
from backend.config import Settings
from backend.models import AdminAccount, AdminSession, Finding, Scan, ToolExecution
from backend.auth import SESSION_COOKIE, _token_hash
from backend.services.evidence_service import store_evidence

SESSION_ALICE = 'session-token-alice-32-chars-long'
SESSION_BOB = 'session-token-bob---32-chars-long'
CSRF_ALICE = 'csrf-token-alice----32-chars-long'
CSRF_BOB = 'csrf-token-bob------32-chars-long'


@pytest.fixture
def multi_user_app(tmp_path):
    settings = Settings(data_dir=tmp_path, api_token='T' * 32, allowed_targets=('127.0.0.1',))
    app = create_app(settings)
    app.config['TESTING'] = True

    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)

    with Session(engine) as session:
        # Create Alice account & session
        session.add(AdminAccount(username='alice', password_hash=generate_password_hash('Password123!')))
        session.add(AdminSession(
            token_hash=_token_hash(SESSION_ALICE),
            username='alice',
            csrf_token=CSRF_ALICE,
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=2),
        ))

        # Create Bob account & session
        session.add(AdminAccount(username='bob', password_hash=generate_password_hash('Password123!')))
        session.add(AdminSession(
            token_hash=_token_hash(SESSION_BOB),
            username='bob',
            csrf_token=CSRF_BOB,
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=2),
        ))

        # Create Alice's scan with findings and execution
        alice_scan = Scan(
            id='alice-scan-001',
            target='127.0.0.1',
            profile='quick',
            state='completed',
            created_by='alice',
            configuration={'tools': ['nmap']},
        )
        alice_scan.findings.append(Finding(
            fingerprint='fp-alice-1',
            title='Alice Sensitive Vulnerability',
            severity='high',
            details={'target': '127.0.0.1:8080', 'description': 'Sensitive secret exposed on Alice host'},
        ))
        alice_scan.executions.append(ToolExecution(tool='nmap', state='completed'))
        session.add(alice_scan)

        # Create Bob's scan with findings and execution
        bob_scan = Scan(
            id='bob-scan-002',
            target='127.0.0.1',
            profile='standard',
            state='completed',
            created_by='bob',
            configuration={'tools': ['httpx']},
        )
        bob_scan.findings.append(Finding(
            fingerprint='fp-bob-1',
            title='Bob Information Notice',
            severity='low',
            details={'target': '127.0.0.1:80', 'description': 'Standard web banner'},
        ))
        bob_scan.executions.append(ToolExecution(tool='httpx', state='completed'))
        session.add(bob_scan)

        session.commit()

    # Store separate evidence items
    store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='alice-scan-001',
        tool='nmap',
        evidence_type='raw_output',
        content=b'Alice private nmap evidence',
        filename='alice_nmap.txt',
        created_by='alice',
    )

    store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='bob-scan-002',
        tool='httpx',
        evidence_type='raw_output',
        content=b'Bob public httpx evidence',
        filename='bob_httpx.txt',
        created_by='bob',
    )

    return app, settings


def client_for(app, token):
    client = app.test_client()
    client.set_cookie(SESSION_COOKIE, token)
    return client


def test_user_scans_listing_isolation(multi_user_app):
    app, _ = multi_user_app
    alice_client = client_for(app, SESSION_ALICE)
    bob_client = client_for(app, SESSION_BOB)

    # Alice queries scans
    res_a = alice_client.get('/api/scans')
    assert res_a.status_code == 200
    scans_a = res_a.get_json()['data']
    assert len(scans_a) == 1
    assert scans_a[0]['id'] == 'alice-scan-001'

    # Bob queries scans
    res_b = bob_client.get('/api/scans')
    assert res_b.status_code == 200
    scans_b = res_b.get_json()['data']
    assert len(scans_b) == 1
    assert scans_b[0]['id'] == 'bob-scan-002'


def test_user_cross_access_scan_detail_rejected(multi_user_app):
    app, _ = multi_user_app
    bob_client = client_for(app, SESSION_BOB)

    # Bob attempts to view Alice's scan directly by ID
    res = bob_client.get('/api/scans/alice-scan-001')
    assert res.status_code == 404

    # Bob attempts to view Alice's findings directly by ID
    res_f = bob_client.get('/api/scans/alice-scan-001/findings')
    assert res_f.status_code == 404

    # Bob attempts to view Alice's report directly by ID
    res_r = bob_client.get('/api/scans/alice-scan-001/report?format=html')
    assert res_r.status_code == 404

    # Bob attempts to cancel Alice's scan
    res_c = bob_client.post(
        '/api/scans/alice-scan-001/cancel',
        headers={'X-CSRF-Token': CSRF_BOB},
    )
    assert res_c.status_code == 404

    # Bob attempts to delete Alice's scan
    res_d = bob_client.delete(
        '/api/scans/alice-scan-001',
        headers={'X-CSRF-Token': CSRF_BOB, 'X-Confirm-Delete': 'alice-scan-001'},
    )
    assert res_d.status_code == 404


def test_dashboard_statistics_scoped_per_user(multi_user_app):
    app, _ = multi_user_app
    alice_client = client_for(app, SESSION_ALICE)
    bob_client = client_for(app, SESSION_BOB)

    # Alice dashboard
    res_a = alice_client.get('/api/dashboard')
    assert res_a.status_code == 200
    data_a = res_a.get_json()['data']
    assert data_a['total_scans'] == 1
    assert data_a['total_findings'] == 1
    assert data_a['severities']['high'] == 1
    assert data_a['severities']['low'] == 0

    # Bob dashboard
    res_b = bob_client.get('/api/dashboard')
    assert res_b.status_code == 200
    data_b = res_b.get_json()['data']
    assert data_b['total_scans'] == 1
    assert data_b['total_findings'] == 1
    assert data_b['severities']['high'] == 0
    assert data_b['severities']['low'] == 1


def test_evidence_scoping_and_cross_download_rejected(multi_user_app):
    app, _ = multi_user_app
    alice_client = client_for(app, SESSION_ALICE)
    bob_client = client_for(app, SESSION_BOB)

    # Alice lists evidence
    res_a = alice_client.get('/api/evidence')
    assert res_a.status_code == 200
    items_a = res_a.get_json()['data']
    assert len(items_a) == 1
    alice_ev_id = items_a[0]['id']
    assert items_a[0]['scan_id'] == 'alice-scan-001'

    # Bob lists evidence
    res_b = bob_client.get('/api/evidence')
    assert res_b.status_code == 200
    items_b = res_b.get_json()['data']
    assert len(items_b) == 1
    assert items_b[0]['scan_id'] == 'bob-scan-002'

    # Bob attempts to get detail of Alice's evidence
    res_detail = bob_client.get(f'/api/evidence/{alice_ev_id}')
    assert res_detail.status_code == 404

    # Bob attempts to download Alice's evidence (raw)
    res_dl = bob_client.get(f'/api/evidence/{alice_ev_id}/download')
    assert res_dl.status_code == 404

    # Bob attempts to preview Alice's evidence (pdf)
    res_prev = bob_client.get(f'/api/evidence/{alice_ev_id}/preview')
    assert res_prev.status_code == 404


def test_empty_user_receives_clean_empty_state(multi_user_app):
    app, _ = multi_user_app
    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    session_charlie = 'session-charlie-32-chars-long'

    # Charlie signs up with 0 scans
    with Session(engine) as session:
        session.add(AdminAccount(username='charlie', password_hash=generate_password_hash('Password123!')))
        session.add(AdminSession(
            token_hash=_token_hash(session_charlie),
            username='charlie',
            csrf_token='csrf-charlie',
            created_at=now_dt,
            expires_at=now_dt + timedelta(hours=2),
        ))
        session.commit()

    charlie_client = client_for(app, session_charlie)

    # Dashboard shows 0 totals
    res_dash = charlie_client.get('/api/dashboard')
    assert res_dash.status_code == 200
    data = res_dash.get_json()['data']
    assert data['total_scans'] == 0
    assert data['total_findings'] == 0
    assert data['recent'] == []

    # Scans listing is empty
    res_scans = charlie_client.get('/api/scans')
    assert res_scans.status_code == 200
    assert res_scans.get_json()['data'] == []

    # Evidence listing is empty
    res_ev = charlie_client.get('/api/evidence')
    assert res_ev.status_code == 200
    assert res_ev.get_json()['data'] == []
