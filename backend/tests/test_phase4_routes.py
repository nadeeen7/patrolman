"""Integration tests for Phase 4: Audit Trail and Evidence Locker routes."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import Scan
from backend.auth import SESSION_COOKIE, AdminSession, _token_hash
from backend.services.audit_service import log_event
from backend.services.evidence_service import store_evidence

TOKEN = 'B' * 32
SESSION_TOKEN = 'test-session-secret-token-32-chars-long'
CSRF_TOKEN = 'test-csrf-secret-token-32-chars-long'


@pytest.fixture
def phase4_env(tmp_path):
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
        session.commit()

    return app, settings


def auth_client(app):
    client = app.test_client()
    client.set_cookie(SESSION_COOKIE, SESSION_TOKEN)
    return client


def test_audit_events_endpoint_unauthenticated(phase4_env):
    app, _ = phase4_env
    client = app.test_client()
    res = client.get('/api/audit-events')
    assert res.status_code == 401


def test_audit_events_endpoint_authenticated_and_filters(phase4_env):
    app, settings = phase4_env
    engine = app.extensions['database']
    client = auth_client(app)

    # Log some events
    log_event(engine, event_type='scan_dispatched', actor='tester', details={'target': '127.0.0.1'})
    log_event(engine, event_type='auth_login', actor='admin', details={'status': 'ok'})

    res = client.get('/api/audit-events')
    assert res.status_code == 200
    json_data = res.get_json()
    assert 'data' in json_data
    assert 'meta' in json_data
    assert json_data['meta']['total'] >= 2

    # Filter by event_type
    res_filtered = client.get('/api/audit-events?event_type=scan_dispatched')
    assert res_filtered.status_code == 200
    filtered_data = res_filtered.get_json()['data']
    assert all(e['event_type'] == 'scan_dispatched' for e in filtered_data)


def test_evidence_endpoint_unauthenticated(phase4_env):
    app, _ = phase4_env
    client = app.test_client()
    res = client.get('/api/evidence')
    assert res.status_code == 401


def test_evidence_workflow_and_download(phase4_env):
    app, settings = phase4_env
    engine = app.extensions['database']
    client = auth_client(app)

    # Seed a scan and evidence
    with Session(engine) as session:
        scan = Scan(id='scan-42', target='127.0.0.1', profile='quick', configuration={})
        session.add(scan)
        session.commit()

    sample_content = b"Simulated nmap port scan result: port 80 open"
    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-42',
        tool='nmap',
        evidence_type='raw_output',
        content=sample_content,
        filename='nmap_output.txt',
    )

    # List evidence
    res = client.get('/api/evidence?scan_id=scan-42')
    assert res.status_code == 200
    items = res.get_json()['data']
    assert len(items) == 1
    assert items[0]['id'] == ev.id
    assert items[0]['tool'] == 'nmap'
    assert items[0]['sha256_hash'] == ev.sha256_hash

    # Get evidence detail
    res_detail = client.get(f'/api/evidence/{ev.id}')
    assert res_detail.status_code == 200
    detail = res_detail.get_json()['data']
    assert detail['id'] == ev.id
    assert detail['file_size'] == len(sample_content)

    # Download evidence
    res_download = client.get(f'/api/evidence/{ev.id}/download')
    assert res_download.status_code == 200
    assert res_download.data == sample_content

    # Downloading logs an audit event
    res_audit = client.get('/api/audit-events?event_type=evidence_downloaded')
    assert res_audit.status_code == 200
    audit_items = res_audit.get_json()['data']
    assert any(a['resource_id'] == ev.id for a in audit_items)


def test_evidence_not_found(phase4_env):
    app, _ = phase4_env
    client = auth_client(app)
    res = client.get('/api/evidence/non-existent-id')
    assert res.status_code == 404
    res_dl = client.get('/api/evidence/non-existent-id/download')
    assert res_dl.status_code == 404


def test_evidence_missing_file_returns_404_not_500(phase4_env):
    """Finding 2: Existing evidence record with a missing file artifact returns 404, never uncaught 500."""
    app, settings = phase4_env
    engine = app.extensions['database']
    client = auth_client(app)

    with Session(engine) as session:
        scan = Scan(id='scan-missing-art', target='127.0.0.1', profile='quick', configuration={})
        session.add(scan)
        session.commit()

    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-missing-art',
        tool='httpx',
        evidence_type='raw_output',
        content=b"content that will disappear",
    )

    # Delete the artifact file from disk
    root = settings.data_dir / 'evidence'
    file_path = root / ev.file_path
    assert file_path.is_file()
    file_path.unlink()

    # Detail request must return 404 (not 500)
    res = client.get(f'/api/evidence/{ev.id}')
    assert res.status_code == 404
    err_body = res.get_json()
    assert 'missing on disk' in err_body['error']['message']
    assert str(settings.data_dir) not in res.text

    # Download request must also return 404 (not 500)
    res_dl = client.get(f'/api/evidence/{ev.id}/download')
    assert res_dl.status_code == 404
    assert 'missing on disk' in res_dl.get_json()['error']['message']


def test_tampered_evidence_returns_409_and_audits(phase4_env):
    """Finding 3: Cryptographic integrity failure rejects operation and records audit event."""
    app, settings = phase4_env
    engine = app.extensions['database']
    client = auth_client(app)

    with Session(engine) as session:
        scan = Scan(id='scan-tamper', target='127.0.0.1', profile='quick', configuration={})
        session.add(scan)
        session.commit()

    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-tamper',
        tool='nmap',
        evidence_type='raw_output',
        content=b"authentic report data",
    )

    # Tamper with file
    root = settings.data_dir / 'evidence'
    file_path = root / ev.file_path
    file_path.write_bytes(b"tampered evil data")

    # Detail request fails closed with 409
    res = client.get(f'/api/evidence/{ev.id}')
    assert res.status_code == 409

    # Verify audit event was logged
    audit_res = client.get('/api/audit-events?event_type=evidence_integrity_failure')
    assert audit_res.status_code == 200
    events = audit_res.get_json()['data']
    assert any(e['resource_id'] == ev.id for e in events)


def test_scan_deletion_preserves_evidence_forensically(phase4_env):
    """Finding 5: Scan deletion preserves evidence records and files under forensic retention."""
    app, settings = phase4_env
    engine = app.extensions['database']
    client = auth_client(app)

    with Session(engine) as session:
        scan = Scan(id='scan-to-delete', target='127.0.0.1', profile='quick', state='completed', configuration={})
        session.add(scan)
        session.commit()

    ev = store_evidence(
        target=engine,
        data_dir=settings.data_dir,
        scan_id='scan-to-delete',
        tool='nuclei',
        evidence_type='raw_output',
        content=b"retained forensic evidence content",
    )

    # Delete scan via authenticated API with explicit confirmation header and CSRF token
    del_res = client.delete(
        '/api/scans/scan-to-delete',
        headers={'X-Confirm-Delete': 'scan-to-delete', 'X-CSRF-Token': CSRF_TOKEN},
    )
    assert del_res.status_code == 200

    # Scan itself is deleted
    assert client.get('/api/scans/scan-to-delete').status_code == 404

    # Evidence record is preserved and queryable by scan_id
    ev_list = client.get('/api/evidence?scan_id=scan-to-delete')
    assert ev_list.status_code == 200
    items = ev_list.get_json()['data']
    assert len(items) == 1
    assert items[0]['id'] == ev.id

    # Evidence detail and download continue to work and verify SHA-256 integrity
    detail_res = client.get(f'/api/evidence/{ev.id}')
    assert detail_res.status_code == 200
    assert detail_res.get_json()['data']['scan_id'] == 'scan-to-delete'

    download_res = client.get(f'/api/evidence/{ev.id}/download')
    assert download_res.status_code == 200
    assert download_res.data == b"retained forensic evidence content"
