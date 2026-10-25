import json
import time
from threading import Event
from datetime import datetime, timezone, timedelta
from pathlib import Path
from contextlib import contextmanager
import pytest
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, Scan, TargetAuditEvent, ToolExecution
from backend.services.process_runner import ProcessResult
from backend.services.scan_service import TERMINAL

TOKEN = 'phase3-test-token-' + 'x'*32
HEADERS = {'Authorization': 'Bearer ' + TOKEN}


@pytest.fixture
def app(tmp_path, monkeypatch):
    settings = Settings(
        data_dir=tmp_path,
        api_token=TOKEN,
        allowed_targets=('127.0.0.1', 'example.local', 'api.example.local'),
        allow_private_targets=True,
        require_authorized_target=True,
    )
    application = create_app(settings)
    application.config['TESTING'] = True
    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    yield application
    application.extensions['scan_manager'].shutdown()
    application.extensions['database'].dispose()


def register_target(engine, **kwargs):
    defaults = {
        'name': 'Corporate Portal Target',
        'target_type': 'organization',
        'owner_organization': 'ACME Corp',
        'scope_domains': ['127.0.0.1', 'example.local'],
        'explicit_subdomains': ['api.example.local'],
        'excluded_scope': ['/admin/secret'],
        'permitted_methods': ['port_scan', 'web_service_discovery', 'tls_audit', 'vulnerability_check'],
        'prohibited_methods': ['dos', 'exploit', 'credential_attack'],
        'rate_limit_rps': 10,
        'valid_from': datetime.now(timezone.utc) - timedelta(days=1),
        'valid_to': datetime.now(timezone.utc) + timedelta(days=30),
        'evidence_reference': 'SOW-2026-XYZ',
        'status': 'active',
        'created_by': 'admin',
        'updated_by': 'admin',
    }
    defaults.update(kwargs)
    with Session(engine) as session:
        t = AuthorizedTarget(**defaults)
        session.add(t)
        session.commit()
        return t.id


def test_create_scan_with_valid_target_id(app):
    client = app.test_client()
    engine = app.extensions['database']
    target_id = register_target(engine)

    payload = {
        'target': '127.0.0.1',
        'target_id': target_id,
        'profile': 'quick',
        'tools': ['nmap', 'httpx'],
        'authorized': True,
    }
    resp = client.post(
        '/api/scans',
        json=payload,
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase3-idempotency-key-01'}),
    )
    assert resp.status_code == 202
    data = resp.json['data']
    assert data['target'] == '127.0.0.1'
    assert data['configuration']['authorized_target_id'] == target_id
    assert data['configuration']['authorized_target_name'] == 'Corporate Portal Target'

    # Verify audit event recorded
    with Session(engine) as session:
        audits = session.scalars(
            select(TargetAuditEvent).where(TargetAuditEvent.target_id == target_id)
        ).all()
        assert len(audits) >= 1
        assert any(a.event_type == 'scan_dispatched' for a in audits)


def test_create_scan_rejects_nonexistent_target_id(app):
    client = app.test_client()
    payload = {
        'target': '127.0.0.1',
        'target_id': 'non-existent-target-id-999',
        'profile': 'quick',
        'tools': ['nmap', 'httpx'],
        'authorized': True,
    }
    resp = client.post(
        '/api/scans',
        json=payload,
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase3-idempotency-key-02'}),
    )
    assert resp.status_code == 404
    assert 'not found' in resp.json['error']['message'].lower()


def test_create_scan_rejects_inactive_or_expired_target(app):
    client = app.test_client()
    engine = app.extensions['database']
    expired_id = register_target(
        engine,
        name='Expired Target',
        valid_from=datetime.now(timezone.utc) - timedelta(days=20),
        valid_to=datetime.now(timezone.utc) - timedelta(days=5),
    )
    payload = {
        'target': '127.0.0.1',
        'target_id': expired_id,
        'profile': 'quick',
        'tools': ['nmap', 'httpx'],
        'authorized': True,
    }
    resp = client.post(
        '/api/scans',
        json=payload,
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase3-idempotency-key-03'}),
    )
    assert resp.status_code == 403
    err_msg = resp.json['error']['message'].lower()
    assert 'not active' in err_msg or 'expired' in err_msg


def test_create_scan_rejects_out_of_scope_host_for_target_id(app):
    client = app.test_client()
    engine = app.extensions['database']
    # Target only covers example.local
    target_id = register_target(engine, scope_domains=['example.local'], explicit_subdomains=[])
    payload = {
        'target': '127.0.0.1',
        'target_id': target_id,
        'profile': 'quick',
        'tools': ['nmap', 'httpx'],
        'authorized': True,
    }
    resp = client.post(
        '/api/scans',
        json=payload,
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase3-idempotency-key-04'}),
    )
    assert resp.status_code == 403
    assert 'not covered' in resp.json['error']['message'].lower()


def test_create_scan_rejects_prohibited_methods_for_target_id(app):
    client = app.test_client()
    engine = app.extensions['database']
    # Prohibit vulnerability_check (maps to nuclei in standard profile)
    target_id = register_target(engine, prohibited_methods=['vulnerability_check'])
    payload = {
        'target': '127.0.0.1',
        'target_id': target_id,
        'profile': 'standard',
        'tools': ['nmap', 'httpx', 'nuclei'],
        'authorized': True,
    }
    resp = client.post(
        '/api/scans',
        json=payload,
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase3-idempotency-key-05'}),
    )
    assert resp.status_code == 403
    assert 'prohibited' in resp.json['error']['message'].lower()


@pytest.mark.parametrize('change', ['scope', 'methods'])
def test_queued_scan_is_blocked_after_scope_or_method_change(app, monkeypatch, change):
    client = app.test_client()
    engine = app.extensions['database']
    target_id = register_target(engine)
    manager = app.extensions['scan_manager']
    monkeypatch.setattr(manager, 'submit', lambda _scan_id: None)
    invoked = []
    monkeypatch.setattr('backend.services.scan_service.run', lambda *args, **kwargs: invoked.append(args))

    response = client.post(
        '/api/scans',
        json={
            'target': '127.0.0.1',
            'target_id': target_id,
            'profile': 'quick',
            'tools': ['nmap', 'httpx'],
            'authorized': True,
        },
        headers=dict(HEADERS, **{'Idempotency-Key': f'phase5-queued-{change}-0001'}),
    )
    assert response.status_code == 202
    scan_id = response.json['data']['id']

    with Session(engine) as session:
        target = session.get(AuthorizedTarget, target_id)
        if change == 'scope':
            target.scope_domains = ['other.example.local']
        else:
            target.permitted_methods = ['tls_audit']
        session.commit()

    manager.work(scan_id, Event())
    assert invoked == []
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.state == 'failed'
        audits = session.scalars(
            select(TargetAuditEvent).where(
                TargetAuditEvent.target_id == target_id,
                TargetAuditEvent.event_type == 'authorization_revalidation_failed',
            )
        ).all()
        assert audits


def test_authorization_is_rechecked_after_rate_limit_wait(app, monkeypatch):
    client = app.test_client()
    engine = app.extensions['database']
    target_id = register_target(engine)
    manager = app.extensions['scan_manager']
    monkeypatch.setattr(manager, 'submit', lambda _scan_id: None)
    invoked = []
    monkeypatch.setattr('backend.services.scan_service.run', lambda *args, **kwargs: invoked.append(args))

    response = client.post(
        '/api/scans',
        json={
            'target': '127.0.0.1',
            'target_id': target_id,
            'profile': 'quick',
            'tools': ['nmap'],
            'authorized': True,
        },
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase5-rate-wait-0000001'}),
    )
    assert response.status_code == 202
    scan_id = response.json['data']['id']

    @contextmanager
    def authorization_changes_during_wait(**_kwargs):
        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            target.permitted_methods = ['tls_audit']
            session.commit()
        yield 1

    monkeypatch.setattr(manager.rate_coordinator, 'claim', authorization_changes_during_wait)
    manager.work(scan_id, Event())
    assert invoked == []
    with Session(engine) as session:
        executions = session.scalars(
            select(ToolExecution).where(ToolExecution.scan_id == scan_id)
        ).all()
        assert executions[0].state == 'blocked'
        assert any(
            event.event_type == 'authorization_revalidation_failed'
            for event in session.scalars(
                select(TargetAuditEvent).where(TargetAuditEvent.target_id == target_id)
            ).all()
        )


def test_running_assessment_blocks_subsequent_tools_when_target_authorization_revoked(app, monkeypatch):
    client = app.test_client()
    engine = app.extensions['database']
    target_id = register_target(
        engine,
        permitted_methods=['port_scan', 'web_service_discovery'],
    )
    manager = app.extensions['scan_manager']
    monkeypatch.setattr(manager, 'submit', lambda _scan_id: None)

    invoked_tools = []

    def mock_run(command, *args, **kwargs):
        cmd_str = ' '.join(str(c) for c in command)
        invoked_tools.append(cmd_str)
        # While tool 1 (nmap) is finishing, revoke target authorization!
        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            target.status = 'revoked'
            session.commit()
        # Return valid Nmap XML output
        xml_out = '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
        return ProcessResult(
            state='completed',
            stdout=xml_out,
            stderr='',
            exit_code=0,
        )

    monkeypatch.setattr('backend.services.scan_service.run', mock_run)
    initial_capacity = manager.capacity._value

    response = client.post(
        '/api/scans',
        json={
            'target': '127.0.0.1',
            'target_id': target_id,
            'profile': 'quick',
            'tools': ['nmap', 'httpx'],
            'authorized': True,
        },
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase5-mid-execution-revoke-001'}),
    )
    assert response.status_code == 202
    scan_id = response.json['data']['id']

    cancel_event = Event()
    manager.events[scan_id] = cancel_event

    manager.work(scan_id, cancel_event)

    # Tool 1 (nmap) was invoked, but Tool 2 (httpx) was NOT executed by process runner
    assert len(invoked_tools) == 1
    assert 'nmap' in invoked_tools[0]

    # Verify execution records in database
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.state in ('completed_with_errors', 'failed')
        executions = {e.tool: e for e in scan.executions}
        assert executions['nmap'].state == 'completed'
        assert executions['httpx'].state == 'blocked'
        assert 'Authorization invalidated' in executions['httpx'].error

        # Verify audit failure recorded
        audits = session.scalars(
            select(TargetAuditEvent).where(
                TargetAuditEvent.target_id == target_id,
                TargetAuditEvent.event_type == 'authorization_revalidation_failed',
            )
        ).all()
        assert audits

    # Verify cancellation and scan manager resources released
    assert scan_id not in manager.events
    assert manager.capacity._value == initial_capacity


def test_target_deactivation_cancels_scans_and_releases_rate_limiter(app, monkeypatch):
    client = app.test_client()
    engine = app.extensions['database']
    target_id = register_target(engine)
    manager = app.extensions['scan_manager']
    monkeypatch.setattr(manager, 'submit', lambda _scan_id: None)

    response = client.post(
        '/api/scans',
        json={
            'target': '127.0.0.1',
            'target_id': target_id,
            'profile': 'quick',
            'tools': ['nmap', 'httpx'],
            'authorized': True,
        },
        headers=dict(HEADERS, **{'Idempotency-Key': 'phase5-cancel-target-001'}),
    )
    assert response.status_code == 202
    scan_id = response.json['data']['id']

    cancel_event = Event()
    manager.events[scan_id] = cancel_event

    # Call cancel_target_scans (as done when target is deactivated)
    manager.cancel_target_scans(target_id, reason='Target deactivated for test')
    manager.rate_coordinator.update_target_capacity(target_id, 0)

    # Verify cancellation event was set
    assert cancel_event.is_set()

    # Rate coordinator capacity has no active claims
    assert manager.rate_coordinator.get_allocated_units(target_id) == 0

    # Running work with cancelled event aborts without invoking tools
    invoked = []
    monkeypatch.setattr('backend.services.scan_service.run', lambda *args, **kwargs: invoked.append(args))
    manager.work(scan_id, cancel_event)
    assert invoked == []

    # Resources are cleaned up
    assert scan_id not in manager.events
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.state == 'cancelled'
        for ex in scan.executions:
            assert ex.state == 'cancelled'


