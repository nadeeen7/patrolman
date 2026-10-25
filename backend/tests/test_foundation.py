import pytest
from datetime import datetime, timezone
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from backend.app import create_app
from backend.config import Settings
from backend.models import Asset, Finding, Scan, ToolExecution
from backend.services.target_validation import normalize_target, validate_target, TargetError, ScopeError
from backend.services.tool_manager import inventory

TOKEN = 'test-only-token-' + 'x' * 32


@pytest.fixture
def app(tmp_path):
    application = create_app(Settings(tmp_path, TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    yield application
    application.extensions['scan_manager'].shutdown()
    application.extensions['database'].dispose()


@pytest.mark.parametrize('value,expected', [('EXAMPLE.COM.', 'example.com'), ('bücher.example', 'xn--bcher-kva.example'), ('::1', '::1'), ('127.0.0.1', '127.0.0.1')])
def test_normalization(value, expected):
    assert normalize_target(value) == expected


@pytest.mark.parametrize('value', ['', None, [], ' example.com', 'example.com\n', 'host;id', '$(id)', '--help', 'https://example.com', 'a/b', 'user@host', 'a..b', 'example.com..', 'a_b', '127.1', '2130706433', '0x7f000001', 'fe80::1%eth0', 'a' * 64 + '.com'])
def test_reject_malformed(value):
    with pytest.raises(TargetError):
        normalize_target(value)


def test_scope_rejects_before_dns():
    def resolver(_):
        pytest.fail('Unapproved hostname reached DNS')
    with pytest.raises(ScopeError):
        validate_target('child.example.com', ('example.com',), resolver=resolver)


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1'])
def test_mixed_dns_answers_fail_closed(address):
    with pytest.raises(ScopeError):
        validate_target('example.com', ('example.com',), resolver=lambda _: ('8.8.8.8', address))


@pytest.mark.parametrize('address', ['169.254.169.254', '0.0.0.0', '224.0.0.1', 'fe80::1', '::'])
def test_lab_mode_still_blocks_special_addresses(address):
    with pytest.raises(ScopeError):
        validate_target(address, (address,), allow_private=True)


def test_lab_loopback_allowed_explicitly():
    assert validate_target('127.0.0.1', ('127.0.0.1',), True).addresses == ('127.0.0.1',)


def test_empty_and_failed_dns():
    with pytest.raises(TargetError):
        validate_target('example.com', ('example.com',), resolver=lambda _: ())
    def resolver(_):
        raise OSError('private infrastructure error')
    with pytest.raises(TargetError, match='Target resolution failed'):
        validate_target('example.com', ('example.com',), resolver=resolver)


def test_public_dns_normalization_and_dedup():
    result = validate_target('EXAMPLE.COM', ('example.com',), resolver=lambda _: ('8.8.8.8', '8.8.8.8'))
    assert result.host == 'example.com'
    assert result.addresses == ('8.8.8.8',)


def test_startup_requires_token(tmp_path):
    # In normal web mode, token-free startup succeeds
    normal_app = create_app(Settings(tmp_path, ''))
    assert normal_app is not None
    # In explicit require_api_token mode, missing token raises ValueError
    with pytest.raises(ValueError):
        create_app(Settings(tmp_path, '', require_api_token=True))
    with pytest.raises(ValueError):
        create_app(Settings(tmp_path, 'REPLACE_WITH_A_RANDOM_TOKEN_OF_AT_LEAST_32_CHARACTERS'))


def test_health_and_protected_tools(app):
    client = app.test_client()
    health = client.get('/api/health')
    assert health.status_code == 200
    assert health.json['data']['scanning_enabled'] is True
    assert client.get('/api/tools').status_code == 401
    assert client.get('/api/tools', headers={'Authorization': 'Bearer wrong'}).status_code == 401
    response = client.get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200
    assert len(response.json['data']) == 9
    # Whether a scanner is installed depends on the machine, so assert the
    # response contract instead of an environment-specific outcome.
    for item in response.json['data']:
        assert {'name', 'status', 'integration_ready', 'version', 'reason'} <= set(item)
        assert item['status'] in {'ready', 'unverified', 'missing', 'blocked', 'disabled', 'configuration_required', 'execution_blocked', 'unknown'}, item
        assert item['integration_ready'] is (item['status'] == 'ready')
        assert 'executable' not in item, 'Executable paths must never reach the API.'


def test_dashboard_reports_database_execution_coverage(app):
    engine = app.extensions['database']
    started = datetime.now(timezone.utc)
    with Session(engine) as session:
        for state, has_started in (
            ('completed', True),
            ('failed', True),
            ('timed_out', True),
            ('skipped', False),
            ('configuration_required', False),
            ('queued', False),
        ):
            scan = Scan(target='127.0.0.1', profile='quick', state='completed')
            scan.executions.append(ToolExecution(
                tool='nmap',
                state=state,
                started_at=started if has_started else None,
            ))
            session.add(scan)
        session.commit()

    response = app.test_client().get('/api/dashboard', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200
    assert response.json['data']['coverage'] == {
        'selected': 6,
        'executed': 3,
        'successful': 1,
        'failed': 1,
        'timed_out': 1,
        'skipped': 1,
        'blocked': 0,
        'unavailable': 0,
        'configuration_required': 1,
        'queued': 1,
        'running': 0,
        'cancelled': 0,
    }


def test_tools_require_current_version_workflow_evidence(app, monkeypatch):
    engine = app.extensions['database']
    started = datetime.now(timezone.utc)
    with Session(engine) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='failed', configuration={
            'tool_metadata': {'nmap': {'version': 'Nmap 7.80'}},
        })
        scan.executions.append(ToolExecution(
            tool='nmap', state='failed', started_at=started, ended_at=started,
        ))
        session.add(scan)
        session.commit()

    monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
        'name': 'nmap', 'status': 'ready', 'state': 'READY', 'integration_ready': True,
        'version': 'Nmap 7.80', 'reason': 'Version verified.', 'executable': 'private-path',
    }])
    response = app.test_client().get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200
    item = response.json['data'][0]
    assert item['status'] == 'unverified'
    assert item['state'] == 'UNVERIFIED'
    assert item['integration_ready'] is False
    assert item['workflow_verification']['status'] == 'failed'
    assert item['workflow_verification']['last_state'] == 'failed'
    assert 'executable' not in item


def test_tools_report_verified_only_for_successful_matching_version(app, monkeypatch):
    engine = app.extensions['database']
    started = datetime.now(timezone.utc)
    with Session(engine) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'nmap': {'version': 'Nmap 7.80'}},
        })
        scan.executions.append(ToolExecution(
            tool='nmap', state='completed', started_at=started, ended_at=started,
        ))
        session.add(scan)
        session.commit()

    monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
        'name': 'nmap', 'status': 'ready', 'state': 'READY', 'integration_ready': True,
        'version': 'Nmap 7.80', 'reason': 'Version verified.',
    }])
    response = app.test_client().get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
    item = response.json['data'][0]
    assert item['status'] == 'ready'
    assert item['integration_ready'] is True
    assert item['workflow_verification']['status'] == 'verified'


def test_validation_api(app):
    client = app.test_client()
    headers = {'Authorization': 'Bearer ' + TOKEN}
    url = '/api/targets/validate'
    assert client.post(url, json={'target': '127.0.0.1'}).status_code == 401
    assert client.post(url, json={'target': '127.0.0.1'}, headers=headers).status_code == 200
    assert client.post(url, json={'target': 'example.com'}, headers=headers).status_code == 403
    assert client.post(url, json={'target': ';id'}, headers=headers).status_code == 400
    assert client.post(url, json=['127.0.0.1'], headers=headers).status_code == 400
    assert client.post(url, json={'target': '127.0.0.1', 'args': '--script all'}, headers=headers).status_code == 400
    assert client.post(url, data='{broken', content_type='application/json', headers=headers).status_code == 400
    assert client.post('/api/scans', json={}, headers=headers).status_code == 400


def test_missing_and_ambiguous_executables(monkeypatch):
    monkeypatch.setattr('backend.services.tool_manager.find_argv', lambda _: None)
    monkeypatch.setattr('backend.services.tool_manager.local_candidate', lambda _: None)
    for name in ('HTTPX', 'WHATWEB', 'NUCLEI', 'GITLEAKS', 'TRIVY', 'SUBFINDER'):
        monkeypatch.delenv(f'AVA_{name}_PATH', raising=False)
    # When executable is missing the status should be 'missing' or 'blocked' (never 'ready').
    assert all(item['status'] in {'missing', 'blocked', 'disabled'} for item in inventory())
    monkeypatch.setattr('backend.services.tool_manager.find_argv', lambda _: '/some/executable')
    # When a non-disabled executable is found but unverified the status must be 'unverified'.
    assert all(
        (item['status'] in {'unverified', 'configuration_required'} and not item['integration_ready'])
        or item['status'] == 'disabled'
        for item in inventory()
    )


def test_database_persistence_relationships_and_uniqueness(app):
    engine = app.extensions['database']
    with Session(engine) as session:
        scan = Scan(target='127.0.0.1', profile='quick')
        scan.assets.append(Asset(address='127.0.0.1', kind='ip'))
        scan.executions.append(ToolExecution(tool='nmap', state='unavailable'))
        scan.findings.append(Finding(fingerprint='abc', title='Synthetic test record'))
        session.add(scan)
        session.commit()
        scan_id = scan.id
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.target == '127.0.0.1' and len(scan.assets) == 1
        assert len(scan.executions) == 1 and len(scan.findings) == 1
        session.add(Finding(scan_id=scan_id, fingerprint='abc', title='duplicate'))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.delete(session.get(Scan, scan_id))
        session.commit()
        assert session.scalar(select(Asset)) is None
        assert session.scalar(select(Finding)) is None
        assert session.scalar(select(ToolExecution)) is None
    with engine.connect() as connection:
        assert connection.scalar(text('PRAGMA foreign_keys')) == 1
        assert connection.scalar(text('PRAGMA journal_mode')) == 'wal'


def test_data_survives_app_recreation(tmp_path):
    settings = Settings(tmp_path, TOKEN)
    first = create_app(settings)
    with Session(first.extensions['database']) as session:
        session.add(Scan(target='127.0.0.1', profile='quick'))
        session.commit()
    first.extensions['database'].dispose()
    second = create_app(settings)
    with Session(second.extensions['database']) as session:
        assert session.scalar(select(Scan)).target == '127.0.0.1'
    second.extensions['database'].dispose()
