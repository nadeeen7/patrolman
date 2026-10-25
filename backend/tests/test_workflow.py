import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy.orm import Session
from sqlalchemy import select
from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, Scan, Finding, ToolExecution
from backend.services.process_runner import ProcessResult
from backend.services.reports import LONGEST_REPORT_NAME, report_directory, write_reports
from backend.services.scan_service import TERMINAL
from backend.tests.test_execution import NMAP, FIXTURES

TOKEN = 'workflow-test-token-' + 'z'*32
HEADERS = {'Authorization': 'Bearer '+TOKEN}


def register_synthetic_target(engine, host='127.0.0.1', methods=None, **kwargs):
    now = datetime.now(timezone.utc)
    defaults = {
        'name': 'Loopback Synthetic Target',
        'target_type': 'internal_system',
        'owner_organization': 'Test Harness',
        'scope_domains': [host],
        'explicit_subdomains': [],
        'excluded_scope': [],
        'permitted_methods': ['port_scan', 'web_service_discovery', 'vulnerability_check'] if methods is None else list(methods),
        'prohibited_methods': ['dos', 'exploit'],
        'rate_limit_rps': 10,
        'valid_from': now - timedelta(days=1),
        'valid_to': now + timedelta(days=30),
        'evidence_reference': 'WORKFLOW-AUTH-2026',
        'status': 'active',
        'created_by': 'admin',
        'updated_by': 'admin',
    }
    defaults.update(kwargs)
    with Session(engine) as session:
        target = AuthorizedTarget(**defaults)
        session.add(target)
        session.commit()
        return target.id


@pytest.fixture
def app(tmp_path, monkeypatch):
    application = create_app(Settings(tmp_path, TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    register_synthetic_target(application.extensions['database'])
    yield application
    application.extensions['scan_manager'].shutdown()
    application.extensions['database'].dispose()


def create(client, **overrides):
    payload = {'target':'127.0.0.1','profile':'quick','tools':['nmap','httpx','whatweb'],'authorized':True}
    payload.update(overrides)
    return client.post('/api/scans', json=payload, headers=dict(HEADERS, **{'Idempotency-Key':'test-idempotency-0001'}))


def finish(client, scan_id, timeout_seconds=2):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        response = client.get('/api/scans/'+scan_id, headers=HEADERS)
        if response.json['data']['state'] in TERMINAL: return response.json['data']
        time.sleep(.1)
    pytest.fail('Scan did not finish')


def fake_run(argv, **kwargs):
    name = Path(argv[0]).name
    if name == 'nmap': return ProcessResult('completed', NMAP, exit_code=0)
    if name == 'httpx': return ProcessResult('completed', FIXTURES['httpx'], exit_code=0)
    if name == 'whatweb':
        output = next(x.split('=',1)[1] for x in argv if x.startswith('--log-json='))
        Path(output).write_text(FIXTURES['whatweb'])
        return ProcessResult('completed', exit_code=0)
    if name == 'nuclei': return ProcessResult('completed', FIXTURES['nuclei'], exit_code=0)
    raise AssertionError(name)


def test_full_mocked_workflow_exports_and_idempotency(app, monkeypatch):
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    client = app.test_client()
    response = create(client)
    assert response.status_code == 202
    scan_id = response.json['data']['id']
    result = finish(client, scan_id)
    assert result['state'] == 'completed'
    assert result['progress']['processed'] == 3
    assert any(a['kind'] == 'web' for a in result['assets'])
    assert create(client).json['data']['id'] == scan_id
    assert create(client, profile='standard').status_code == 409
    for format_name in ('html','json','vulnerabilities'):
        assert client.get(f'/api/scans/{scan_id}/report?format={format_name}').status_code == 401
        export = client.get(f'/api/scans/{scan_id}/report?format={format_name}', headers=HEADERS)
        assert export.status_code == 200
    directory = Path(app.extensions['database'].url.database).parent
    assert len(list(directory.glob('reports/*/*/report.html'))) == 1
    dashboard = client.get('/api/dashboard', headers=HEADERS).json['data']
    assert dashboard['total_scans'] == 1
    assert client.get('/api/scans?page_size=0', headers=HEADERS).status_code == 400
    assert client.get('/api/scans/'+scan_id+'/findings?sort=bad', headers=HEADERS).status_code == 400
    assert client.delete('/api/scans/'+scan_id, headers=HEADERS).status_code == 400
    assert client.delete('/api/scans/'+scan_id, headers=dict(HEADERS, **{'X-Confirm-Delete':scan_id})).status_code == 200
    assert client.get('/api/scans/'+scan_id, headers=HEADERS).status_code == 404


def test_reports_use_their_own_dark_theme(app, monkeypatch):
    """Exported reports carry a fixed dark theme, independent of the workspace.

    The report must not reference the workspace theme attribute or storage key,
    and it must not follow the operating-system preference, so a user in light
    mode still receives a readable dark report and vice versa."""
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    client = app.test_client()
    scan_id = create(client).json['data']['id']
    finish(client, scan_id)
    html = client.get(f'/api/scans/{scan_id}/report', headers=HEADERS).text
    assert 'color-scheme:dark' in html
    assert 'background:#0e1211' in html
    assert 'data-theme=' not in html and 'ava-theme' not in html
    assert 'prefers-color-scheme' not in html
    assert 'background:#fff' not in html and 'background:#ffffff' not in html
    # The report is still a real, populated document, not an empty page.
    assert 'Security assessment report' in html and 'Executive summary' in html


def test_report_writer_stays_inside_windows_max_path(tmp_path):
    """Regression: report paths longer than Windows MAX_PATH fail to open.

    On a host with LongPathsEnabled=0 a 260-character-or-longer path raises
    FileNotFoundError even though its directory exists, so mkdir succeeded while
    opening vulnerabilities.json.tmp failed and the report endpoint answered
    internal_error. Long local-directory targets must be shortened, stay unique,
    and leave short targets untouched so existing reports remain findable."""
    data_dir = tmp_path / ('p' * 40) / 'db'
    target = str(tmp_path / ('t' * 90))
    scan = dict(id='1b4ca44b-9537-4eca-b01f-fe913663d292', target=target, profile='local',
                state='completed', created_at='2026-10-11T00:00:00+00:00',
                started_at=None, ended_at=None, configuration={}, finding_count=0,
                progress={'processed': 0, 'total': 0, 'current_tool': None}, executions=[],
                coverage={'completed': [], 'untested_or_incomplete': [], 'not_selected': []},
                severities={}, assets=[], findings=[])

    directory = write_reports(data_dir, scan)
    for name in ('scan.json', 'vulnerabilities.json', 'report.html'):
        assert (directory / name).is_file(), name
    assert len(str(directory / LONGEST_REPORT_NAME)) <= 259
    assert len(str(directory)) <= 247
    # Two long targets sharing a prefix still get separate directories.
    other = dict(scan, id='aaf6e07b-b5cd-4e75-9971-6ed49655bc78', target=target + '-second')
    assert report_directory(data_dir, other) != report_directory(data_dir, scan)
    # Short targets keep the historic layout byte for byte.
    short = dict(scan, target='127.0.0.1')
    assert report_directory(data_dir, short) == data_dir / 'reports' / '127.0.0.1' / scan['id']


def test_missing_scanners_not_clean_scan(app, monkeypatch):
    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda _: None)
    client = app.test_client()
    scan_id = create(client).json['data']['id']
    result = finish(client, scan_id)
    assert result['state'] == 'failed'
    assert all(e['state'] == 'unavailable' for e in result['executions'])
    assert result['findings'] == []


@pytest.mark.parametrize('failure', ['failed', 'timed_out', 'output_limit', 'malformed'])
def test_partial_failures(app, monkeypatch, failure):
    def runner(argv, **kwargs):
        if Path(argv[0]).name == 'httpx':
            return ProcessResult('completed', 'bad output') if failure == 'malformed' else ProcessResult(failure)
        return fake_run(argv, **kwargs)
    monkeypatch.setattr('backend.services.scan_service.run', runner)
    client = app.test_client()
    result = finish(client, create(client).json['data']['id'])
    assert result['state'] == 'completed_with_errors'
    assert result['executions'][1]['state'] != 'completed'
    assert result['executions'][2]['state'] == 'skipped'


def test_cancellation(app, monkeypatch):
    started = threading.Event()
    def runner(argv, cancel=None, **kwargs):
        started.set()
        assert cancel.wait(2)
        return ProcessResult('cancelled')
    monkeypatch.setattr('backend.services.scan_service.run', runner)
    client = app.test_client()
    scan_id = create(client).json['data']['id']
    assert started.wait(1)
    assert client.post(f'/api/scans/{scan_id}/cancel', headers=HEADERS).status_code == 202
    assert finish(client, scan_id)['state'] == 'cancelled'
    assert client.post(f'/api/scans/{scan_id}/cancel', headers=HEADERS).status_code == 409


def test_input_access_scope(app):
    client = app.test_client()
    assert client.post('/api/scans', json={}).status_code == 401
    assert create(client, authorized=False).status_code == 400
    assert create(client, target='8.8.8.8').status_code == 403
    assert create(client, target=';bad').status_code == 400
    assert create(client, tools=['unknown']).status_code == 400
    assert create(client, tools=['whatweb']).status_code == 400
    assert client.get('/api/scans/compare?first=no&second=no', headers=HEADERS).status_code == 404


def test_findings_xss_filter_and_compare(app, monkeypatch):
    def runner(argv, **kwargs):
        if Path(argv[0]).name == 'nuclei':
            row = json.loads(FIXTURES['nuclei']); row['info']['name'] = '<script>alert(1)</script>'
            return ProcessResult('completed', json.dumps(row)+'\n'+json.dumps(row))
        return fake_run(argv, **kwargs)
    monkeypatch.setattr('backend.services.scan_service.run', runner)
    client = app.test_client()
    scan_id = create(client, profile='standard', tools=['nmap','httpx','nuclei']).json['data']['id']
    result = finish(client, scan_id)
    assert len(result['findings']) == 1
    findings = client.get(f'/api/scans/{scan_id}/findings?severity=informational&scanner=nuclei', headers=HEADERS).json
    assert findings['meta']['total'] == 1
    html = client.get(f'/api/scans/{scan_id}/report', headers=HEADERS).text
    assert '<script>alert' not in html and '&lt;script&gt;' in html
    comparison = client.get(f'/api/scans/compare?first={scan_id}&second={scan_id}', headers=HEADERS).json['data']
    assert len(comparison['unchanged']) == 1 and comparison['new'] == []


def test_restart_recovery_marks_interrupted_scan_failed(tmp_path):
    settings = Settings(tmp_path, TOKEN)
    first = create_app(settings)
    with Session(first.extensions['database']) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='running')
        scan.executions.append(ToolExecution(tool='nmap', state='running'))
        session.add(scan);session.commit();scan_id=scan.id
    first.extensions['scan_manager'].shutdown();first.extensions['database'].dispose()
    second = create_app(settings)
    try:
        data = second.test_client().get('/api/scans/'+scan_id, headers=HEADERS).json['data']
        assert data['state'] == 'failed' and data['executions'][0]['state'] == 'failed'
        assert 'restarted' in data['configuration']['failure']
    finally:
        second.extensions['scan_manager'].shutdown();second.extensions['database'].dispose()


def test_queue_and_throttle(app, monkeypatch):
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    client=app.test_client()
    assert create(client).status_code == 202
    response=client.post('/api/scans',json={'target':'127.0.0.1','profile':'quick','tools':['nmap'],'authorized':True},headers=dict(HEADERS,**{'Idempotency-Key':'a-different-key-123'}))
    assert response.status_code == 429


def test_disabled_and_unverified_tools_fail_closed(app, monkeypatch):
    """Disabled integrations are skipped with their reason; a binary that fails
    identity verification is a failure, never a clean result.

    This is the real-world shape of a tool that is present but cannot execute
    (for example a binary blocked by an endpoint security policy)."""
    monkeypatch.delenv('AVA_WAPITI_ENABLED', raising=False)
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (False, None))
    # Deterministic fixture for the identity check: the probe completes but the
    # binary identity never verifies, so the execution fails as unverified.
    monkeypatch.setattr('backend.services.tool_manager.run',
                        lambda *args, **kwargs: ProcessResult('completed', stdout='not a verified tool identity'))
    client = app.test_client()
    result = finish(client, create(client, profile='comprehensive',
                                  tools=['nmap', 'httpx', 'wapiti']).json['data']['id'])
    executions = {e['tool']: e for e in result['executions']}

    # Present but unverified: failed, with no exit code, never "clean".
    assert executions['nmap']['state'] == 'failed'
    assert executions['httpx']['state'] == 'failed'
    assert 'identity/version verification failed' in executions['nmap']['error']
    assert executions['nmap']['exit_code'] is None

    # The safety-disabled integration is skipped with an explicit reason and
    # never run; nothing else in the registry is disabled.
    disabled = executions['wapiti']
    assert disabled['state'] == 'skipped'
    assert disabled['exit_code'] is None
    assert disabled['error'], 'wapiti skipped without a reason'
    assert 'disabled' in disabled['error'].lower()

    # No tool completed, so the scan must not claim success in any form.
    assert result['state'] == 'failed'
    assert result['findings'] == [] and result['assets'] == []


def test_rebinding_is_rejected(app, monkeypatch):
    from backend.services.target_validation import ValidatedTarget
    monkeypatch.setattr('backend.services.scan_service.validate_target',lambda *args:ValidatedTarget('127.0.0.1',('127.0.0.2',)))
    def should_not_run(*args,**kwargs):pytest.fail('Rebound target reached scanner')
    monkeypatch.setattr('backend.services.scan_service.run',should_not_run)
    client=app.test_client();result=finish(client,create(client).json['data']['id'])
    assert result['state']=='failed'
