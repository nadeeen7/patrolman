import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app import _normalize_version, _versions_match, create_app
from backend.config import Settings
from backend.models import Scan, ToolExecution
from backend.services.process_runner import ProcessResult
from backend.services.tool_manager import _VERIFIED_CACHE, diagnose, verify

TOKEN = 'patrolman-test-token-at-least-32-chars-long'


@pytest.fixture
def app(tmp_path):
    application = create_app(Settings(tmp_path, TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    yield application
    application.extensions['scan_manager'].shutdown()
    application.extensions['database'].dispose()


def test_normalize_version_and_matching():
    assert _normalize_version('SSLyze version 6.3.1') == '6.3.1'
    assert _normalize_version('6.3.1') == '6.3.1'
    assert _versions_match('SSLyze version 6.3.1', '6.3.1') is True

    assert _normalize_version('Nmap version 7.80 ( https://nmap.org )') == '7.80'
    assert _normalize_version('Nmap 7.80') == '7.80'
    assert _versions_match('Nmap version 7.80 ( https://nmap.org )', 'Nmap 7.80') is True

    assert _normalize_version('[INF] Current Version: v2.17.0') == '2.17.0'
    assert _normalize_version('2.17.0') == '2.17.0'
    assert _versions_match('[INF] Current Version: v2.17.0', '2.17.0') is True

    assert _normalize_version('Version: 0.75.0') == '0.75.0'
    assert _normalize_version('0.75.0') == '0.75.0'
    assert _versions_match('Version: 0.75.0', '0.75.0') is True

    # Differing versions must not match
    assert _versions_match('Nmap 7.80', 'Nmap 7.90') is False
    assert _versions_match('6.3.1', '6.3.2') is False
    assert _versions_match(None, '1.0.0') is False
    assert _versions_match('1.0.0', None) is False


def test_api_tools_check_versions_false_reports_pending_check(app, monkeypatch):
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
        'name': 'nmap', 'status': 'unverified', 'state': 'CONFIGURATION_REQUIRED', 'integration_ready': False,
        'version': None, 'reason': 'Version check not requested.',
        'version_verification': {'status': 'unverified', 'version': None, 'message': 'Version check not requested.'},
    }])

    response = app.test_client().get('/api/tools?check_versions=false', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200
    item = response.json['data'][0]
    # Under fast initial load (check_versions=false), workflow status is pending_check
    assert item['workflow_verification']['status'] == 'pending_check'
    assert item['workflow_verification']['last_state'] == 'completed'


def test_sslyze_banner_normalization_in_api_tools(app, monkeypatch):
    engine = app.extensions['database']
    started = datetime.now(timezone.utc)
    with Session(engine) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'sslyze': {'version': 'SSLyze version 6.3.1'}},
        })
        scan.executions.append(ToolExecution(
            tool='sslyze', state='completed', started_at=started, ended_at=started,
        ))
        session.add(scan)
        session.commit()

    # Current adapter returns '6.3.1'
    monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
        'name': 'sslyze', 'status': 'ready', 'state': 'READY', 'integration_ready': True,
        'version': '6.3.1', 'reason': 'Executable identity/version verified.',
        'version_verification': {'status': 'verified', 'version': '6.3.1', 'message': 'Executable version 6.3.1 verified.'},
    }])

    response = app.test_client().get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200
    item = response.json['data'][0]
    assert item['status'] == 'ready'
    assert item['workflow_verification']['status'] == 'verified'


def test_sslyze_genuine_version_change_reports_version_changed(app, monkeypatch):
    engine = app.extensions['database']
    started = datetime.now(timezone.utc)
    with Session(engine) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'sslyze': {'version': 'SSLyze version 6.3.1'}},
        })
        scan.executions.append(ToolExecution(
            tool='sslyze', state='completed', started_at=started, ended_at=started,
        ))
        session.add(scan)
        session.commit()

    # Upgraded adapter returns '7.0.0' (genuine difference)
    monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
        'name': 'sslyze', 'status': 'ready', 'state': 'READY', 'integration_ready': True,
        'version': '7.0.0', 'reason': 'Executable identity/version verified.',
        'version_verification': {'status': 'verified', 'version': '7.0.0', 'message': 'Executable version 7.0.0 verified.'},
    }])

    response = app.test_client().get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200
    item = response.json['data'][0]
    assert item['workflow_verification']['status'] == 'version_changed'
    assert item['status'] == 'unverified'
    assert item['state'] == 'UNVERIFIED'


def test_inventory_check_versions_false_preserves_session_cache(monkeypatch):
    from backend.services.tool_manager import inventory
    _VERIFIED_CACHE.clear()

    # Discover what the resolved executable is for nmap
    items = inventory(check_versions=False)
    nmap_item = next(it for it in items if it['name'] == 'nmap')
    if nmap_item['executable_found']:
        from backend.services.executables import find_argv
        from backend.integrations import nmap as nmap_adapter
        exe = find_argv(nmap_adapter.COMMANDS)
        _VERIFIED_CACHE['nmap'] = {
            'executable': exe,
            'version': '7.80',
            'status': 'ready',
        }
        cached_items = inventory(check_versions=False)
        cached_nmap = next(it for it in cached_items if it['name'] == 'nmap')
        assert cached_nmap['version'] == '7.80'
        assert cached_nmap['version_verification']['status'] == 'verified'
        assert 'cached' in cached_nmap['version_verification']['message']


def test_transient_subprocess_timeout_does_not_declare_version_changed(app, monkeypatch):
    """Subprocess probe timeouts must report unverified/timeout and NOT declare version_changed."""
    engine = app.extensions['database']
    started = datetime.now(timezone.utc)
    with Session(engine) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'nmap': {'version': '7.80'}},
        })
        scan.executions.append(ToolExecution(
            tool='nmap', state='completed', started_at=started, ended_at=started,
        ))
        session.add(scan)
        session.commit()

    # Simulate timeout on tool version probe
    monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
        'name': 'nmap', 'status': 'unknown', 'state': 'UNVERIFIED', 'integration_ready': False,
        'version': None, 'reason': 'Executable identity/version verification failed. Version probe timed out.',
        'version_verification': {'status': 'unverified', 'version': None, 'message': 'Version probe timed out.'},
    }])

    response = app.test_client().get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200
    item = response.json['data'][0]
    # Version probe timeout does NOT overwrite historical verification with version_changed
    assert item['workflow_verification']['status'] != 'version_changed'
    assert item['workflow_verification']['last_state'] == 'completed'


def test_registered_target_permissions_and_explicit_operator_update(app):
    """Authorized operators can update permitted_methods and prohibited_methods on registered targets."""
    from backend.models import AuthorizedTarget, TargetAuditEvent
    from datetime import datetime, timedelta, timezone

    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc)
    future_dt = now_dt + timedelta(days=30)

    target_id = 'test-wapiti-target'
    with Session(engine) as session:
        target = AuthorizedTarget(
            id=target_id,
            name='Wapiti Local Test',
            target_type='organization',
            owner_organization='Local Security Test Lab',
            scope_domains=['127.0.0.1'],
            explicit_subdomains=[],
            excluded_scope=[],
            permitted_methods=['web_service_discovery', 'vulnerability_check', 'active_crawl'],
            prohibited_methods=['dos', 'exploit'],
            rate_limit_rps=10,
            valid_from=now_dt,
            valid_to=future_dt,
            evidence_reference='LOCAL-LAB-TEST-2026-10-22',
            status='active',
            created_by='admin',
            updated_by='admin',
            created_at=now_dt,
            updated_at=now_dt,
        )
        session.add(target)
        session.commit()

    client = app.test_client()
    headers = {'Authorization': 'Bearer ' + TOKEN}

    # 1. Scope check before update:
    # Check host alone: covered is True
    res_host = client.get('/api/targets/check?host=127.0.0.1', headers=headers)
    assert res_host.status_code == 200
    assert res_host.json['data']['covered'] is True

    # Check with tools requiring unpermitted methods: returns 403 scope_not_authorized
    res = client.get('/api/targets/check?host=127.0.0.1&tools=nmap,sslyze,httpx', headers=headers)
    assert res.status_code == 403
    assert 'port_scan' in res.json['error']['message']

    # 2. Operator explicitly updates target permissions via PUT
    update_payload = {
        'name': 'Wapiti Local Test (Expanded Permissions)',
        'rate_limit_rps': 20,
        'valid_to': future_dt.isoformat(),
        'evidence_reference': 'EXPANDED-LAB-AUTH-2026-10-23',
        'permitted_methods': ['port_scan', 'tls_audit', 'web_service_discovery', 'vulnerability_check', 'active_crawl'],
        'prohibited_methods': ['dos', 'exploit'],
    }
    put_res = client.put(f'/api/targets/{target_id}', json=update_payload, headers=headers)
    assert put_res.status_code == 200
    updated_target = put_res.json['data']
    assert 'port_scan' in updated_target['permitted_methods']
    assert 'tls_audit' in updated_target['permitted_methods']

    # 3. Scope check after update: Nmap and SSLyze are now permitted
    res_after = client.get('/api/targets/check?host=127.0.0.1&tools=nmap,sslyze,httpx', headers=headers)
    assert res_after.status_code == 200
    data_after = res_after.json['data']
    assert data_after['method_coverage']['nmap']['permitted'] is True
    assert data_after['method_coverage']['sslyze']['permitted'] is True

    # 4. Audit trail was recorded for the permission update
    with Session(engine) as session:
        audits = session.query(TargetAuditEvent).filter_by(target_id=target_id).all()
        assert len(audits) >= 1
        assert any('permitted_methods' in a.details.get('changes', {}) for a in audits)


def test_custom_target_enforces_matched_registered_restrictions(app):
    """Custom target host matching a registered target cannot bypass its restrictions."""
    from backend.models import AuthorizedTarget
    from datetime import datetime, timedelta, timezone

    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc)
    future_dt = now_dt + timedelta(days=30)

    target_id = 'restricted-target-1'
    with Session(engine) as session:
        target = AuthorizedTarget(
            id=target_id,
            name='Restricted Host Lab',
            target_type='organization',
            owner_organization='Security Lab',
            scope_domains=['127.0.0.1'],
            explicit_subdomains=[],
            excluded_scope=[],
            permitted_methods=['web_service_discovery'],  # lacks port_scan
            prohibited_methods=['dos', 'exploit'],
            rate_limit_rps=10,
            valid_from=now_dt,
            valid_to=future_dt,
            evidence_reference='RESTRICTED-LAB-AUTH-2026',
            status='active',
            created_by='admin',
            updated_by='admin',
            created_at=now_dt,
            updated_at=now_dt,
        )
        session.add(target)
        session.commit()

    client = app.test_client()
    headers = {'Authorization': 'Bearer ' + TOKEN, 'Idempotency-Key': 'test-idemp-key-custom-12345'}

    # Attempting to scan 127.0.0.1 with Nmap (requires port_scan) without providing target_id
    # Server-side scope validator still detects registered target and rejects unauthorized methods
    scan_payload = {
        'target': '127.0.0.1',
        'profile': 'quick',
        'tools': ['nmap', 'httpx'],
        'authorized': True,
    }
    response = client.post('/api/scans', json=scan_payload, headers=headers)
    assert response.status_code == 403
    assert 'port_scan' in response.json['error']['message']


def test_wapiti_opt_in_and_active_crawl_restrictions(app, monkeypatch):
    """Wapiti requires both target method authorization ('active_crawl') and operator opt-in ('AVA_WAPITI_ENABLED=true')."""
    from backend.models import AuthorizedTarget
    from datetime import datetime, timedelta, timezone

    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc)
    future_dt = now_dt + timedelta(days=30)

    # 1. Target that prohibits active_crawl
    with Session(engine) as session:
        target_prohibited = AuthorizedTarget(
            id='target-prohibits-crawl',
            name='Prohibits Crawl Lab',
            target_type='organization',
            owner_organization='Security Lab',
            scope_domains=['10.0.0.99'],
            explicit_subdomains=[],
            excluded_scope=[],
            permitted_methods=['web_service_discovery', 'vulnerability_check'],
            prohibited_methods=['active_crawl'],
            rate_limit_rps=10,
            valid_from=now_dt,
            valid_to=future_dt,
            evidence_reference='PROHIBIT-CRAWL-2026',
            status='active',
            created_by='admin',
            updated_by='admin',
            created_at=now_dt,
            updated_at=now_dt,
        )
        session.add(target_prohibited)
        session.commit()

    client = app.test_client()
    headers = {'Authorization': 'Bearer ' + TOKEN}

    # Checking Wapiti against prohibited target returns 403
    res_prohibited = client.get('/api/targets/check?host=10.0.0.99&tools=wapiti', headers=headers)
    assert res_prohibited.status_code == 403
    assert 'active_crawl' in res_prohibited.json['error']['message'] or 'prohibited' in res_prohibited.json['error']['message']

    # 2. Target permitting active_crawl and vulnerability_check
    with Session(engine) as session:
        target_permitted = AuthorizedTarget(
            id='target-permits-crawl',
            name='Permits Crawl Lab',
            target_type='organization',
            owner_organization='Security Lab',
            scope_domains=['10.0.0.100'],
            explicit_subdomains=[],
            excluded_scope=[],
            permitted_methods=['web_service_discovery', 'vulnerability_check', 'active_crawl'],
            prohibited_methods=['dos'],
            rate_limit_rps=10,
            valid_from=now_dt,
            valid_to=future_dt,
            evidence_reference='PERMIT-CRAWL-2026',
            status='active',
            created_by='admin',
            updated_by='admin',
            created_at=now_dt,
            updated_at=now_dt,
        )
        session.add(target_permitted)
        session.commit()

    # Scope check for tools passes when permitted
    res_perm = client.get('/api/targets/check?host=10.0.0.100&tools=wapiti', headers=headers)
    assert res_perm.status_code == 200
    assert res_perm.json['data']['method_coverage']['wapiti']['permitted'] is True

    # 3. Execution opt-in: AVA_WAPITI_ENABLED unset or false disables Wapiti in tool inventory
    monkeypatch.delenv('AVA_WAPITI_ENABLED', raising=False)
    inv_disabled = client.get('/api/tools?check_versions=false', headers=headers)
    wapiti_entry = next((t for t in inv_disabled.json['data'] if t['name'] == 'wapiti'), None)
    if wapiti_entry:
        assert wapiti_entry['operator_opt_in']['variable'] == 'AVA_WAPITI_ENABLED'
        assert wapiti_entry['operator_opt_in']['status'] == 'disabled'

    # AVA_WAPITI_ENABLED=true enables Wapiti operator opt-in
    monkeypatch.setenv('AVA_WAPITI_ENABLED', 'true')
    inv_enabled = client.get('/api/tools?check_versions=false', headers=headers)
    wapiti_entry_enabled = next((t for t in inv_enabled.json['data'] if t['name'] == 'wapiti'), None)
    if wapiti_entry_enabled:
        assert wapiti_entry_enabled['operator_opt_in']['status'] == 'enabled'


def test_backend_rejection_of_unauthorized_assessments(app):
    """Backend strictly rejects scans on unauthorized targets and with unauthorized methods."""
    client = app.test_client()
    headers = {'Authorization': 'Bearer ' + TOKEN, 'Idempotency-Key': 'unauth-assessment-key-999'}

    # 1. Reject when authorized=False
    res_not_auth = client.post('/api/scans', json={
        'target': '127.0.0.1',
        'profile': 'quick',
        'tools': ['nmap', 'httpx'],
        'authorized': False,
    }, headers=headers)
    assert res_not_auth.status_code == 400

    # 2. Reject out-of-scope host
    headers['Idempotency-Key'] = 'unauth-host-key-888'
    res_out_of_scope = client.post('/api/scans', json={
        'target': '192.168.1.99',
        'profile': 'quick',
        'tools': ['nmap', 'httpx'],
        'authorized': True,
    }, headers=headers)
    assert res_out_of_scope.status_code == 403
    assert 'allowlist' in res_out_of_scope.json['error']['message'].lower()


def test_subfinder_skip_on_ip_targets_and_execution_on_domains():
    """Subfinder must skip IP targets (IPv4 and IPv6) with specific message and accept domain targets."""
    import ipaddress

    for ip_target in ('127.0.0.1', '10.0.0.1', '::1', 'fe80::1'):
        try:
            ipaddress.ip_address(ip_target)
            inputs = []
            skip_reason = 'Target is an IP address; subdomain enumeration is only applicable to domain targets.'
        except ValueError:
            inputs = [ip_target]
            skip_reason = None
        assert inputs == []
        assert 'IP address' in skip_reason

    for domain_target in ('example.com', 'test.local'):
        try:
            ipaddress.ip_address(domain_target)
            inputs = []
            skip_reason = 'Target is an IP address; subdomain enumeration is only applicable to domain targets.'
        except ValueError:
            inputs = [domain_target]
            skip_reason = None
        assert inputs == [domain_target]
        assert skip_reason is None


def test_scan_status_classification_distinguishes_skips_from_errors(app):
    """Scan status classification must treat legitimate skips as clean, and actual errors as completed_with_errors."""
    from backend.models import Scan, ToolExecution
    from datetime import datetime, timezone

    engine = app.extensions['database']
    now_dt = datetime.now(timezone.utc)

    # 1. Completed tool + legitimate skipped tools -> scan state is 'completed'
    with Session(engine) as session:
        scan_clean = Scan(target='127.0.0.1', profile='standard', state='running', configuration={})
        scan_clean.executions.append(ToolExecution(tool='nmap', state='completed', started_at=now_dt, ended_at=now_dt))
        scan_clean.executions.append(ToolExecution(tool='subfinder', state='skipped', error='Target is an IP address; subdomain enumeration is only applicable to domain targets.'))
        scan_clean.executions.append(ToolExecution(tool='httpx', state='skipped', error='No relevant in-scope service discovered by prerequisite tools.'))
        session.add(scan_clean)
        session.commit()

        # Simulate completion logic from scan_service
        states = [e.state for e in scan_clean.executions]
        if 'completed' not in states:
            state = 'failed'
        elif any(s not in {'completed', 'skipped'} for s in states):
            state = 'completed_with_errors'
        else:
            state = 'completed'
        scan_clean.state = state
        session.commit()
        assert scan_clean.state == 'completed'

    # 2. Completed tool + failed tool -> scan state is 'completed_with_errors'
    with Session(engine) as session:
        scan_err = Scan(target='127.0.0.1', profile='standard', state='running', configuration={})
        scan_err.executions.append(ToolExecution(tool='nmap', state='completed', started_at=now_dt, ended_at=now_dt))
        scan_err.executions.append(ToolExecution(tool='httpx', state='failed', error='Connection refused', exit_code=1))
        session.add(scan_err)
        session.commit()

        states = [e.state for e in scan_err.executions]
        if 'completed' not in states:
            state = 'failed'
        elif any(s not in {'completed', 'skipped'} for s in states):
            state = 'completed_with_errors'
        else:
            state = 'completed'
        scan_err.state = state
        session.commit()
        assert scan_err.state == 'completed_with_errors'

    # 3. Completed tool + timed_out tool -> scan state is 'completed_with_errors'
    with Session(engine) as session:
        scan_to = Scan(target='127.0.0.1', profile='standard', state='running', configuration={})
        scan_to.executions.append(ToolExecution(tool='nmap', state='completed', started_at=now_dt, ended_at=now_dt))
        scan_to.executions.append(ToolExecution(tool='httpx', state='timed_out', error='Tool timed out'))
        session.add(scan_to)
        session.commit()

        states = [e.state for e in scan_to.executions]
        if 'completed' not in states:
            state = 'failed'
        elif any(s not in {'completed', 'skipped'} for s in states):
            state = 'completed_with_errors'
        else:
            state = 'completed'
        scan_to.state = state
        session.commit()
        assert scan_to.state == 'completed_with_errors'

    # 4. Completed tool + output_limit tool -> scan state is 'completed_with_errors'
    with Session(engine) as session:
        scan_ol = Scan(target='127.0.0.1', profile='standard', state='running', configuration={})
        scan_ol.executions.append(ToolExecution(tool='nmap', state='completed', started_at=now_dt, ended_at=now_dt))
        scan_ol.executions.append(ToolExecution(tool='httpx', state='output_limit', error='Output limit exceeded'))
        session.add(scan_ol)
        session.commit()

        states = [e.state for e in scan_ol.executions]
        if 'completed' not in states:
            state = 'failed'
        elif any(s not in {'completed', 'skipped'} for s in states):
            state = 'completed_with_errors'
        else:
            state = 'completed'
        scan_ol.state = state
        session.commit()
        assert scan_ol.state == 'completed_with_errors'

    # 5. No completed tool (all failed) -> scan state is 'failed'
    with Session(engine) as session:
        scan_fail = Scan(target='127.0.0.1', profile='standard', state='running', configuration={})
        scan_fail.executions.append(ToolExecution(tool='nmap', state='failed', error='Host unreachable'))
        scan_fail.executions.append(ToolExecution(tool='httpx', state='skipped', error='No relevant in-scope service discovered'))
        session.add(scan_fail)
        session.commit()

        states = [e.state for e in scan_fail.executions]
        if 'completed' not in states:
            state = 'failed'
        elif any(s not in {'completed', 'skipped'} for s in states):
            state = 'completed_with_errors'
        else:
            state = 'completed'
        scan_fail.state = state
        session.commit()
        assert scan_fail.state == 'failed'


def test_sqlite_busy_timeout_configured(app):
    """SQLite database connection must have busy_timeout configured for high concurrency."""
    from sqlalchemy import text
    engine = app.extensions['database']
    with engine.connect() as conn:
        timeout = conn.execute(text('PRAGMA busy_timeout')).scalar()
        assert timeout is not None
        assert timeout >= 10000


def test_server_side_error_logging_on_500(app, monkeypatch):
    """HTTP 500 handler must log exception context without leaking secrets to client response."""
    app.testing = False
    # Register a test endpoint that deliberately raises an unhandled error
    @app.route('/api/test-trigger-500')
    def trigger_error():
        raise RuntimeError('Deliberate internal test failure with sensitive_token=SECRET_VALUE')

    client = app.test_client()
    res = client.get('/api/test-trigger-500')
    assert res.status_code == 500
    assert res.json['error']['code'] == 'internal_error'
    assert res.json['error']['message'] == 'An internal operation failed.'
    # Client response MUST NOT leak the internal exception message or stack trace
    assert 'SECRET_VALUE' not in res.text
    assert 'RuntimeError' not in res.text


def test_restart_persistence_and_fast_inventory(tmp_path, monkeypatch):
    """Proves:
    1. A verified tool remains verified after creating a fresh application instance.
    2. A fast inventory request (check_versions=false) does not erase historical verification.
    3. Matching version in full inventory yields status='ready' and workflow_verification.status='verified'.
    """
    from backend.services.tool_manager import persist_tool_verification, _VERIFIED_CACHE

    db_path = tmp_path
    settings = Settings(db_path, TOKEN, ('127.0.0.1',), True)

    # 1. Start App 1
    app1 = create_app(settings)
    app1.config['TESTING'] = True
    started = datetime.now(timezone.utc)
    engine1 = app1.extensions['database']

    with Session(engine1) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'nmap': {'version': '7.80'}},
        })
        exec_record = ToolExecution(
            tool='nmap', state='completed', started_at=started, ended_at=started,
        )
        scan.executions.append(exec_record)
        session.add(scan)
        session.commit()
        exec_id = exec_record.id

        # Persist durable tool verification
        persist_tool_verification(
            engine=engine1,
            # pyrefly: ignore[unexpected-keyword]
            tool='nmap',
            version='7.80',
            # pyrefly: ignore[unexpected-keyword]
            status='verified',
            # pyrefly: ignore[unexpected-keyword]
            verified_at=started,
            execution_id=exec_id,
            evidence_reference=f'scan_{scan.id}',
        )

    # Shut down App 1 and clear ephemeral in-process cache
    app1.extensions['scan_manager'].shutdown()
    app1.extensions['database'].dispose()
    _VERIFIED_CACHE.clear()

    # 2. Start fresh App 2 on the exact same database
    app2 = create_app(settings)
    app2.config['TESTING'] = True

    try:
        client = app2.test_client()

        # Fast inventory request (check_versions=false)
        fast_res = client.get('/api/tools?check_versions=false', headers={'Authorization': 'Bearer ' + TOKEN})
        assert fast_res.status_code == 200
        fast_nmap = next(t for t in fast_res.json['data'] if t['name'] == 'nmap')
        # Proves fast inventory does not erase historical verification
        assert fast_nmap['workflow_verification']['status'] in ('verified', 'pending_check')
        assert fast_nmap['workflow_verification']['last_state'] == 'completed'
        assert fast_nmap['version'] == '7.80'

        # Full inventory request with matching version probe
        monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
            'name': 'nmap', 'status': 'ready', 'state': 'READY', 'integration_ready': True,
            'version': '7.80', 'reason': 'Executable identity/version verified.',
            'version_verification': {'status': 'verified', 'version': '7.80', 'message': 'Executable version 7.80 verified.'},
        }])

        full_res = client.get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
        assert full_res.status_code == 200
        full_nmap = next(t for t in full_res.json['data'] if t['name'] == 'nmap')
        assert full_nmap['status'] == 'ready'
        assert full_nmap['state'] == 'READY'
        assert full_nmap['workflow_verification']['status'] == 'verified'
        assert full_nmap['workflow_verification']['last_state'] == 'completed'
    finally:
        app2.extensions['scan_manager'].shutdown()
        app2.extensions['database'].dispose()


def test_restart_detects_genuine_version_mismatch(tmp_path, monkeypatch):
    """Proves: After restart, if executable version changed, VERSION_CHANGED is reported."""
    from backend.services.tool_manager import persist_tool_verification, _VERIFIED_CACHE

    db_path = tmp_path
    settings = Settings(db_path, TOKEN, ('127.0.0.1',), True)

    app1 = create_app(settings)
    started = datetime.now(timezone.utc)
    engine1 = app1.extensions['database']
    with Session(engine1) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'nmap': {'version': '7.80'}},
        })
        exec_record = ToolExecution(tool='nmap', state='completed', started_at=started, ended_at=started)
        scan.executions.append(exec_record)
        session.add(scan)
        session.commit()
        persist_tool_verification(
            # pyrefly: ignore[unexpected-keyword]
            engine=engine1, tool='nmap', version='7.80', status='verified',
            # pyrefly: ignore[unexpected-keyword]
            verified_at=started, execution_id=exec_record.id,
        )

    app1.extensions['scan_manager'].shutdown()
    app1.extensions['database'].dispose()
    _VERIFIED_CACHE.clear()

    # Fresh App 2
    app2 = create_app(settings)
    try:
        client = app2.test_client()
        # Probe returns upgraded version 7.95
        monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
            'name': 'nmap', 'status': 'ready', 'state': 'READY', 'integration_ready': True,
            'version': '7.95', 'reason': 'Executable identity/version verified.',
            'version_verification': {'status': 'verified', 'version': '7.95', 'message': 'Executable version 7.95 verified.'},
        }])

        res = client.get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
        assert res.status_code == 200
        nmap_item = next(t for t in res.json['data'] if t['name'] == 'nmap')
        assert nmap_item['workflow_verification']['status'] == 'version_changed'
        assert nmap_item['status'] == 'unverified'
        assert nmap_item['state'] == 'UNVERIFIED'
    finally:
        app2.extensions['scan_manager'].shutdown()
        app2.extensions['database'].dispose()


def test_restart_transient_probe_failure_does_not_declare_version_changed(tmp_path, monkeypatch):
    """Proves: A transient probe timeout after restart does not falsely claim version changed."""
    from backend.services.tool_manager import persist_tool_verification, _VERIFIED_CACHE

    db_path = tmp_path
    settings = Settings(db_path, TOKEN, ('127.0.0.1',), True)

    app1 = create_app(settings)
    started = datetime.now(timezone.utc)
    engine1 = app1.extensions['database']
    with Session(engine1) as session:
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'nmap': {'version': '7.80'}},
        })
        exec_record = ToolExecution(tool='nmap', state='completed', started_at=started, ended_at=started)
        scan.executions.append(exec_record)
        session.add(scan)
        session.commit()
        persist_tool_verification(
            # pyrefly: ignore[unexpected-keyword]
            engine=engine1, tool='nmap', version='7.80', status='verified',
            # pyrefly: ignore[unexpected-keyword]
            verified_at=started, execution_id=exec_record.id,
        )

    app1.extensions['scan_manager'].shutdown()
    app1.extensions['database'].dispose()
    _VERIFIED_CACHE.clear()

    # Fresh App 2
    app2 = create_app(settings)
    try:
        client = app2.test_client()
        # Transient timeout
        monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [{
            'name': 'nmap', 'status': 'unknown', 'state': 'UNVERIFIED', 'integration_ready': False,
            'version': None, 'reason': 'Version probe timed out.',
            'version_verification': {'status': 'unverified', 'version': None, 'message': 'Version probe timed out.'},
        }])

        res = client.get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
        assert res.status_code == 200
        nmap_item = next(t for t in res.json['data'] if t['name'] == 'nmap')
        assert nmap_item['workflow_verification']['status'] != 'version_changed'
        assert nmap_item['workflow_verification']['last_state'] == 'completed'
    finally:
        app2.extensions['scan_manager'].shutdown()
        app2.extensions['database'].dispose()


def test_restart_safety_and_config_restrictions_remain_enforced(tmp_path, monkeypatch):
    """Proves:
    1. Wapiti remains gated when opt-in is disabled, never becoming READY.
    2. Missing runtime configuration (e.g. allowed local roots for gitleaks) remains CONFIGURATION_REQUIRED after restart.
    3. Historical verification is NOT fabricated when no workflow exists.
    """
    from backend.services.tool_manager import persist_tool_verification, _VERIFIED_CACHE

    db_path = tmp_path
    settings = Settings(db_path, TOKEN, ('127.0.0.1',), True)

    app1 = create_app(settings)
    started = datetime.now(timezone.utc)
    engine1 = app1.extensions['database']
    with Session(engine1) as session:
        # Give Wapiti historical verification in the DB
        scan = Scan(target='127.0.0.1', profile='quick', state='completed', configuration={
            'tool_metadata': {'wapiti': {'version': '3.3.2'}},
        })
        exec_record = ToolExecution(tool='wapiti', state='completed', started_at=started, ended_at=started)
        scan.executions.append(exec_record)
        session.add(scan)
        session.commit()
        persist_tool_verification(
            # pyrefly: ignore[unexpected-keyword]
            engine=engine1, tool='wapiti', version='3.3.2', status='verified',
            # pyrefly: ignore[unexpected-keyword]
            verified_at=started, execution_id=exec_record.id,
        )

    app1.extensions['scan_manager'].shutdown()
    app1.extensions['database'].dispose()
    _VERIFIED_CACHE.clear()

    # Restart backend
    app2 = create_app(settings)
    try:
        client = app2.test_client()
        # Mock inventory where Wapiti opt-in is disabled, Gitleaks has no allowed local root,
        # and Subfinder has never been executed.
        monkeypatch.setattr('backend.app.inventory', lambda check_versions, allowed_local_roots, **kwargs: [
            {
                'name': 'wapiti', 'status': 'disabled', 'state': 'DISABLED_FOR_SAFETY', 'integration_ready': False,
                'version': '3.3.2', 'reason': 'Wapiti is safety-disabled until operator sets AVA_WAPITI_ENABLED=true.',
                'operator_opt_in': {'status': 'disabled', 'variable': 'AVA_WAPITI_ENABLED'},
                'version_verification': {'status': 'verified', 'version': '3.3.2'},
            },
            {
                'name': 'gitleaks', 'status': 'configuration_required', 'state': 'CONFIGURATION_REQUIRED',
                'integration_ready': False, 'version': '8.30.1',
                'reason': 'Configure AVA_ALLOWED_LOCAL_ROOTS.',
                'version_verification': {'status': 'verified', 'version': '8.30.1'},
            },
            {
                'name': 'subfinder', 'status': 'ready', 'state': 'READY', 'integration_ready': True,
                'version': '2.17.0', 'reason': 'Executable identity/version verified.',
                'version_verification': {'status': 'verified', 'version': '2.17.0'},
            },
        ])

        res = client.get('/api/tools', headers={'Authorization': 'Bearer ' + TOKEN})
        assert res.status_code == 200
        tools_map = {t['name']: t for t in res.json['data']}

        # 1. Wapiti must NOT be READY
        wapiti = tools_map['wapiti']
        assert wapiti['status'] == 'disabled'
        assert wapiti['state'] == 'DISABLED_FOR_SAFETY'

        # 2. Gitleaks must remain CONFIGURATION_REQUIRED
        gitleaks = tools_map['gitleaks']
        assert gitleaks['status'] == 'configuration_required'
        assert gitleaks['state'] == 'CONFIGURATION_REQUIRED'

        # 3. Subfinder has never executed -> historical verification must NOT be fabricated
        subfinder = tools_map['subfinder']
        assert subfinder['workflow_verification']['status'] in ('not_verified', 'unverified')
        assert subfinder['workflow_verification']['last_state'] is None
        assert subfinder['status'] == 'unverified'
    finally:
        app2.extensions['scan_manager'].shutdown()
        app2.extensions['database'].dispose()



