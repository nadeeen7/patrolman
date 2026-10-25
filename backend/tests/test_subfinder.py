"""Subfinder operational tests: approved binary detection, scope and reporting.

Subfinder is now runnable on this host through the discovered approved local binary
(`tools/subfinder/subfinder.exe`), whose release archive
SHA-256 matches the published `subfinder_2.17.0_checksums.txt` entry. One test
executes the real binary's version probe (no enumeration, no network). Everything
else is a fixture or a mock: **no live subdomain enumeration is performed**, because
that needs a domain the operator explicitly authorizes.
"""
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.integrations import subfinder
from backend.models import AuthorizedTarget
from backend.services import executables
from backend.services.executables import find_argv
from backend.services.process_runner import ProcessResult, run
from backend.services.scan_service import TERMINAL, TOOL_TIMEOUT
from backend.services.tool_manager import inventory
from backend.tests.test_execution import NMAP
from backend.tests.test_workflow import HEADERS, TOKEN, finish


def register_synthetic_target(engine, host='example.com', methods=None, **kwargs):
    now = datetime.now(timezone.utc)
    defaults = {
        'name': 'Synthetic Subfinder Target',
        'target_type': 'internal_system',
        'owner_organization': 'Test Harness',
        'scope_domains': [host],
        'explicit_subdomains': [],
        'excluded_scope': [],
        'permitted_methods': ['port_scan', 'web_service_discovery'] if methods is None else list(methods),
        'prohibited_methods': ['dos', 'exploit'],
        'rate_limit_rps': 10,
        'valid_from': now - timedelta(days=1),
        'valid_to': now + timedelta(days=30),
        'evidence_reference': 'SUBFINDER-AUTH-2026',
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

APPROVED = Path(__file__).resolve().parents[2] / 'tools' / 'subfinder' / 'subfinder.exe'
DOMAIN = 'example.com'
FIXTURE = '\n'.join([
    '{"host":"api.example.com","source":"crtsh"}',
    '{"host":"SUB.EXAMPLE.COM.","source":"provider"}',
    '{"host":"deep.a.b.example.com","source":"provider"}',
    '{"host":"example.com","source":"provider"}',
    '{"host":"unrelated.example","source":"provider"}',
    '{"host":"evil-example.com","source":"provider"}',
    '{"host":"example.com.attacker.net","source":"provider"}',
])


# --- 1. Detection and configuration -----------------------------------------

def test_discovery_finds_local_subfinder_and_preserves_explicit_override(monkeypatch, tmp_path):
    """The binary is discovered automatically, but explicit paths remain authoritative."""
    project = tmp_path / 'project'
    automatic = project / 'tools' / 'subfinder' / 'subfinder.exe'
    explicit = tmp_path / 'approved' / 'subfinder.exe'
    automatic.parent.mkdir(parents=True)
    explicit.parent.mkdir()
    automatic.write_bytes(b'local candidate')
    explicit.write_bytes(b'explicit candidate')
    monkeypatch.setattr(executables, 'PROJECT_ROOT', project)
    monkeypatch.setattr(executables, 'WINDOWS', True)
    monkeypatch.setattr(executables.shutil, 'which', lambda *args, **kwargs: None)
    monkeypatch.delenv('AVA_SUBFINDER_PATH', raising=False)
    assert find_argv(subfinder.COMMANDS) == str(automatic.resolve())

    monkeypatch.setenv('AVA_SUBFINDER_PATH', str(explicit))
    assert find_argv(subfinder.COMMANDS) == str(explicit.resolve())

    monkeypatch.setenv('AVA_SUBFINDER_PATH', str(tmp_path / 'missing.exe'))
    assert find_argv(subfinder.COMMANDS) is None


def test_runtime_reporting_distinguishes_discovery_from_authorization(monkeypatch, tmp_path):
    project = tmp_path / 'project'
    binary = project / 'tools' / 'subfinder' / 'subfinder.exe'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'discovered candidate')
    monkeypatch.setattr(executables, 'PROJECT_ROOT', project)
    monkeypatch.setattr(executables, 'WINDOWS', True)
    monkeypatch.setattr(executables.shutil, 'which', lambda *args, **kwargs: None)
    monkeypatch.setattr(subfinder, 'integrity_status', lambda _: {
        'status': 'unpinned', 'expected': None, 'actual': None, 'message': 'test candidate is unpinned',
    })
    monkeypatch.delenv('AVA_SUBFINDER_PATH', raising=False)
    monkeypatch.delenv('AVA_SUBFINDER_PROVIDER_CONFIG', raising=False)
    entry = {item['name']: item for item in inventory(check_versions=False)}['subfinder']
    message = entry['runtime_configuration']['message']
    assert 'Environment configuration is present' not in message
    assert entry['executable_found'] is True
    assert entry['status'] == 'unverified'
    assert entry['state'] == 'CONFIGURATION_REQUIRED'
    assert entry['runtime_configuration']['status'] == 'configured'
    assert 'never scan permission' in message
    monkeypatch.setenv('AVA_SUBFINDER_PATH', str(binary))
    configured = {item['name']: item for item in inventory(check_versions=False)}['subfinder']
    assert configured['executable_found'] is True
    assert configured['integrity']['status'] == 'unpinned'
    assert 'built-in default providers' in configured['runtime_configuration']['message']


def test_missing_provider_file_is_configuration_required(monkeypatch, tmp_path):
    monkeypatch.setenv('AVA_SUBFINDER_PROVIDER_CONFIG', str(tmp_path / 'absent-providers.yaml'))
    entry = {item['name']: item for item in inventory(check_versions=False)}['subfinder']
    assert entry['runtime_configuration']['status'] == 'configuration_required'
    assert subfinder.configuration_error()
    with pytest.raises(ValueError, match='provider configuration missing'):
        subfinder.command('C:/tools/subfinder.exe', DOMAIN, 'standard', tmp_path / 'out.json')


def test_provider_file_contents_are_never_read_by_patrolman(monkeypatch, tmp_path):
    """A provider file holding keys is only ever passed as a path; its text is not reported."""
    secret = 'SYNTHSUBFINDERPROVIDERKEY77'
    provider = tmp_path / 'providers.yaml'
    provider.write_text('providers:\n  - name: synthetic\n    keys: ' + secret + '\n', encoding='utf-8')
    monkeypatch.setenv('AVA_SUBFINDER_PROVIDER_CONFIG', str(provider))
    monkeypatch.setenv('AVA_SUBFINDER_PATH', r'C:\ApprovedTools\subfinder\subfinder.exe')
    payload = json.dumps(inventory(check_versions=False))
    assert secret not in payload


# --- 2. Command and target validation ---------------------------------------

def test_command_targets_only_the_normalized_authorized_domain(tmp_path, monkeypatch):
    monkeypatch.delenv('AVA_SUBFINDER_PROVIDER_CONFIG', raising=False)
    argv = subfinder.command('C:/tools/subfinder.exe', 'EXAMPLE.com.', 'standard', tmp_path / 'out.json')
    assert isinstance(argv, list) and all(isinstance(part, str) for part in argv)
    assert argv[0] == 'C:/tools/subfinder.exe'
    assert argv[argv.index('-d') + 1] == DOMAIN
    for flag in ('-json', '-silent', '-rl', '-timeout', '-max-time', '-duc'):
        assert flag in argv, flag
    # Passive, rate-limited and bounded: 2 requests/second at most and a one-minute
    # ceiling, well inside the shared runner bound.
    assert argv[argv.index('-rl') + 1] == '2'
    assert int(argv[argv.index('-max-time') + 1]) * 60 < TOOL_TIMEOUT
    assert len([part for part in argv if re.fullmatch(r'[a-z0-9.-]+\.[a-z]{2,}', part or '')]) == 1


@pytest.mark.parametrize('bad_target', ['http://example.com', 'example.com:8080', '*.example.com',
                                        'example.com/path', 'exa mple.com', '', 'example.com\n--other'])
def test_invalid_or_expanded_targets_are_rejected(bad_target, tmp_path):
    with pytest.raises(ValueError):
        subfinder.command('C:/tools/subfinder.exe', bad_target, 'standard', tmp_path / 'out.json')


# --- 3. Parsing and scope filtering -----------------------------------------

def test_parse_keeps_only_strict_subdomains_of_the_authorized_domain():
    parsed = subfinder.parse(FIXTURE, DOMAIN)
    hosts = sorted(asset['address'] for asset in parsed.assets)
    assert hosts == ['api.example.com', 'deep.a.b.example.com', 'sub.example.com']
    assert not parsed.findings
    for asset in parsed.assets:
        assert asset['kind'] == 'subdomain' and asset['details']['passive'] is True
        assert asset['details']['authorized_for_scanning'] is False
        assert asset['details']['source'] == 'subfinder'


@pytest.mark.parametrize('payload', ['not json', '{"host":""}', '{"nothost":"x"}', '[]'])
def test_malformed_output_fails_instead_of_inventing_assets(payload):
    with pytest.raises((ValueError, KeyError, TypeError, SyntaxError)):
        subfinder.parse(payload, DOMAIN)


# --- 4. Timeout, failure and diagnostics ------------------------------------

def _pinned_artifact(tmp_path, monkeypatch, digest=None):
    """Pin a synthetic artifact so the digest gate passes inside a mocked scan."""
    from backend.services.integrity import sha256_file
    artifact = tmp_path / 'subfinder.exe'
    artifact.write_bytes(b'PATROLMAN synthetic subfinder artifact for tests\n')
    manifest = tmp_path / 'approved_binaries.json'
    manifest.write_text(json.dumps({'subfinder': {'sha256': digest or sha256_file(artifact)}}), encoding='utf-8')
    monkeypatch.setenv('AVA_APPROVED_BINARIES', str(manifest))
    return artifact


def _scan(tmp_path, monkeypatch, result, tools=('nmap', 'subfinder'), output=None,
          subfinder_path='auto', launched=None):
    """Run an offline mocked scan; `subfinder_path=None` simulates an unresolvable tool."""
    artifact = _pinned_artifact(tmp_path, monkeypatch) if subfinder_path == 'auto' else subfinder_path

    def resolve(commands):
        if commands[0] == 'subfinder':
            return str(artifact) if artifact else None
        return '/mock/' + commands[0]

    def fake_run(argv, **kwargs):
        name = Path(argv[0]).stem
        if launched is not None:
            launched.append(name)
        if name == nmap_stem:
            return ProcessResult('completed', NMAP, exit_code=0)
        if name == 'subfinder':
            return result
        raise AssertionError('Unexpected executable: ' + str(argv[0]))

    nmap_stem = Path('/mock/nmap').stem
    # No DNS and no packets: the domain target is authorized against a stubbed
    # resolution so the scan stays entirely offline and self-contained.
    from backend.services.target_validation import ValidatedTarget
    resolved = ValidatedTarget(DOMAIN, ('127.0.0.1',))
    monkeypatch.setattr('backend.routes.validate_target', lambda *args, **kwargs: resolved)
    monkeypatch.setattr('backend.services.scan_service.validate_target', lambda *args, **kwargs: resolved)
    monkeypatch.setattr('backend.services.scan_service.find_argv', resolve)
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1', 'example.com'), True))
    app.config['TESTING'] = True
    register_synthetic_target(app.extensions['database'], host=DOMAIN)
    client = app.test_client()
    created = client.post('/api/scans', json={'target': DOMAIN, 'profile': 'standard', 'tools': list(tools),
        'authorized': True}, headers=dict(HEADERS, **{'Idempotency-Key': 'subfinder-scan-00001'}))
    assert created.status_code == 202, created.json
    data = finish(client, created.json['data']['id'])
    return app, client, data


def test_timed_out_enumeration_is_reported_as_timed_out(tmp_path, monkeypatch):
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('timed_out', stderr='killed'))
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'timed_out' and execution['outcome'] == 'TIMED_OUT'
        assert data['state'] == 'completed_with_errors'
        assert [a for a in data['assets'] if a['kind'] == 'subdomain'] == []
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_failed_enumeration_withholds_diagnostics_and_secrets(tmp_path, monkeypatch):
    """Subfinder diagnostics may echo provider keys, so they are never surfaced."""
    secret = 'SYNTHSUBFINDERPROVIDERKEY88'
    app, client, data = _scan(tmp_path, monkeypatch,
        ProcessResult('failed', stderr='provider auth failed key=' + secret, exit_code=1))
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'failed'
        assert 'Diagnostic output withheld' in execution['error']
        assert secret not in json.dumps(data)
        assert data['state'] == 'completed_with_errors'
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_empty_output_is_reported_as_incomplete_enumeration(tmp_path, monkeypatch):
    """Zero subdomains is not proof of complete enumeration, and the scan says so."""
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('completed', '', exit_code=0))
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'completed'
        assert execution['finding_count'] == 0
        assert 'not proof of complete enumeration' in execution['limitations']
        assert [a for a in data['assets'] if a['kind'] == 'subdomain'] == []
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


# --- 5. Results, history and reports ---------------------------------------

def test_subdomain_assets_reach_results_history_and_both_reports(tmp_path, monkeypatch):
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('completed', FIXTURE, exit_code=0))
    try:
        assert data['state'] == 'completed', data['executions']
        discovered = sorted(a['address'] for a in data['assets'] if a['kind'] == 'subdomain')
        assert discovered == ['api.example.com', 'deep.a.b.example.com', 'sub.example.com']
        assert all(a['details']['authorized_for_scanning'] is False for a in data['assets'] if a['kind'] == 'subdomain')

        listed = client.get('/api/scans/' + data['id'], headers=HEADERS).json['data']
        assert sorted(a['address'] for a in listed['assets'] if a['kind'] == 'subdomain') == discovered
        html = client.get('/api/scans/' + data['id'] + '/report', headers=HEADERS).text
        directory = Path(app.extensions['database'].url.database).parent
        scan_json = next(directory.glob('reports/*/*/scan.json')).read_text(encoding='utf-8')
        for name in discovered:
            assert name in scan_json, name
            assert name in html, name
        # Passive discovery creates inventory, not findings, and names the tools that ran.
        assert data['findings'] == []
        assert set(json.loads(scan_json)['coverage']['completed']) == {'nmap', 'subfinder'}
        # Discovered subdomains are inventory only: the stored scan records that they
        # are not authorized for scanning, so nothing silently expands scope.
        stored = json.loads(scan_json)
        assert all(a['details']['authorized_for_scanning'] is False
                   for a in stored['assets'] if a['kind'] == 'subdomain')
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


# --- 6. Approved-digest pin enforcement -------------------------------------

def test_execution_is_refused_when_the_digest_does_not_match(tmp_path, monkeypatch):
    """A tampered or replaced binary must never run, and the scan must say so."""
    launched = []
    # Pin a digest that the artifact on disk does not have.
    artifact = tmp_path / 'tampered-subfinder.exe'
    artifact.write_bytes(b'some other file entirely')
    manifest = tmp_path / 'approved_binaries.json'
    manifest.write_text(json.dumps({'subfinder': {'sha256': 'a' * 64}}), encoding='utf-8')
    monkeypatch.setenv('AVA_APPROVED_BINARIES', str(manifest))
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('completed', FIXTURE, exit_code=0),
                              subfinder_path=str(artifact), launched=launched)
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'configuration_required'
        assert execution['outcome'] == 'CONFIGURATION_REQUIRED'
        assert 'does not match the approved digest' in execution['error']
        assert execution['integrity'] == 'mismatch'
        assert execution['integrity_actual'] != execution['integrity_expected']
        # The binary was never launched: only nmap ran.
        assert 'subfinder' not in launched and launched == ['nmap']
        assert data['state'] == 'completed_with_errors'
        assert [a for a in data['assets'] if a['kind'] == 'subdomain'] == []
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_execution_proceeds_and_records_the_verified_digest(tmp_path, monkeypatch):
    launched = []
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('completed', FIXTURE, exit_code=0), launched=launched)
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'completed' and execution['integrity'] == 'verified'
        assert execution['integrity_expected'] == execution['integrity_actual']
        assert 'subfinder' in launched
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_an_unpinned_tool_still_runs_and_says_so(tmp_path, monkeypatch):
    """Removing the pin must not break the tool; it must only be reported as unpinned."""
    launched = []
    artifact = tmp_path / 'subfinder.exe'
    artifact.write_bytes(b'synthetic artifact')
    monkeypatch.setenv('AVA_APPROVED_BINARIES', str(tmp_path / 'absent-manifest.json'))
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('completed', FIXTURE, exit_code=0),
                              subfinder_path=str(artifact), launched=launched)
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'completed' and execution['integrity'] == 'unpinned'
        assert 'subfinder' in launched
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_a_corrupt_manifest_refuses_execution(tmp_path, monkeypatch):
    """A broken integrity control fails closed instead of silently disabling itself."""
    launched = []
    artifact = tmp_path / 'subfinder.exe'
    artifact.write_bytes(b'synthetic artifact')
    manifest = tmp_path / 'approved_binaries.json'
    manifest.write_text('{not valid json', encoding='utf-8')
    monkeypatch.setenv('AVA_APPROVED_BINARIES', str(manifest))
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('completed', FIXTURE, exit_code=0),
                              subfinder_path=str(artifact), launched=launched)
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'configuration_required' and execution['integrity'] == 'error'
        assert 'manifest' in execution['error']
        assert 'subfinder' not in launched
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_configured_path_that_does_not_exist_is_unavailable(tmp_path, monkeypatch):
    """A mis-typed path is reported as unavailable, before any integrity verdict."""
    monkeypatch.setenv('AVA_SUBFINDER_PATH', str(tmp_path / 'typo' / 'no-such-binary.exe'))
    launched = []
    app, client, data = _scan(tmp_path, monkeypatch, ProcessResult('completed', FIXTURE, exit_code=0),
                              subfinder_path=None, launched=launched)
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'subfinder')
        assert execution['state'] == 'unavailable' and execution['outcome'] == 'NOT_INSTALLED'
        assert launched == ['nmap']
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


# --- 7. Live-test readiness (no enumeration performed) ----------------------

def test_an_unauthorized_domain_is_rejected_before_any_execution(tmp_path, monkeypatch):
    """Scope is enforced at scan creation, so nothing executes for an unlisted domain."""
    launched = []
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    app.config['TESTING'] = True
    try:
        monkeypatch.setattr('backend.services.scan_service.run',
                            lambda argv, **kwargs: launched.append(Path(argv[0]).name) or ProcessResult('completed', '', exit_code=0))
        client = app.test_client()
        created = client.post('/api/scans', json={'target': DOMAIN, 'profile': 'standard',
            'tools': ['nmap', 'subfinder'], 'authorized': True},
            headers=dict(HEADERS, **{'Idempotency-Key': 'subfinder-scope-0001'}))
        assert created.status_code == 403, created.json
        history = client.get('/api/scans', headers=HEADERS).json['data']
        assert history == [] or history.get('items') == []
        assert launched == []
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_the_mocked_scan_enforces_rate_limits_timeouts_and_no_scope_expansion(tmp_path, monkeypatch):
    """The argv actually used by a scan keeps its rate limit, timeout and single domain."""
    captured = []
    artifact = _pinned_artifact(tmp_path, monkeypatch)

    def fake_run(argv, **kwargs):
        name = Path(argv[0]).name
        if name == 'nmap':
            captured.append(list(argv))
            return ProcessResult('completed', NMAP, exit_code=0)
        captured.append(list(argv))
        return ProcessResult('completed', FIXTURE, exit_code=0)

    from backend.services.target_validation import ValidatedTarget
    resolved = ValidatedTarget(DOMAIN, ('127.0.0.1',))
    monkeypatch.setattr('backend.routes.validate_target', lambda *args, **kwargs: resolved)
    monkeypatch.setattr('backend.services.scan_service.validate_target', lambda *args, **kwargs: resolved)
    monkeypatch.setattr('backend.services.scan_service.find_argv',
                        lambda commands: str(artifact) if commands[0] == 'subfinder' else '/mock/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1', 'example.com'), True))
    app.config['TESTING'] = True
    register_synthetic_target(app.extensions['database'], host=DOMAIN)
    try:
        client = app.test_client()
        created = client.post('/api/scans', json={'target': DOMAIN, 'profile': 'standard',
            'tools': ['nmap', 'subfinder'], 'authorized': True},
            headers=dict(HEADERS, **{'Idempotency-Key': 'subfinder-limits-01'}))
        assert created.status_code == 202, created.json
        data = finish(client, created.json['data']['id'])
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()
    subfinder_argv = next(argv for argv in captured if argv[0] == str(artifact))
    assert subfinder_argv[subfinder_argv.index('-rl') + 1] == '2'
    assert int(subfinder_argv[subfinder_argv.index('-max-time') + 1]) * 60 < TOOL_TIMEOUT
    domains = [part for part in subfinder_argv if part.endswith(DOMAIN)]
    assert domains == [DOMAIN], domains
    assert data['state'] == 'completed'
    assert all(a['details']['authorized_for_scanning'] is False
               for a in data['assets'] if a['kind'] == 'subdomain')
    # Only the selected tools have executions: a discovered subdomain is never
    # silently promoted into a new scan target or a new execution.
    assert {e['tool'] for e in data['executions']} == {'nmap', 'subfinder'}
    assert 'subfinder' in data['coverage']['completed']


# --- 8. Genuine binary identity and digest (no enumeration) ------------------

@pytest.mark.skipif(not APPROVED.is_file(), reason='Approved local Subfinder binary is not present.')
def test_genuine_subfinder_binary_identity_and_version():
    """The real approved binary runs its version probe. No enumeration, no network."""
    result = run([str(APPROVED), '-version'], timeout=30, max_output=65536)
    assert result.state == 'completed', (result.state, result.stderr[-300:])
    assert subfinder.IDENTITY in (result.stdout + result.stderr).lower()
    assert '2.17.0' in (result.stdout + result.stderr)


@pytest.mark.skipif(not APPROVED.is_file(), reason='Approved local Subfinder binary is not present.')
def test_genuine_binary_matches_the_shipped_approved_digest():
    """The real artifact hashes to the digest recorded in the shipped manifest."""
    from backend.services.integrity import approved_digest, sha256_file, verify_digest
    assert sha256_file(APPROVED) == approved_digest('subfinder')
    assert verify_digest('subfinder', str(APPROVED))['status'] == 'verified'
