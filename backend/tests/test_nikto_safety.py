"""Nikto retirement regression tests: Nikto cannot run, and cannot come back.

Nikto was removed from PATROLMAN's active functionality. There is no adapter, no
registry entry, no profile selection, no manifest hint, no executable-resolution
branch and no API acceptance for it, so no code path can build or launch a Nikto
command. These tests pin that retirement, so a later edit cannot silently
reintroduce an executable Nikto path.

Nothing here downloads, installs or executes Nikto, and no Windows security
setting is read or changed. The investigation that produced the original
`DISABLED_FOR_SAFETY` gate is preserved in
`docs/NIKTO_SAFETY_INVESTIGATION.md`.
"""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.integrations import ADAPTERS
from backend.models import AuthorizedTarget
from backend.services.process_runner import ProcessResult
from backend.services.scan_service import PROFILES
from backend.services.tool_manager import inventory
from backend.tests.test_execution import NMAP
from backend.tests.test_workflow import HEADERS, TOKEN, finish


def _register_target(app, methods):
    now = datetime.now(timezone.utc)
    with Session(app.extensions['database']) as session:
        session.add(AuthorizedTarget(
            name='Synthetic Loopback Target',
            target_type='internal_system',
            owner_organization='Security Testing Harness',
            scope_domains=['127.0.0.1'],
            explicit_subdomains=[],
            excluded_scope=[],
            permitted_methods=methods,
            prohibited_methods=['dos', 'exploit'],
            rate_limit_rps=10,
            valid_from=now - timedelta(days=1),
            valid_to=now + timedelta(days=30),
            evidence_reference='TEST-AUTH-2026',
            status='active',
            created_by='admin',
            updated_by='admin',
        ))
        session.commit()


PROJECT = Path(__file__).resolve().parents[2]
EXPECTED_TOOLS = {'nmap', 'whatweb', 'httpx', 'subfinder', 'nuclei', 'wapiti', 'gitleaks', 'trivy', 'sslyze'}
RETIRED = 'nikto'


# --- 1. The adapter, its registry entry and its profile selection are gone ----

def test_nikto_adapter_module_no_longer_exists():
    """The integration module is deleted, so no Nikto command can be built."""
    assert importlib.util.find_spec('backend.integrations.nikto') is None
    assert not (PROJECT / 'backend' / 'integrations' / 'nikto.py').exists()


def test_registry_has_exactly_nine_tools_and_no_nikto():
    assert set(ADAPTERS) == EXPECTED_TOOLS
    assert len(ADAPTERS) == 9
    assert RETIRED not in ADAPTERS


def test_no_profile_can_select_nikto():
    for name, profile in PROFILES.items():
        assert RETIRED not in profile['tools'], name


def test_inventory_reports_only_the_nine_active_tools():
    """Nikto is not an available, installed, ready or disabled *active* tool."""
    entries = {item['name']: item for item in inventory(check_versions=False)}
    assert set(entries) == EXPECTED_TOOLS
    assert RETIRED not in entries
    assert RETIRED not in json.dumps(list(entries.values())).lower()


def test_a_configured_nikto_path_and_old_opt_in_names_are_inert(monkeypatch, tmp_path):
    """Even a real file at the old path plus the old opt-in spellings changes nothing."""
    fake = tmp_path / 'nikto.exe'
    fake.write_text('placeholder, never executed')
    for variable in ('AVA_NIKTO_PATH', 'AVA_NIKTO_ENABLE', 'AVA_NIKTO_OPT_IN', 'AVA_NIKTO_SAFE'):
        monkeypatch.setenv(variable, str(fake))
    entries = {item['name']: item for item in inventory(check_versions=False)}
    assert RETIRED not in entries
    assert set(entries) == EXPECTED_TOOLS


def test_shipped_manifest_has_no_nikto_pin():
    manifest = json.loads((PROJECT / 'backend' / 'approved_binaries.json').read_text(encoding='utf-8'))
    assert RETIRED not in manifest
    assert RETIRED not in json.dumps(manifest).lower()
    assert 'subfinder' in manifest


# --- 2. No active source, template, manifest or configuration reference -------

def active_source_files():
    """Every file that ships as running code, a template or shipped configuration.

    Tests, documentation, generated builds and historical data are deliberately
    out of scope: they are allowed to name the retired tool.
    """
    skip = {'tests', '__pycache__', 'node_modules', 'dist', 'build', '.venv'}
    for root in (PROJECT / 'backend', PROJECT / 'frontend' / 'src'):
        for path in root.rglob('*'):
            if not path.is_file() or any(part in skip for part in path.parts):
                continue
            if path.suffix.lower() in {'.py', '.js', '.jsx', '.html', '.json', '.css'} or path.name == '.env.example':
                yield path


def test_no_active_source_or_configuration_mentions_the_retired_tool():
    """Only the safety document and these retirement tests may name Nikto."""
    offenders = [str(path.relative_to(PROJECT)) for path in active_source_files()
                 if RETIRED in path.read_text(encoding='utf-8', errors='replace').lower()]
    assert offenders == [], f'Active files still reference the retired tool: {offenders}'


def test_the_safety_investigation_is_preserved():
    """The decision record stays, including the blockers it documented."""
    document = (PROJECT / 'docs' / 'NIKTO_SAFETY_INVESTIGATION.md').read_text(encoding='utf-8')
    assert 'retired from PATROLMAN' in document
    assert 'DISABLED_FOR_SAFETY' in document
    assert 'no checksum' in document and 'HackTool:Perl/NiktoSanner' in document


# --- 3. The API refuses the retired tool name ---------------------------------

def test_selecting_the_retired_tool_is_rejected_without_running_anything(monkeypatch, tmp_path):
    launched = []
    monkeypatch.setattr('backend.services.scan_service.run',
                        lambda argv, **kwargs: launched.append(argv) or pytest.fail('A process was launched for a retired tool.'))
    monkeypatch.setattr('backend.services.scan_service.find_argv',
                        lambda commands: launched.append(commands) or '/mock/' + commands[0])
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    app.config['TESTING'] = True
    try:
        client = app.test_client()
        for tools in ([RETIRED], ['nmap', 'httpx', RETIRED]):
            response = client.post('/api/scans',
                                   json={'target': '127.0.0.1', 'profile': 'comprehensive',
                                         'tools': tools, 'authorized': True},
                                   headers=dict(HEADERS, **{'Idempotency-Key': 'retired-tool-' + str(len(tools)) + 'z' * 8}))
            assert response.status_code == 400, response.json
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()
    assert launched == [], launched


def test_an_authorized_scan_records_and_launches_no_retired_tool(monkeypatch, tmp_path):
    """A comprehensive scan contains only selected active tools, and launches only them."""
    launched = []

    def fake_run(argv, **kwargs):
        launched.append(Path(argv[0]).name)
        if launched[-1] == 'nmap':
            return ProcessResult('completed', NMAP, exit_code=0)
        if launched[-1] == 'httpx':
            return ProcessResult('completed', '{"url":"http://127.0.0.1:8000","status_code":200}', exit_code=0)
        raise AssertionError('Unexpected executable: ' + launched[-1])

    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    app.config['TESTING'] = True
    _register_target(app, ['port_scan', 'web_service_discovery'])
    try:
        client = app.test_client()
        created = client.post('/api/scans',
                              json={'target': '127.0.0.1', 'profile': 'comprehensive',
                                    'tools': ['nmap', 'httpx'], 'authorized': True},
                              headers=dict(HEADERS, **{'Idempotency-Key': 'retired-tool-scan-01'}))
        assert created.status_code == 202, created.json
        result = finish(client, created.json['data']['id'])
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()
    assert [execution['tool'] for execution in result['executions']] == ['nmap', 'httpx']
    assert all(RETIRED not in name for name in launched), launched
    assert RETIRED not in json.dumps(result).lower()
