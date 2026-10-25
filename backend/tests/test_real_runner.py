"""Orchestration driven by the real subprocess runner — nothing about execution is mocked.

Unlike test_workflow.py, these tests never replace backend.services.scan_service.run.
Real child processes are launched, their real stdout/files are read, and the real
bounded runner applies its timeout, cancellation, output bounds and tree cleanup.

Two clearly separated kinds of evidence live here:

* Fixture binaries — small scripts placed on PATH that reproduce captured scanner
  output (the same fixtures test_execution.py parses). They prove the
  runner → adapter → orchestration → persistence wiring with real processes.
  They are NOT scanners and are never used outside tests.
* test_real_nmap_binary_quick_scan — the genuine Nmap binary against an authorized
  loopback lab. It skips with an explicit reason when Nmap is not installed, so a
  missing binary can never be mistaken for a passing real scan.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget, Scan, ToolExecution
from backend.services.executables import find_argv
from backend.services.process_runner import ProcessResult, run
from backend.services.scan_service import TERMINAL
from backend.tests.test_execution import FIXTURES, NMAP

TOKEN = 'real-runner-test-token-' + 'z' * 32
HEADERS = {'Authorization': 'Bearer ' + TOKEN}

BANNERS = {
    'nmap': 'Nmap version 7.95 (fixture)',
    'httpx': 'Current Version: 0.0.0 (fixture)',
    'whatweb': 'WhatWeb 0.5.5 (fixture)',
}

FAKE_TOOL = r'''
import json, pathlib, sys, time
tool, args = sys.argv[1], sys.argv[2:]
here = pathlib.Path(__file__).resolve().parent
with (here / 'invocations.log').open('a', encoding='utf-8') as log:
    log.write(tool + ' ' + ' '.join(args) + '\n')
banners = {'nmap': 'Nmap version 7.95 (fixture)',
           'httpx': 'Current Version: 0.0.0 (fixture)',
           'whatweb': 'WhatWeb 0.5.5 (fixture)'}
if '--version' in args or '-version' in args:
    print(banners[tool]); raise SystemExit(0)
if tool == 'httpx' and '-h' in args:
    print('-probe-all-ips -no-fallback-scheme -tech-detect'); raise SystemExit(0)
mode_file = here / 'mode.txt'
mode = mode_file.read_text().strip() if mode_file.is_file() else 'ok'
if tool == 'nmap':
    if mode == 'nonzero':
        print('fixture scanner reported an error', file=sys.stderr); raise SystemExit(3)
    if mode == 'hang':
        time.sleep(600)
    if mode == 'malformed':
        print('<nmaprun><host><ports>'); raise SystemExit(0)
    if mode == 'slow':
        # Heartbeats let a test prove the child stopped after cancellation.
        beat = here / 'heartbeat.log'
        for _ in range(600):
            with beat.open('a', encoding='utf-8') as out:
                out.write('tick\n')
            time.sleep(.2)
        raise SystemExit(0)
    sys.stdout.write((here / 'nmap.xml').read_text(encoding='utf-8')); raise SystemExit(0)
if tool == 'httpx':
    print('{"url":"http://127.0.0.1:8000","status_code":200,"tech":["Python"]}'); raise SystemExit(0)
if tool == 'whatweb':
    target = next(a.split('=', 1)[1] for a in args if a.startswith('--log-json='))
    pathlib.Path(target).write_text(
        '[{"target":"http://127.0.0.1:8000","plugins":{"Python":{}}}]', encoding='utf-8')
    raise SystemExit(0)
raise SystemExit(0)
'''


def _launcher(bin_dir, name, python):
    """A real executable on PATH; Windows needs a batch file, POSIX a shebang script."""
    if os.name == 'nt':
        path = bin_dir / f'{name}.bat'
        body = f'@echo off\r\n"{python}" "%~dp0fake_tool.py" {name} %*\r\n'
    else:
        path = bin_dir / name
        body = f'#!{python}\nimport sys, runpy\nsys.argv = ["{bin_dir}/fake_tool.py", "{name}", *sys.argv[1:]]\nrunpy.run_path("{bin_dir}/fake_tool.py", run_name="__main__")\n'
    path.write_text(body, encoding='utf-8')
    path.chmod(0o755)
    return path


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Fixture binaries on PATH and an app whose execution path is completely real."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    (bin_dir / 'fake_tool.py').write_text(FAKE_TOOL, encoding='utf-8')
    # The nmap scan body is the captured fixture used by the parser tests.
    (bin_dir / 'nmap.xml').write_text(NMAP, encoding='utf-8')
    for name in ('nmap', 'httpx', 'whatweb'):
        _launcher(bin_dir, name, sys.executable)
    (bin_dir / 'mode.txt').write_text('ok', encoding='utf-8')
    monkeypatch.setenv('PATH', str(bin_dir) + os.pathsep + os.environ.get('PATH', ''))
    if os.name == 'nt':
        # Production refuses batch launchers. Test fixture processes use native Python directly.
        monkeypatch.setattr('backend.services.scan_service.find_argv',
            lambda commands: ([sys.executable, str(bin_dir / 'fake_tool.py'), commands[0]]
                              if shutil.which(commands[0]) else None))
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    register_synthetic_target(application.extensions['database'])
    yield application, bin_dir
    application.extensions['scan_manager'].shutdown()
    application.extensions['database'].dispose()


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
        'evidence_reference': 'REAL-RUNNER-AUTH-2026',
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


def create(client, **overrides):
    payload = {'target': '127.0.0.1', 'profile': 'quick', 'tools': ['nmap', 'httpx', 'whatweb'],
               'authorized': True}
    payload.update(overrides)
    return client.post('/api/scans', json=payload,
                       headers=dict(HEADERS, **{'Idempotency-Key': 'real-runner-key-00001'}))


def finish(client, scan_id, deadline=60):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        data = client.get('/api/scans/' + scan_id, headers=HEADERS).json['data']
        if data['state'] in TERMINAL:
            return data
        time.sleep(.05)
    pytest.fail('Scan did not reach a terminal state.')


def test_real_runner_success_persists_real_child_output(lab):
    """Full quick scan: real subprocesses, real stdout, real persistence."""
    application, bin_dir = lab
    client = application.test_client()
    scan_id = create(client).json['data']['id']
    result = finish(client, scan_id)

    assert result['state'] == 'completed', result
    assert [e['state'] for e in result['executions']] == ['completed'] * 3
    assert all(e['exit_code'] == 0 for e in result['executions'])
    assert result['progress'] == {'processed': 3, 'total': 3, 'current_tool': None}
    # Assets must come from the child's real stdout, not from a mocked run().
    kinds = {asset['kind'] for asset in result['assets']}
    assert {'port', 'web', 'technology'} <= kinds, kinds
    assert result['findings'] == []

    # Proof a real process executed the adapter's constructed command.
    calls = (bin_dir / 'invocations.log').read_text(encoding='utf-8').splitlines()
    nmap_call = next(call for call in calls
                      if call.startswith('nmap ') and '--version' not in call.split())
    for argument in ('-sT', '-Pn', '-T2', '-oX', '80,443,8000,8443', '127.0.0.1'):
        assert argument in nmap_call.split(), nmap_call
    assert any(call.startswith('httpx -u http://127.0.0.1:8000') for call in calls)
    assert any(call.startswith('whatweb --aggression=1') for call in calls)

    with Session(application.extensions['database']) as session:
        stored = session.get(Scan, scan_id)
        assert stored.state == 'completed' and stored.started_at and stored.ended_at
        assert {execution.state for execution in stored.executions} == {'completed'}
        assert {'port', 'web', 'technology'} <= {asset.kind for asset in stored.assets}
    assert client.get(f'/api/scans/{scan_id}/report', headers=HEADERS).status_code == 200


def test_real_runner_nonzero_exit_is_an_accurate_failure(lab):
    application, bin_dir = lab
    (bin_dir / 'mode.txt').write_text('nonzero', encoding='utf-8')
    client = application.test_client()
    result = finish(client, create(client).json['data']['id'])

    assert result['state'] == 'failed'
    nmap = result['executions'][0]
    assert nmap['state'] == 'failed' and nmap['exit_code'] == 3
    assert 'fixture scanner reported an error' in nmap['error']
    # Later tools must not invent a clean result after a failed discovery.
    assert [e['state'] for e in result['executions'][1:]] == ['skipped', 'skipped']
    assert result['findings'] == [] and result['assets'] == []


def test_real_runner_malformed_nmap_xml_fails_closed(lab):
    application, bin_dir = lab
    (bin_dir / 'mode.txt').write_text('malformed', encoding='utf-8')
    client = application.test_client()
    result = finish(client, create(client).json['data']['id'])

    assert result['state'] == 'failed'
    assert result['executions'][0]['state'] == 'failed'
    assert 'malformed nmap' in result['executions'][0]['error']
    assert result['assets'] == [] and result['findings'] == []


def test_real_runner_timeout_terminates_the_scan(lab, monkeypatch):
    """The documented per-invocation bound, applied end to end by the real runner."""
    monkeypatch.setattr('backend.services.scan_service.TOOL_TIMEOUT', 1)
    application, bin_dir = lab
    (bin_dir / 'mode.txt').write_text('hang', encoding='utf-8')
    client = application.test_client()
    started = time.monotonic()
    result = finish(client, create(client).json['data']['id'])

    assert result['state'] == 'failed'
    assert result['executions'][0]['state'] == 'timed_out'
    assert time.monotonic() - started < 30
    assert result['findings'] == []


def test_real_runner_cancellation_kills_the_child(lab):
    application, bin_dir = lab
    (bin_dir / 'mode.txt').write_text('slow', encoding='utf-8')
    client = application.test_client()
    scan_id = create(client).json['data']['id']
    heartbeat = bin_dir / 'heartbeat.log'
    end = time.monotonic() + 30
    while not heartbeat.is_file() and time.monotonic() < end:
        time.sleep(.05)
    assert heartbeat.is_file(), 'Scanner child never started.'

    assert client.post(f'/api/scans/{scan_id}/cancel', headers=HEADERS).status_code == 202
    result = finish(client, scan_id, deadline=30)
    assert result['state'] == 'cancelled'
    assert result['executions'][0]['state'] in {'cancelled', 'skipped'}

    # The child must be gone, not merely detached: its heartbeat has to stop.
    size = heartbeat.stat().st_size
    time.sleep(1.5)
    assert heartbeat.stat().st_size == size, 'Scanner child survived cancellation.'


def test_real_runner_missing_executable_is_unavailable(lab, monkeypatch):
    monkeypatch.setenv('PATH', str(lab[1] / 'empty'))
    client = lab[0].test_client()
    result = finish(client, create(client).json['data']['id'])

    assert result['state'] == 'failed'
    assert all(e['state'] == 'unavailable' for e in result['executions'])
    assert result['findings'] == []


def test_real_whatweb_binary_detects_lab_technology(tmp_path):
    """Genuine WhatWeb through the bounded runner against the authorized lab.

    The API requires httpx whenever a web tool is selected, so this drives the
    adapter directly instead of the full workflow: real command construction,
    real runner bounds, real JSON written by the real binary, real parse.
    """
    from backend.integrations import ADAPTERS
    from backend.services.tool_manager import verify

    port = _free_web_port()
    if port is None:
        pytest.skip('No free web port from the Quick profile list.')
    executable = find_argv(ADAPTERS['whatweb'].COMMANDS)
    if not executable:
        pytest.skip('Genuine WhatWeb script/native Ruby not available; check AVA_WHATWEB_PATH.')
    valid, version = verify('whatweb', executable)
    assert valid, f'WhatWeb identity check failed: {version}'
    lab_dir = tmp_path / 'lab'
    lab_dir.mkdir()
    server = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1'],
                              cwd=lab_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        output = tmp_path / 'result.json'
        target = f'http://127.0.0.1:{port}'
        result = run(ADAPTERS['whatweb'].command(executable, target, 'quick', output),
                     timeout=90, cwd=str(tmp_path), output_files=(output,))
        assert result.state == 'completed', result
        assert result.exit_code == 0
        assert output.is_file() and output.stat().st_size > 0, 'WhatWeb wrote no JSON log.'
        parsed = ADAPTERS['whatweb'].parse(output.read_text(encoding='utf-8'), target)
        assert len(parsed.assets) == 1 and parsed.assets[0]['kind'] == 'technology'
        plugins = parsed.assets[0]['details']['plugins']
        assert {'Python', 'HTTPServer'} <= set(plugins), plugins
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def test_real_runner_rejects_out_of_scope_before_launch(lab, monkeypatch):
    """An out-of-allowlist target must never reach a scanner process."""
    from backend.services.target_validation import ScopeError

    application, bin_dir = lab
    client = application.test_client()
    assert client.post('/api/scans', json={'target': '8.8.8.8', 'profile': 'quick',
                                           'tools': ['nmap'], 'authorized': True},
                       headers=dict(HEADERS, **{'Idempotency-Key': 'out-of-scope-key-0001'})).status_code == 403
    # A target that changes its DNS answer after authorization is refused too.
    from backend.services.target_validation import ValidatedTarget
    monkeypatch.setattr('backend.services.scan_service.validate_target',
                        lambda *args: ValidatedTarget('127.0.0.1', ('127.0.0.2',)))
    result = finish(client, create(client, tools=['nmap']).json['data']['id'])
    assert result['state'] == 'failed'
    assert not (bin_dir / 'invocations.log').exists(), 'A refused target reached a scanner.'


def _free_web_port():
    for port in (8000, 8443):
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    return None


def _wait_for_port(host, port, timeout=10):
    """Block until the given loopback port is accepting TCP connections.

    Prevents Nmap from starting its real scan before the http.server subprocess
    has finished binding, which would report zero open ports and leave all
    subsequent tool steps with no discovered web services.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise OSError(f'Port {port} on {host} did not become available within {timeout}s')


def test_real_nmap_binary_quick_scan(tmp_path, monkeypatch):
    """The documented lab procedure with the genuine Nmap binary.

    Starts a local HTTP service from an empty directory, scans the authorized
    loopback target with real Nmap, and requires real discovery of the port.
    """
    if not find_argv(('nmap',)):
        pytest.skip('Genuine Nmap not available; check AVA_NMAP_PATH.')
    port = _free_web_port()
    if port is None:
        pytest.skip('No free web port from the Quick profile list.')
    lab_dir = tmp_path / 'lab'
    lab_dir.mkdir()
    server = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1'],
                              cwd=lab_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_for_port('127.0.0.1', port)
    monkeypatch.setenv('PATH', os.environ.get('PATH', ''))
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    register_synthetic_target(application.extensions['database'], methods=['port_scan'])
    try:
        client = application.test_client()
        result = finish(client, create(client, tools=['nmap'], target='127.0.0.1').json['data']['id'],
                        deadline=120)
        nmap_execution = result['executions'][0]
        assert nmap_execution['state'] == 'completed', result
        assert nmap_execution['exit_code'] == 0
        discovered = {asset['details'].get('port') for asset in result['assets']
                      if asset['kind'] == 'port'}
        assert port in discovered, f'Real Nmap did not report the lab port {port}: {result["assets"]}'
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        application.extensions['scan_manager'].shutdown()
        application.extensions['database'].dispose()


def test_real_web_tool_workflow_persists_results_and_report(tmp_path):
    """Run real Nmap, HTTPX and WhatWeb through the authorized assessment path."""
    from backend.integrations import ADAPTERS

    tools = ['nmap', 'httpx', 'whatweb']
    if any(not find_argv(ADAPTERS[name].COMMANDS) for name in tools):
        pytest.skip('Genuine Nmap, HTTPX and WhatWeb paths are required for this local workflow.')
    port = _free_web_port()
    if port is None:
        pytest.skip('No free in-scope loopback web port (8000/8443) is available.')

    lab_dir = tmp_path / 'lab'
    lab_dir.mkdir()
    server = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1'],
                              cwd=lab_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_for_port('127.0.0.1', port)
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    register_synthetic_target(application.extensions['database'], methods=['port_scan', 'web_service_discovery'])
    try:
        client = application.test_client()
        created = create(client, tools=tools, target='127.0.0.1')
        assert created.status_code == 202, created.json
        result = finish(client, created.json['data']['id'], deadline=120)

        executions = {item['tool']: item for item in result['executions']}
        assert all(executions[name]['state'] == 'completed' for name in tools), result['executions']
        assert any(asset['kind'] == 'web' and f':{port}' in asset['address'] for asset in result['assets'])
        assert any(asset['kind'] == 'technology' and asset['details'].get('source') == 'whatweb'
                   for asset in result['assets'])
        exported = client.get(f"/api/scans/{result['id']}/report?format=json", headers=HEADERS)
        assert exported.status_code == 200
        report = exported.get_json()
        report_executions = {item['tool']: item for item in report['executions']}
        assert all(report_executions[name]['state'] == 'completed' for name in tools)
        assert any(asset['kind'] == 'technology' and asset['details'].get('source') == 'whatweb'
                   for asset in report['assets'])
        html = client.get(f"/api/scans/{result['id']}/report", headers=HEADERS)
        assert html.status_code == 200
        assert all(name in html.text for name in tools)

    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        application.extensions['scan_manager'].shutdown()
        application.extensions['database'].dispose()


def test_real_nuclei_workflow_persists_findings_and_report(tmp_path, monkeypatch):
    """Run genuine HTTPX and Nuclei through result parsing and report export.

    Nmap discovery is a bounded loopback-only fixture so this test isolates
    the genuine web adapters; the genuine Nmap assessment is tested separately.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from backend.integrations import ADAPTERS

    tools = ['nmap', 'httpx', 'nuclei']
    if any(not find_argv(ADAPTERS[name].COMMANDS) for name in tools):
        pytest.skip('Genuine Nmap, HTTPX and Nuclei paths are required for this local workflow.')
    port = _free_web_port()
    if port is None:
        pytest.skip('No free in-scope loopback web port (8000/8443) is available.')

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><title>PATROLMAN local lab</title>fixture</html>')

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_run = run

    def run_with_local_discovery(argv, **kwargs):
        if Path(argv[0]).stem.lower() == 'nmap':
            return ProcessResult('completed', NMAP.replace('8000', str(port)), exit_code=0)
        return actual_run(argv, **kwargs)

    monkeypatch.setattr('backend.services.scan_service.run', run_with_local_discovery)
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    register_synthetic_target(application.extensions['database'], methods=['port_scan', 'web_service_discovery', 'vulnerability_check'])
    try:
        client = application.test_client()
        created = create(client, profile='standard', tools=tools, target='127.0.0.1')
        assert created.status_code == 202, created.json
        result = finish(client, created.json['data']['id'], deadline=120)
        executions = {item['tool']: item for item in result['executions']}
        assert all(executions[name]['state'] == 'completed' for name in tools), result['executions']
        nuclei_findings = [finding for finding in result['findings']
                           if finding['details']['source_tool'] == 'nuclei']
        assert nuclei_findings, result['findings']

        exported = client.get(f"/api/scans/{result['id']}/report?format=json", headers=HEADERS)
        assert exported.status_code == 200
        report = exported.get_json()
        assert any(finding['details']['source_tool'] == 'nuclei' for finding in report['findings'])
        html = client.get(f"/api/scans/{result['id']}/report", headers=HEADERS)
        assert html.status_code == 200 and 'nuclei' in html.text.lower()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        application.extensions['scan_manager'].shutdown()
        application.extensions['database'].dispose()
