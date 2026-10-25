"""OS policy-block classification: confirmed evidence only, honest otherwise.

Smart App Control blocked real components on this host (SQLAlchemy's compiled
extension, Ruby's socket.so) and the tool page reported CONFIGURATION_REQUIRED
because the classifier only recognised launch-time error codes. These tests
pin the contract: BLOCKED_BY_POLICY requires OS evidence (winerror 577/1260 at
launch, or an exact Windows policy message on the *stderr* of a run that did
not complete); a launch Windows refused without that evidence is
EXECUTION_BLOCKED; missing, timed-out, crashed or dependency-broken probes are
honestly NOT_INSTALLED or UNKNOWN. All fixtures are mocked ProcessResults or
isolated local children - no Windows security setting is read or changed.
"""
from datetime import datetime, timedelta, timezone
import sys

import pytest
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget
from backend.services.process_runner import ProcessResult, policy_block_evidence, run
from backend.services.tool_manager import diagnose, inventory
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


POLICY_TEXT = '4551: An Application Control policy has blocked this file'
LAUNCH_BLOCKED = 'Windows policy prevented execution; ask the policy administrator to approve the official binary.'


def probe(monkeypatch, result):
    """Run the real diagnose() against a mocked version-probe result."""
    monkeypatch.setattr('backend.services.tool_manager.run', lambda *args, **kwargs: result)
    return diagnose('httpx', 'C:/fake/httpx.exe')


def inventory_states(monkeypatch, result=None, found=True):
    """Full inventory path with executable resolution and probes controlled."""
    monkeypatch.setattr('backend.services.tool_manager.find_argv',
                        lambda commands: 'C:/fake/tool' if found else None)
    monkeypatch.setattr('backend.services.tool_manager.local_candidate', lambda commands: None)
    for name in ('HTTPX', 'WHATWEB', 'NUCLEI', 'GITLEAKS', 'TRIVY', 'SUBFINDER'):
        monkeypatch.delenv(f'AVA_{name}_PATH', raising=False)
    if result is not None:
        monkeypatch.setattr('backend.services.tool_manager.run', lambda *args, **kwargs: result)
    return {item['name']: item for item in inventory(check_versions=True)}


# --- 1. Confirmed policy-block evidence -> BLOCKED_BY_POLICY -----------------

def test_confirmed_policy_message_on_stderr_is_blocked(monkeypatch):
    """The live case: Ruby/Python prints the Application Control message and
    exits non-zero, so the run 'failed' rather than failing to launch."""
    _, _, status, reason = probe(monkeypatch, ProcessResult('failed', stderr='... ' + POLICY_TEXT, exit_code=1))
    assert status == 'blocked'
    assert 'application control policy' in reason
    states = inventory_states(monkeypatch, ProcessResult('failed', stderr=POLICY_TEXT, exit_code=1))
    assert states['nmap']['state'] == 'BLOCKED_BY_POLICY'
    assert states['nmap']['status'] == 'blocked'
    assert states['nmap']['integration_ready'] is False


def test_confirmed_policy_launch_error_is_blocked(monkeypatch):
    """winerror 1260/577 at launch: Windows itself reported the policy block."""
    _, _, status, reason = probe(monkeypatch, ProcessResult('blocked', stderr=LAUNCH_BLOCKED, winerror=1260))
    assert status == 'blocked'
    assert reason == LAUNCH_BLOCKED
    states = inventory_states(monkeypatch, ProcessResult('blocked', stderr=LAUNCH_BLOCKED, winerror=577))
    assert states['nmap']['state'] == 'BLOCKED_BY_POLICY'


# --- 2. Missing executable -> NOT_INSTALLED ----------------------------------

def test_missing_executable_is_not_installed(monkeypatch):
    states = inventory_states(monkeypatch, found=False)
    real = [item for item in states.values() if item['status'] != 'disabled']
    assert real and all(item['state'] == 'NOT_INSTALLED' for item in real)
    # Found at resolution time but gone at execution time: also NOT_INSTALLED,
    # never a configuration complaint.
    _, _, status, _ = probe(monkeypatch, ProcessResult('unavailable', stderr='Executable not found.'))
    assert status == 'missing'
    states = inventory_states(monkeypatch, ProcessResult('unavailable', stderr='Executable not found.'))
    assert states['nmap']['state'] == 'NOT_INSTALLED'


# --- 3. Missing dependency -> not a policy block -----------------------------

@pytest.mark.parametrize('stderr,exit_code,expected', [
    ("cannot load such file -- whatweb/parser", 1, 'cannot load such file'),
    ('The code execution cannot proceed because httpx.dll was missing.', -1073741515, 'httpx.dll was missing'),
])
def test_missing_dependency_is_not_a_policy_block(monkeypatch, stderr, exit_code, expected):
    _, _, status, reason = probe(monkeypatch, ProcessResult('failed', stderr=stderr, exit_code=exit_code))
    assert status == 'unknown'
    assert status != 'blocked'
    assert expected in reason
    assert f'exit code {exit_code}' in reason


# --- 4. Timeout -> not a policy block ----------------------------------------

def test_timeout_is_unknown_not_policy(monkeypatch):
    _, _, status, reason = probe(monkeypatch, ProcessResult('timed_out'))
    assert status == 'unknown'
    assert 'timed out' in reason
    states = inventory_states(monkeypatch, ProcessResult('timed_out'))
    assert states['nmap']['state'] == 'UNKNOWN'


# --- 5. Ordinary non-zero exit -> not a policy block --------------------------

def test_ordinary_nonzero_exit_is_unknown_not_policy(monkeypatch):
    _, _, status, reason = probe(monkeypatch, ProcessResult('failed', stderr='nmap: directive unknown', exit_code=1))
    assert status == 'unknown'
    assert 'exit code 1' in reason
    assert 'nmap: directive unknown' in reason


# --- 6. Insufficient evidence -> EXECUTION_BLOCKED ----------------------------

@pytest.mark.parametrize('winerror', [5, 193, 225, 4551])
def test_launch_refusal_without_policy_evidence_is_execution_blocked(monkeypatch, winerror):
    """Access denied, bad image and antivirus (225) blocks are plausible but
    unconfirmed: EXECUTION_BLOCKED states the facts without claiming policy."""
    _, _, status, reason = probe(monkeypatch, ProcessResult('failed', stderr='Unable to launch executable.', winerror=winerror))
    assert status == 'execution_blocked'
    assert f'error {winerror}' in reason
    assert 'insufficient' in reason


def test_execution_blocked_state_reaches_the_api(monkeypatch):
    states = inventory_states(monkeypatch, ProcessResult('failed', stderr='Unable to launch executable.', winerror=5))
    assert states['nmap']['state'] == 'EXECUTION_BLOCKED'
    assert states['nmap']['status'] == 'execution_blocked'
    assert states['nmap']['integration_ready'] is False


# --- Over-claim guards --------------------------------------------------------

def test_policy_text_in_stdout_or_success_is_never_a_block():
    # Scanned content can contain the phrases; only failed stderr counts.
    assert policy_block_evidence(ProcessResult('failed', stdout=POLICY_TEXT, stderr='permission denied', exit_code=1)) is None
    assert policy_block_evidence(ProcessResult('completed', stdout=POLICY_TEXT)) is None
    assert policy_block_evidence(ProcessResult('cancelled')) is None
    # A plain permission failure with no OS evidence is not a confirmed block.
    assert policy_block_evidence(ProcessResult('failed', stderr='[Errno 13] Permission denied', exit_code=1)) is None


def test_real_runner_classifies_launch_refusals_without_touching_the_system(monkeypatch):
    from backend.services import process_runner
    def refuse(*args, **kwargs):
        error = OSError('access denied')
        error.winerror = 5
        raise error
    monkeypatch.setattr(process_runner.subprocess, 'Popen', refuse)
    result = process_runner.run(['C:/fake/tool'])
    assert result.state == 'failed' and result.winerror == 5
    assert 'insufficient' in result.stderr and 'C:' not in result.stderr
    def policy(*args, **kwargs):
        error = OSError('policy')
        error.winerror = 1260
        raise error
    monkeypatch.setattr(process_runner.subprocess, 'Popen', policy)
    result = process_runner.run(['C:/fake/tool'])
    assert result.state == 'blocked' and result.winerror == 1260
    assert result.stderr == LAUNCH_BLOCKED


def test_real_child_printing_the_policy_message_is_confirmed_evidence():
    """Genuine runner: a local child emits the Windows message on stderr and
    exits non-zero; the evidence helper must confirm it end to end."""
    result = run([sys.executable, '-c',
                  f'import sys; print({POLICY_TEXT!r}, file=sys.stderr); sys.exit(1)'])
    assert result.state == 'failed' and result.exit_code == 1
    evidence = policy_block_evidence(result)
    assert evidence and 'application control policy' in evidence


# --- Diagnostics stay bounded and free of paths/secrets (task 7) --------------

def test_diagnostics_mask_paths_and_redact_secrets(monkeypatch):
    _, _, status, reason = probe(
        monkeypatch, ProcessResult('failed', stderr=r'C:\Users\Public\httpx.exe: The system cannot find the file specified.', winerror=5))
    assert status == 'execution_blocked'
    assert 'C:' not in reason and 'Users' not in reason
    _, _, status, reason = probe(
        monkeypatch, ProcessResult('failed', stderr=r'crashed in C:\Projects\tool\bin\x.pyc with api_key=abc123', exit_code=2))
    assert status == 'unknown'
    assert 'C:' not in reason and 'abc123' not in reason
    assert 'api_key=[REDACTED]' in reason
    assert len(reason) < 400


# --- Scan-time outcome: confirmed evidence upgrades to BLOCKED_BY_POLICY -----

def test_scan_time_policy_block_reports_blocked_outcome(tmp_path, monkeypatch):
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    _register_target(application, ['port_scan'])
    try:
        monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
        monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
        monkeypatch.setattr('backend.services.scan_service.run',
                            lambda *args, **kwargs: ProcessResult('failed', stderr=POLICY_TEXT, exit_code=1))
        client = application.test_client()
        response = client.post('/api/scans',
                               json={'target': '127.0.0.1', 'profile': 'quick', 'tools': ['nmap'], 'authorized': True},
                               headers=dict(HEADERS, **{'Idempotency-Key': 'policy-block-scan-0001'}))
        assert response.status_code == 202, response.json
        scan = finish(client, response.json['data']['id'])
        execution = scan['executions'][0]
        assert execution['state'] == 'blocked'
        assert execution['outcome'] == 'BLOCKED_BY_POLICY'
        assert 'Confirmed Windows policy block' in execution['error']
        assert 'application control policy' in execution['error']
        # Nothing completed, so the assessment must not claim success.
        assert scan['state'] == 'failed'
    finally:
        application.extensions['scan_manager'].shutdown()
        application.extensions['database'].dispose()


def test_scan_time_ordinary_failure_stays_failed_not_policy(tmp_path, monkeypatch):
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    _register_target(application, ['port_scan'])
    try:
        monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
        monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
        monkeypatch.setattr('backend.services.scan_service.run',
                            lambda *args, **kwargs: ProcessResult('failed', stderr='nmap: bogus argument', exit_code=1))
        client = application.test_client()
        response = client.post('/api/scans',
                               json={'target': '127.0.0.1', 'profile': 'quick', 'tools': ['nmap'], 'authorized': True},
                               headers=dict(HEADERS, **{'Idempotency-Key': 'ordinary-failure-scan-0001'}))
        assert response.status_code == 202, response.json
        scan = finish(client, response.json['data']['id'])
        execution = scan['executions'][0]
        assert execution['state'] == 'failed'
        assert execution['outcome'] == 'FAILED'
        assert 'bogus argument' in execution['error']
        assert scan['state'] == 'failed'
    finally:
        application.extensions['scan_manager'].shutdown()
        application.extensions['database'].dispose()
