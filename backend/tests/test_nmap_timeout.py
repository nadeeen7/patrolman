"""Nmap timeout and partial-result regression tests.

These pin the contract that a sweep which does not finish can never be reported as
a successful assessment with zero open ports. Two independent guards are covered:

* the command asks Nmap for a bounded per-host scan that the shared runner bound
  still outlasts, so the runner cannot cut a slow-but-valid sweep in half; and
* `nmap.parse` rejects a host that is up but has no port result at all, which is
  what Nmap emits when it gives up mid-sweep under `--host-timeout`.

Everything here is a fixture, a mock or an isolated local child process. No
unauthorized target is contacted and no port is scanned outside a test fixture.
"""
import pytest

from backend.app import create_app
from backend.config import Settings
from backend.integrations import nmap
from backend.services.process_runner import ProcessResult, run
from backend.services.scan_service import TERMINAL, TOOL_TIMEOUT
from backend.tests.test_execution import NMAP, FIXTURES
from backend.tests.test_workflow import HEADERS, TOKEN, finish

# Emitted when Nmap gives up on a host before the port stage: the host is up and
# there is no <ports> element at all (captured from a real 60s host timeout).
ABORTED = ('<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sT 127.0.0.1">'
           '<scaninfo type="connect" protocol="tcp" numservices="29" services="8000"/>'
           '<host starttime="1" endtime="63"><status state="up" reason="user-set" reason_ttl="0"/>'
           '<address addr="127.0.0.1" addrtype="ipv4"/><hostnames></hostnames></host>'
           '<runstats><finished time="63" timestr="x" elapsed="63.27" summary="Nmap done" exit="success"/></runstats></nmaprun>')
# A sweep that really finished and genuinely found nothing open: <ports> exists and
# only <extraports> is reported.
NO_PORTS = ('<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sT 127.0.0.1">'
            '<host starttime="1" endtime="2"><status state="up" reason="user-set" reason_ttl="0"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/><ports>'
            '<extraports state="closed" count="29"><extrareasons reason="resets" count="29"/></extraports>'
            '</ports></host>'
            '<runstats><finished time="2" timestr="x" elapsed="1.2" summary="Nmap done" exit="success"/></runstats></nmaprun>')


# --- 1. Timeout configuration -------------------------------------------------

@pytest.mark.parametrize('profile,ports', [('quick', '80,443,8000,8443'),
                                           ('standard', nmap.PORTS['standard']),
                                           ('comprehensive', nmap.PORTS['comprehensive'])])
def test_command_bounds_the_sweep_within_the_runner_bound(profile, ports, tmp_path):
    """Nmap's own per-host bound must expire before the shared runner bound does."""
    argv = nmap.command('C:/tools/nmap.exe', '127.0.0.1', profile, tmp_path / 'out.xml')
    assert argv[:2] == ['C:/tools/nmap.exe', '-sT']
    for flag in ('-Pn', '-n', '--max-retries', '1', '--host-timeout', '-p', '-oX'):
        assert flag in argv, flag
    host_timeout = int(argv[argv.index('--host-timeout') + 1].rstrip('s'))
    assert host_timeout == 120
    # The runner bound must outlast the host bound, or a valid slow sweep is killed
    # mid-flight and its results are lost.
    assert host_timeout < TOOL_TIMEOUT
    assert argv[argv.index('-p') + 1] == ports
    assert '8080' not in ports
    assert argv[-1] == '127.0.0.1'
    # IPv6 targets get the -6 switch and still carry the same bounds.
    argv6 = nmap.command('C:/tools/nmap.exe', '::1', profile, tmp_path / 'out.xml')
    assert '-6' in argv6 and '--host-timeout' in argv6


def test_runner_enforces_its_own_timeout_on_a_sleeping_child():
    """The shared runner independently bounds execution, independent of Nmap's flag."""
    import sys
    result = run([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.3)
    assert result.state == 'timed_out'
    # The bound is enforced by killing the child, so it never reports a clean zero exit.
    assert result.exit_code != 0


# --- 2. An interrupted sweep is never a zero-port success ---------------------

def test_interrupted_sweep_raises_instead_of_reporting_no_open_ports():
    """A host that is up with no <ports> element is an incomplete sweep, not a clean one."""
    with pytest.raises(ValueError, match='did not finish the port sweep'):
        nmap.parse(ABORTED, '127.0.0.1')


def test_host_timeout_flag_is_still_rejected():
    """Nmap's explicit timedout marker is rejected as before."""
    timed_out = ABORTED.replace('<host starttime="1" endtime="63">', '<host starttime="1" endtime="63" timedout="true">')
    with pytest.raises(ValueError, match='timed out'):
        nmap.parse(timed_out, '127.0.0.1')


def test_completed_sweep_with_zero_open_ports_is_distinguishable():
    """A genuinely finished sweep with nothing open parses cleanly and yields no ports."""
    result = nmap.parse(NO_PORTS, '127.0.0.1')
    assert not result.findings
    assert [asset['kind'] for asset in result.assets] == ['host']
    assert all(asset['details'].get('port') is None for asset in result.assets)


def test_failed_sweep_is_not_silently_successful():
    """An Nmap run that reports failure cannot be parsed as a successful assessment."""
    broken = ABORTED.replace('exit="success"', 'exit="error"')
    with pytest.raises(ValueError, match='successful completion'):
        nmap.parse(broken, '127.0.0.1')


# --- 3. The honest status reaches orchestration ------------------------------

def _scan_with_nmap_result(tmp_path, monkeypatch, result):
    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/nmap')
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    monkeypatch.setattr('backend.services.scan_service.run', lambda *args, **kwargs: result)
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    app.config['TESTING'] = True
    from datetime import datetime, timedelta, timezone
    from sqlalchemy.orm import Session
    from backend.models import AuthorizedTarget
    now = datetime.now(timezone.utc)
    with Session(app.extensions['database']) as session:
        session.add(AuthorizedTarget(
            name='Loopback Nmap Target', target_type='internal_system',
            owner_organization='Test Harness', scope_domains=['127.0.0.1'],
            explicit_subdomains=[], excluded_scope=[],
            permitted_methods=['port_scan'],
            prohibited_methods=['dos', 'exploit'], rate_limit_rps=10,
            valid_from=now - timedelta(days=1), valid_to=now + timedelta(days=30),
            evidence_reference='NMAP-TIMEOUT-AUTH-2026', status='active',
            created_by='admin', updated_by='admin',
        ))
        session.commit()
    try:
        client = app.test_client()
        created = client.post('/api/scans', json={'target': '127.0.0.1', 'profile': 'comprehensive',
            'tools': ['nmap'], 'authorized': True}, headers=dict(HEADERS, **{'Idempotency-Key': 'nmap-timeout-scan-1'}))
        assert created.status_code == 202, created.json
        return client, finish(client, created.json['data']['id'])
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_incomplete_sweep_is_reported_as_failed_not_as_an_empty_assessment(tmp_path, monkeypatch):
    """The interrupted XML must surface as a failure, never as zero findings.

    Only Nmap is selected, so nothing can be reported as successful and the whole
    scan fails honestly instead of appearing to have finished cleanly.
    """
    client, data = _scan_with_nmap_result(tmp_path, monkeypatch, ProcessResult('completed', ABORTED, exit_code=0))
    execution = data['executions'][0]
    assert execution['state'] == 'failed'
    assert execution['outcome'] == 'FAILED'
    assert execution['error'] == 'Unsupported or malformed nmap output (ValueError).'
    assert data['state'] == 'failed'
    assert data['state'] in TERMINAL
    assert data['findings'] == []
    assert data['assets'] == []
    assert 'nmap' in data['coverage']['untested_or_incomplete']


def test_runner_timeout_is_reported_as_timed_out(tmp_path, monkeypatch):
    """A sweep the runner had to kill is TIMED_OUT, and the scan is not successful."""
    client, data = _scan_with_nmap_result(tmp_path, monkeypatch,
        ProcessResult('timed_out', stderr='killed', exit_code=None))
    execution = data['executions'][0]
    assert execution['state'] == 'timed_out'
    assert execution['outcome'] == 'TIMED_OUT'
    assert data['state'] == 'failed'
    assert data['assets'] == []


def test_policy_block_evidence_wins_over_a_plain_timeout(tmp_path, monkeypatch):
    """Confirmed Windows policy evidence still reports BLOCKED_BY_POLICY."""
    blocked = ProcessResult('failed', stderr='An Application Control policy has blocked this file', exit_code=1)
    client, data = _scan_with_nmap_result(tmp_path, monkeypatch, blocked)
    execution = data['executions'][0]
    assert execution['state'] == 'blocked' and execution['outcome'] == 'BLOCKED_BY_POLICY'


# --- 4. Existing Nmap behaviour is unchanged ---------------------------------

def test_completed_fixture_sweep_still_yields_port_assets(tmp_path):
    """The ordinary successful path is untouched by the new guard."""
    result = nmap.parse(NMAP, '127.0.0.1')
    ports = [asset['details'].get('port') for asset in result.assets if asset['kind'] == 'port']
    assert ports == [8000]
    assert [asset['kind'] for asset in result.assets] == ['host', 'port']
    assert not result.findings
    assert nmap.parse(FIXTURES['nmap'], '127.0.0.1').assets


def test_entities_and_out_of_scope_hosts_are_still_rejected():
    with pytest.raises(ValueError, match='XML entities prohibited'):
        nmap.parse('<!ENTITY x "y">' + NMAP, '127.0.0.1')
    foreign = NMAP.replace('addr="127.0.0.1"', 'addr="192.168.1.9"')
    with pytest.raises(ValueError, match='out-of-scope host'):
        nmap.parse(foreign, '127.0.0.1')
