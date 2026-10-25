"""Wapiti integration: contracts, safety gates and a local end-to-end lab run.

No public or third-party system is contacted. The end-to-end test serves an
intentionally vulnerable application on loopback and executes a stub Wapiti
process that emits a Wapiti-shaped JSON report for that loopback URL, so the
real command construction, process execution, report parsing and persistence
path is exercised without requiring the scanner to be installed.
"""
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.integrations import wapiti
from backend.models import AuthorizedTarget
from backend.integrations.base import Results, asset
from backend.services.executables import find_argv
from backend.services.process_runner import ProcessResult, run
from backend.services.results import SEVERITIES, deduplicate
from backend.services.scan_service import TERMINAL
from backend.services.tool_manager import diagnose, inventory, verify
from backend.tests.test_execution import NMAP

TOKEN = 'wapiti-test-token-' + 'w' * 32
HEADERS = {'Authorization': 'Bearer ' + TOKEN}


def register_loopback_target(engine, host='127.0.0.1'):
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        target = AuthorizedTarget(
            name='Wapiti Loopback Lab', target_type='internal_system',
            owner_organization='Test Harness', scope_domains=[host],
            explicit_subdomains=[], excluded_scope=[],
            permitted_methods=['port_scan', 'web_service_discovery', 'vulnerability_check'],
            prohibited_methods=['dos', 'exploit'], rate_limit_rps=10,
            valid_from=now - timedelta(days=1), valid_to=now + timedelta(days=30),
            evidence_reference='WAPITI-AUTH-2026', status='active',
            created_by='admin', updated_by='admin',
        )
        session.add(target)
        session.commit()
        return target.id


def finish(client, scan_id, timeout_seconds=20):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        response = client.get('/api/scans/' + scan_id, headers=HEADERS)
        if response.json['data']['state'] in TERMINAL:
            return response.json['data']
        time.sleep(.05)
    pytest.fail('Scan did not finish')


def report(target='http://127.0.0.1:8000/', **overrides):
    host = urlsplit(target).netloc
    document = {
        'classifications': {
            'Cross Site Scripting': {'desc': 'Input is reflected without encoding.',
                                     'sol': 'Encode output for the correct context.',
                                     'ref': ['https://owasp.org/www-community/attacks/xss/']},
            'Security Headers': {'desc': 'A security header is missing.', 'sol': 'Add the missing header.',
                                 'ref': ['https://owasp.org/www-project-secure-headers/']},
        },
        'vulnerabilities': {
            'Cross Site Scripting': [
                {'level': 3, 'parameter': 'name', 'method': 'GET', 'path': '/?name=<script>alert(1)</script>',
                 'referer': target, 'module': 'xss', 'info': 'Unescaped reflection in the page body',
                 'wstg': ['WSTG-INPV-01'],
                 'http_request': f'GET /?name=<script>alert(1)</script> HTTP/1.1\nHost: {host}\n',
                 'curl_command': f'curl "{target}?name=<script>alert(1)</script>"'},
                # An exact duplicate, as Wapiti can emit for one request.
                {'level': 3, 'parameter': 'name', 'method': 'GET', 'path': '/?name=<script>alert(1)</script>',
                 'referer': target, 'module': 'xss', 'info': 'Unescaped reflection in the page body',
                 'wstg': ['WSTG-INPV-01'],
                 'http_request': f'GET /?name=<script>alert(1)</script> HTTP/1.1\nHost: {host}\n',
                 'curl_command': f'curl "{target}?name=<script>alert(1)</script>"'},
            ],
            'Security Headers': [
                {'level': 1, 'parameter': '', 'method': 'GET', 'path': '/', 'referer': '', 'module': 'http_headers',
                 'info': 'X-Frame-Options header is missing', 'wstg': ['WSTG-CONF-07'],
                 'http_request': f'GET / HTTP/1.1\nHost: {host}\n', 'curl_command': f'curl "{target}"'},
            ],
        },
        'anomalies': {'Timeout': [{'level': 0, 'module': 'http_headers', 'path': '/slow'}]},
        'additionals': {},
        'infos': {'target': target, 'version': '3.3.2', 'scope': 'url', 'crawled_pages_nbr': 1,
                  'auth': {'type': None}, 'detailed_report_level': 0},
        'suppressed_findings': {},
    }
    document.update(overrides)
    return json.dumps(document)


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('text,expected', [
    ('3.3.2\n', '3.3.2'),
    ('Wapiti 3.3.2', '3.3.2'),
    ('Wapiti version 3.3.2 (Python 3.13.1)', '3.3.2'),
    ('wapiti3 3.1.8', '3.1.8'),
    ('\x1b[32m3.3.2\x1b[0m', '3.3.2'),
    ('3.4', '3.4'),
])
def test_version_output_is_parsed(text, expected):
    assert wapiti.parse_version(text) == expected
    assert wapiti.matches_identity(text) is True


@pytest.mark.parametrize('text', ['', 'not installed', 'urllib3 2.2.1', '3', 'wapiti', None, 3.3])
def test_non_version_output_is_rejected(text):
    assert wapiti.parse_version(text) is None
    assert wapiti.matches_identity(text) is False


# ---------------------------------------------------------------------------
# Argument construction
# ---------------------------------------------------------------------------

def option(argv, name):
    return argv[argv.index(name) + 1]


def test_command_is_bounded_explicit_and_offline(monkeypatch):
    monkeypatch.delenv('AVA_WAPITI_MODULES', raising=False)
    argv = wapiti.command(['wapiti'], 'http://127.0.0.1:8000', 'comprehensive', '/tmp/result.json')
    assert argv[:3] == ['wapiti', '-u', 'http://127.0.0.1:8000/']
    assert option(argv, '--scope') == 'url'
    assert option(argv, '-m') == ','.join(wapiti.DEFAULT_MODULES)
    assert option(argv, '-l') == '1'
    assert option(argv, '-f') == 'json'
    assert option(argv, '-o') == '/tmp/result.json'
    assert option(argv, '-S') == 'paranoid'
    assert option(argv, '--tasks') == '1'
    assert option(argv, '--max-scan-time') == '120'
    assert option(argv, '--max-attack-time') == '60'
    assert option(argv, '-t') == '10'
    assert '--flush-session' in argv and '--no-bugreport' in argv
    # No implicit module expansion and no external out-of-band endpoint.
    assert not {'all', 'common'} & set(argv)
    assert '--endpoint' not in argv and '-p' not in argv


def test_command_prefix_supports_a_script_interpreter(tmp_path):
    argv = wapiti.command([sys.executable, str(tmp_path / 'wapiti.py')], 'http://127.0.0.1:8000',
                          'comprehensive', tmp_path / 'result.json')
    assert argv[:2] == [sys.executable, str(tmp_path / 'wapiti.py')]
    assert option(argv, '-u') == 'http://127.0.0.1:8000/'


def test_module_selection_is_explicit_and_bounded(monkeypatch):
    monkeypatch.setenv('AVA_WAPITI_MODULES', 'xss,sql')
    assert option(wapiti.command(['wapiti'], 'http://127.0.0.1:8000', 'comprehensive', 'out'), '-m') == 'xss,sql'
    for setting in ('all', 'common', 'ssrf', 'brute_login_form', 'wapp', 'not-a-module'):
        monkeypatch.setenv('AVA_WAPITI_MODULES', setting)
        issue = wapiti.configuration_error()
        assert issue and 'Supported modules' in issue, setting
        with pytest.raises(ValueError):
            wapiti.command(['wapiti'], 'http://127.0.0.1:8000', 'comprehensive', 'out')
    monkeypatch.setenv('AVA_WAPITI_MODULES', '')
    assert wapiti.enabled_modules() == wapiti.DEFAULT_MODULES


def test_scan_force_and_deadlines_are_bounded(monkeypatch):
    for variable, value in [('AVA_WAPITI_SCAN_FORCE', 'aggressive'), ('AVA_WAPITI_SCAN_FORCE', 'insane'),
                            ('AVA_WAPITI_SCAN_FORCE', 'normal'),
                            ('AVA_WAPITI_MAX_SCAN_TIME', '900'), ('AVA_WAPITI_MAX_SCAN_TIME', '5'),
                            ('AVA_WAPITI_MAX_SCAN_TIME', 'soon'),
                            ('AVA_WAPITI_MAX_ATTACK_TIME', '0'),
                            ('AVA_WAPITI_HTTP_TIMEOUT', '0'), ('AVA_WAPITI_HTTP_TIMEOUT', '-1')]:
        monkeypatch.setenv(variable, value)
        assert wapiti.configuration_error(), (variable, value)
        with pytest.raises(ValueError):
            wapiti.command(['wapiti'], 'http://127.0.0.1:8000', 'comprehensive', 'out')
        monkeypatch.delenv(variable)
    monkeypatch.setenv('AVA_WAPITI_SCAN_FORCE', 'sneaky')
    monkeypatch.setenv('AVA_WAPITI_MAX_SCAN_TIME', '30')
    monkeypatch.setenv('AVA_WAPITI_MAX_ATTACK_TIME', '15')
    monkeypatch.setenv('AVA_WAPITI_HTTP_TIMEOUT', '3')
    assert wapiti.configuration_error() is None
    argv = wapiti.command(['wapiti'], 'http://127.0.0.1:8000', 'comprehensive', 'out')
    assert option(argv, '-S') == 'sneaky' and option(argv, '--max-scan-time') == '30'
    assert option(argv, '--max-attack-time') == '15' and option(argv, '-t') == '3'


# ---------------------------------------------------------------------------
# Target validation (SSRF hardening)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('value', [
    'http://localhost:8000', 'http://LOCALHOST:8000', 'http://127.1:8000', 'http://2130706433',
    'http://0177.0.0.1:8000', 'http://example.com', 'http://127.0.0.1.nip.io:8000',
    'http://127.0.0.1@example.com', 'http://user:pass@127.0.0.1:8000', 'http://127.0.0.1:8000/#fragment',
    'http://127.0.0.1:8000/?q=1', 'http://[::ffff:127.0.0.1]:8000', 'http://0.0.0.0:8000',
    'http://169.254.169.254/', 'http://224.0.0.1/', 'http://127.0.0.1:99999', 'http://127.0.0.1:0',
    'file:///etc/passwd', 'ftp://127.0.0.1/', 'http://127.0.0.1:8000/../../etc/passwd',
    'http://127.0.0.1:8000/a b', 'http://8.8.8.8/', 'gopher://127.0.0.1:8000',
])
def test_target_validation_rejects_ssrf_spellings(value):
    with pytest.raises(ValueError):
        wapiti.validate_scan_url(value)
    with pytest.raises(ValueError):
        wapiti.command(['wapiti'], value, 'comprehensive', 'out')


@pytest.mark.parametrize('value', ['http://127.0.0.1:8000', 'https://127.0.0.1', 'http://[::1]:8000',
                                   'http://127.0.0.1:8000/app'])
def test_target_validation_accepts_loopback(value):
    assert wapiti.validate_scan_url(value)


def test_non_loopback_requires_explicit_operator_opt_in(monkeypatch):
    with pytest.raises(ValueError, match='AVA_WAPITI_ALLOW_REMOTE_TARGETS'):
        wapiti.validate_scan_url('http://192.168.1.10:8000')
    monkeypatch.setenv('AVA_WAPITI_ALLOW_REMOTE_TARGETS', 'true')
    assert wapiti.validate_scan_url('http://192.168.1.10:8000')


# ---------------------------------------------------------------------------
# Result parsing and normalization
# ---------------------------------------------------------------------------

def test_report_parsing_normalizes_findings_and_deduplicates():
    parsed = wapiti.parse(report(), 'http://127.0.0.1:8000')
    findings = deduplicate(parsed.findings)
    assert {finding['title'] for finding in findings} == {'Cross Site Scripting', 'Security Headers'}
    xss = next(finding for finding in findings if finding['title'] == 'Cross Site Scripting')
    assert xss['severity'] == 'high'
    assert xss['target'] == 'http://127.0.0.1:8000/?name=<script>alert(1)</script>'
    assert xss['sources'][0]['tool'] == 'wapiti'
    assert xss['sources'][0]['evidence']['module'] == 'xss'
    assert xss['sources'][0]['evidence']['parameter'] == 'name'
    assert 'Unescaped reflection' in xss['sources'][0]['evidence']['info']
    assert xss['sources'][0]['evidence']['wstg'] == ['WSTG-INPV-01']
    assert xss['sources'][0]['remediation'] == 'Encode output for the correct context.'
    assert xss['sources'][0]['description'] == 'Input is reflected without encoding.'
    headers = next(finding for finding in findings if finding['title'] == 'Security Headers')
    assert headers['severity'] == 'low'
    assert headers['target'] == 'http://127.0.0.1:8000/'
    assert any(asset['kind'] == 'wapiti_anomaly' for asset in parsed.assets)


@pytest.mark.parametrize('level,severity', [(0, 'informational'), (1, 'low'), (2, 'medium'),
                                            (3, 'high'), (4, 'critical'), (9, 'unknown'), ('3', 'unknown')])
def test_severity_levels_are_mapped_strictly(level, severity):
    document = json.loads(report())
    document['vulnerabilities']['Security Headers'][0]['level'] = level
    parsed = wapiti.parse(json.dumps(document), 'http://127.0.0.1:8000')
    headers = next(item for item in parsed.findings if item['title'] == 'Security Headers')
    assert headers['severity'] == severity


@pytest.mark.parametrize('text', ['not json', '[]', '{}', 'null', '{"vulnerabilities": []}',
                                  '{"vulnerabilities": {"X": "not a list"}}'])
def test_malformed_reports_fail_closed(text):
    with pytest.raises(ValueError):
        wapiti.parse(text, 'http://127.0.0.1:8000')


def test_out_of_scope_report_target_request_and_referer_are_rejected():
    base = 'http://127.0.0.1:8000'
    document = json.loads(report())
    document['infos']['target'] = 'http://127.0.0.2:8000'
    with pytest.raises(ValueError, match='scope'):
        wapiti.parse(json.dumps(document), base)

    document = json.loads(report())
    document['vulnerabilities']['Security Headers'][0]['http_request'] = \
        'GET / HTTP/1.1\nHost: 127.0.0.2:8000\n'
    with pytest.raises(ValueError, match='scope'):
        wapiti.parse(json.dumps(document), base)

    document = json.loads(report())
    document['vulnerabilities']['Security Headers'][0]['referer'] = 'http://127.0.0.2/'
    with pytest.raises(ValueError, match='scope'):
        wapiti.parse(json.dumps(document), base)

    document = json.loads(report())
    document['vulnerabilities']['Security Headers'][0]['http_request'] = \
        'GET http://127.0.0.2/ HTTP/1.1\nHost: 127.0.0.1:8000\n'
    with pytest.raises(ValueError, match='absolute-form'):
        wapiti.parse(json.dumps(document), base)


def test_unusable_entries_are_counted_not_trusted():
    document = json.loads(report())
    document['vulnerabilities']['Security Headers'].append('not an entry')
    document['vulnerabilities']['Security Headers'].append({'module': 'http_headers', 'path': 'relative'})
    document['vulnerabilities']['Broken'] = 'not a list'
    parsed = wapiti.parse(json.dumps(document), 'http://127.0.0.1:8000')
    assert len(parsed.findings) == 2
    issues = [asset for asset in parsed.assets if asset['kind'] == 'wapiti_report_issue']
    assert issues and issues[0]['details']['skipped_entries'] == 3


def test_secrets_in_report_evidence_are_redacted():
    document = json.loads(report())
    entry = document['vulnerabilities']['Cross Site Scripting'][0]
    entry['http_request'] = ('GET /?name=1 HTTP/1.1\nHost: 127.0.0.1:8000\n'
                             'Authorization: Bearer SYNTHBEARER123\nCookie: sid=SYNTHCOOKIE123\n')
    entry['info'] = 'leaked api_key=SYNTHAPIKEY123 and password=SYNTHPASSWORD123'
    serialized = json.dumps(deduplicate(wapiti.parse(json.dumps(document), 'http://127.0.0.1:8000').findings))
    for secret in ('SYNTHBEARER123', 'SYNTHCOOKIE123', 'SYNTHAPIKEY123', 'SYNTHPASSWORD123'):
        assert secret not in serialized
    assert '[REDACTED]' in serialized


# ---------------------------------------------------------------------------
# Installation detection, version verification and status reporting
# ---------------------------------------------------------------------------

def wapiti_help():
    return 'usage: wapiti [-h] [' + '] ['.join(wapiti.HELP_FLAGS) + ']'


def test_missing_wapiti_is_reported_as_not_installed(monkeypatch):
    monkeypatch.setattr('backend.services.tool_manager.find_argv', lambda commands: None)
    monkeypatch.setattr('backend.services.tool_manager.local_candidate', lambda commands: None)
    monkeypatch.delenv('AVA_WAPITI_PATH', raising=False)
    entry = next(item for item in inventory(True) if item['name'] == 'wapiti')
    assert entry['status'] == 'missing'
    assert entry['state'] == 'NOT_INSTALLED'
    assert entry['executable_found'] is False
    assert entry['capabilities'] == list(wapiti.CAPABILITIES)


def test_installed_wapiti_is_safety_disabled_until_opted_in(monkeypatch):
    monkeypatch.setattr('backend.services.tool_manager.find_argv', lambda commands: '/opt/wapiti')
    monkeypatch.setattr('backend.services.tool_manager.local_candidate', lambda commands: None)
    monkeypatch.delenv('AVA_WAPITI_ENABLED', raising=False)

    def probe(argv, **kwargs):
        if '--version' in argv:
            return ProcessResult('completed', '3.3.2\n', exit_code=0)
        return ProcessResult('completed', wapiti_help(), exit_code=0)

    monkeypatch.setattr('backend.services.tool_manager.run', probe)
    entry = next(item for item in inventory(True) if item['name'] == 'wapiti')
    assert entry['status'] == 'disabled'
    assert entry['state'] == 'DISABLED_FOR_SAFETY'
    assert entry['version'] == '3.3.2'
    assert entry['operator_opt_in']['status'] == 'disabled'
    assert entry['operator_opt_in']['variable'] == 'AVA_WAPITI_ENABLED'
    assert 'disabled' in entry['reason'].lower()

    monkeypatch.setenv('AVA_WAPITI_ENABLED', 'true')
    entry = next(item for item in inventory(True) if item['name'] == 'wapiti')
    assert entry['status'] == 'ready'
    assert entry['state'] == 'READY'
    assert entry['operator_opt_in']['status'] == 'enabled'
    assert entry['runtime_configuration']['status'] == 'configured'


def test_invalid_module_configuration_is_reported_without_launching(monkeypatch):
    monkeypatch.setattr('backend.services.tool_manager.find_argv', lambda commands: '/opt/wapiti')
    monkeypatch.setattr('backend.services.tool_manager.local_candidate', lambda commands: None)
    monkeypatch.setenv('AVA_WAPITI_ENABLED', 'true')
    monkeypatch.setenv('AVA_WAPITI_MODULES', 'ssrf')

    def probe(argv, **kwargs):
        return ProcessResult('completed', '3.3.2\n' if '--version' in argv else wapiti_help(), exit_code=0)

    monkeypatch.setattr('backend.services.tool_manager.run', probe)
    entry = next(item for item in inventory(True) if item['name'] == 'wapiti')
    assert entry['status'] == 'configuration_required'
    assert entry['state'] == 'CONFIGURATION_REQUIRED'
    assert 'Supported modules' in entry['reason']


def test_unsupported_cli_option_fails_version_verification(monkeypatch):
    monkeypatch.setattr('backend.services.tool_manager.run',
                        lambda argv, **kwargs: ProcessResult('completed', '3.3.2\n' if '--version' in argv
                                                             else 'usage: wapiti [-h] [-u URL]', exit_code=0))
    valid, version, status, reason = diagnose('wapiti', '/opt/wapiti')
    assert valid is False and version is None and status == 'unverified'
    assert 'verification failed' in reason.lower()


# ---------------------------------------------------------------------------
# Orchestration states (timeout, cancellation, opted-in execution)
# ---------------------------------------------------------------------------

@pytest.fixture
def wapiti_app(tmp_path, monkeypatch):
    monkeypatch.setenv('AVA_WAPITI_ENABLED', 'true')
    monkeypatch.delenv('AVA_WAPITI_MODULES', raising=False)
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    register_loopback_target(application.extensions['database'])
    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, '3.3.2'))
    yield application
    application.extensions['scan_manager'].shutdown()
    application.extensions['database'].dispose()


def create_wapiti_scan(client, key='wapiti-orchestration-key-01'):
    payload = {'target': '127.0.0.1', 'profile': 'comprehensive',
               'tools': ['nmap', 'httpx', 'wapiti'], 'authorized': True}
    return client.post('/api/scans', json=payload, headers=dict(HEADERS, **{'Idempotency-Key': key}))


@pytest.mark.parametrize('state', ['timed_out', 'cancelled'])
def test_scan_records_wapiti_timeout_and_cancellation(wapiti_app, monkeypatch, state):
    def runner(argv, **kwargs):
        name = Path(argv[0]).name
        if name == 'nmap':
            return ProcessResult('completed', NMAP, exit_code=0)
        if name == 'httpx':
            return ProcessResult('completed', '{"url":"http://127.0.0.1:8000","status_code":200}', exit_code=0)
        return ProcessResult(state, stderr='fixture', exit_code=None)

    monkeypatch.setattr('backend.services.scan_service.run', runner)
    client = wapiti_app.test_client()
    response = create_wapiti_scan(client)
    assert response.status_code == 202, response.json
    result = finish(client, response.json['data']['id'])
    execution = next(item for item in result['executions'] if item['tool'] == 'wapiti')
    assert execution['state'] == state
    assert result['findings'] == []
    assert result['state'] != 'completed'


# ---------------------------------------------------------------------------
# End-to-end local lab: real process + real parser against a vulnerable app
# ---------------------------------------------------------------------------

class VulnerableLab(BaseHTTPRequestHandler):
    """Intentionally vulnerable: reflects an unescaped parameter, no headers."""

    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        reflected = query.get('name', [''])[0]
        body = ('<html><head><title>PATROLMAN vulnerable lab</title></head><body>'
                f'<h1>Hello {reflected}</h1></body></html>')
        payload = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


STUB = '''
import json, sys, urllib.request

args = sys.argv[1:]


def option(name):
    return args[args.index(name) + 1]


url = option('-u')
output = option('-o')
modules = option('-m')
page = urllib.request.urlopen(url, timeout=5).read().decode('utf-8', 'replace')
host = url.split('://', 1)[1]
assert 'xss' not in modules and 'http_headers' in modules, modules
findings = {
    'Cross Site Scripting': [{
        'level': 3, 'parameter': 'name', 'method': 'GET',
        'path': '/?name=<script>alert(1)</script>', 'referer': url, 'module': 'xss',
        'info': 'The parameter value is reflected unescaped: ' + page[:60],
        'wstg': ['WSTG-INPV-01'],
        'http_request': 'GET /?name=<script>alert(1)</script> HTTP/1.1\\nHost: ' + host + '\\n',
        'curl_command': 'curl "' + url + '?name=<script>alert(1)</script>"',
    }],
    'Content Security Policy Configuration': [{
        'level': 1, 'parameter': '', 'method': 'GET', 'path': '/', 'referer': '', 'module': 'http_headers',
        'info': 'No Content-Security-Policy header was returned', 'wstg': ['WSTG-CONF-12'],
        'http_request': 'GET / HTTP/1.1\\nHost: ' + host + '\\n', 'curl_command': 'curl "' + url + '"',
    }],
}
document = {
    'classifications': {
        'Cross Site Scripting': {'desc': 'Reflected input is echoed unescaped.', 'sol': 'Encode output.',
                                 'ref': ['https://owasp.org/www-community/attacks/xss/']},
        'Content Security Policy Configuration': {'desc': 'No CSP header.', 'sol': 'Add a CSP header.',
                                                  'ref': []},
    },
    'vulnerabilities': findings,
    'anomalies': {},
    'additionals': {},
    'infos': {'target': url, 'version': '3.3.2', 'scope': 'url', 'crawled_pages_nbr': 1,
              'auth': {'type': None}, 'detailed_report_level': 0},
    'suppressed_findings': {},
}
with open(output, 'w', encoding='utf-8') as handle:
    json.dump(document, handle)
'''


def test_end_to_end_local_vulnerable_application(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(('127.0.0.1', 0), VulnerableLab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    url = f'http://127.0.0.1:{port}'
    stub = tmp_path / 'wapiti_stub.py'
    stub.write_text(STUB, encoding='utf-8')
    monkeypatch.setenv('AVA_WAPITI_ENABLED', 'true')
    monkeypatch.delenv('AVA_WAPITI_MODULES', raising=False)
    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    register_loopback_target(application.extensions['database'])
    monkeypatch.setattr('backend.services.scan_service.find_argv',
                        lambda commands: [sys.executable, str(stub)] if commands[0] == 'wapiti'
                        else '/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, '3.3.2'))
    # The lab listens on an OS-assigned port while the Nmap fixture advertises
    # 8000; this test-only parser substitute hands the discovered web service
    # the lab's real URL. Everything after discovery is the real Wapiti path.
    monkeypatch.setattr('backend.integrations.httpx_scanner.parse',
                        lambda text, target: Results(assets=[asset(url, 'web', status_code=200, source='httpx')]))

    def router(argv, **kwargs):
        if len(argv) > 1 and argv[0] == sys.executable and argv[1] == str(stub):
            # The real runner executes the stub, which really requests the lab.
            return run(argv, **kwargs)
        name = Path(argv[0]).name
        if name == 'nmap':
            # The fixture advertises port 8000, which is the discovery rule the
            # orchestrator applies before any web tool is offered a destination.
            return ProcessResult('completed', NMAP, exit_code=0)
        if name == 'httpx':
            return ProcessResult('completed', json.dumps({'url': url, 'status_code': 200}), exit_code=0)
        raise AssertionError(name)

    monkeypatch.setattr('backend.services.scan_service.run', router)
    try:
        client = application.test_client()
        response = create_wapiti_scan(client, 'wapiti-local-lab-key-01')
        assert response.status_code == 202, response.json
        result = finish(client, response.json['data']['id'], timeout_seconds=60)
        execution = next(item for item in result['executions'] if item['tool'] == 'wapiti')
        assert execution['state'] == 'completed', (execution, result)
        assert execution['version'] == '3.3.2'
        findings = [item for item in result['findings'] if item['details']['source_tool'] == 'wapiti']
        titles = {item['title'] for item in findings}
        assert titles == {'Cross Site Scripting', 'Content Security Policy Configuration'}
        xss = next(item for item in findings if item['title'] == 'Cross Site Scripting')
        assert xss['severity'] == 'high'
        assert xss['details']['target'].startswith(url)
        assert xss['details']['evidence']['parameter'] == 'name'
        assert xss['details']['sources'][0]['remediation'] == 'Encode output.'
        html = client.get(f"/api/scans/{result['id']}/report", headers=HEADERS).text
        assert 'Cross Site Scripting' in html and 'Encode output.' in html
    finally:
        application.extensions['scan_manager'].shutdown()
        application.extensions['database'].dispose()
        server.shutdown()
        server.server_close()
        thread.join()


# ---------------------------------------------------------------------------
# Genuine installation: real Wapiti against the local vulnerable lab
# ---------------------------------------------------------------------------

def test_genuine_wapiti_scan_of_local_vulnerable_application(tmp_path, monkeypatch):
    """Run the installed Wapiti against a loopback lab and parse its real report.

    Skipped when Wapiti is not installed; never contacts a non-loopback
    destination. The adapter's own bounded command is executed verbatim through
    the shared runner, so the real CLI, the real JSON schema and the real
    parser are all exercised together.
    """
    executable = find_argv(wapiti.COMMANDS)
    if not executable:
        pytest.skip('Genuine Wapiti binary is not installed.')
    valid, version = verify('wapiti', executable)
    if not valid or not version:
        pytest.fail('Installed Wapiti identity check failed.')
    assert wapiti.parse_version(version)
    monkeypatch.setenv('AVA_WAPITI_ENABLED', 'true')
    monkeypatch.delenv('AVA_WAPITI_MODULES', raising=False)
    # Keep the genuine run short and bounded inside the documented bounds.
    monkeypatch.setenv('AVA_WAPITI_MAX_SCAN_TIME', '30')
    monkeypatch.setenv('AVA_WAPITI_MAX_ATTACK_TIME', '10')
    monkeypatch.setenv('AVA_WAPITI_HTTP_TIMEOUT', '5')

    server = ThreadingHTTPServer(('127.0.0.1', 0), VulnerableLab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    output = tmp_path / 'wapiti.json'
    try:
        argv = wapiti.command(executable, url, 'comprehensive', output)
        result = run(argv, timeout=180, max_output=2_000_000, cwd=str(tmp_path),
                     output_files=(output,))
        assert result.state == 'completed', (result.state, result.exit_code,
                                             result.stderr[-1500:])
        assert output.is_file(), 'Wapiti completed without writing its JSON report.'
        parsed = wapiti.parse(output.read_text(encoding='utf-8'), url)
        findings = deduplicate(parsed.findings)
        # The lab intentionally lacks CSP, X-Frame-Options and friends, so the
        # default response-inspection modules must report at least one issue.
        assert findings, 'Genuine Wapiti reported no findings for the vulnerable lab.'
        for item in findings:
            assert item['severity'] in SEVERITIES
            assert item['target'].startswith(url)
            source = item['sources'][0]
            assert source['tool'] == 'wapiti'
            assert source['evidence'].get('module')
            assert source['evidence'].get('request')
        assert any(source.get('remediation') for item in findings
                   for source in item['sources']), \
            'Classification metadata (remediation) was not preserved from the real report.'
        assert any(source.get('description') for item in findings
                   for source in item['sources'])
        # The genuine report must stay inside the authorized loopback origin.
        assert all(urlsplit(item['target']).hostname == '127.0.0.1' for item in findings)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_genuine_wapiti_full_assessment_and_workflow_verification(tmp_path, monkeypatch):
    """Run a genuine assessment using installed Wapiti and verify findings & workflow verification."""
    executable = find_argv(wapiti.COMMANDS)
    if not executable:
        pytest.skip('Genuine Wapiti binary is not installed.')
    valid, version = verify('wapiti', executable)
    if not valid or not version:
        pytest.fail('Installed Wapiti identity check failed.')

    server = ThreadingHTTPServer(('127.0.0.1', 0), VulnerableLab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    url = f'http://127.0.0.1:{port}'

    monkeypatch.setenv('AVA_WAPITI_ENABLED', 'true')
    monkeypatch.delenv('AVA_WAPITI_MODULES', raising=False)
    monkeypatch.setenv('AVA_WAPITI_MAX_SCAN_TIME', '30')
    monkeypatch.setenv('AVA_WAPITI_MAX_ATTACK_TIME', '10')
    monkeypatch.setenv('AVA_WAPITI_HTTP_TIMEOUT', '5')

    application = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    application.config['TESTING'] = True
    register_loopback_target(application.extensions['database'])

    client = application.test_client()

    # Pre-assessment: workflow verification is not_verified
    pre_tools = client.get('/api/tools', headers=HEADERS).json['data']
    wapiti_pre = next(item for item in pre_tools if item['name'] == 'wapiti')
    assert wapiti_pre['workflow_verification']['status'] == 'not_verified'
    assert wapiti_pre['status'] == 'unverified'
    assert wapiti_pre['version'] == version

    # Router: mock nmap and httpx to direct the scan to the local lab url, but run genuine Wapiti
    monkeypatch.setattr('backend.services.scan_service.find_argv',
                        lambda commands: executable if commands[0] in {'wapiti', 'wapiti3'}
                        else '/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify',
                        lambda name, *args: (True, version) if name == 'wapiti' else (True, 'fixture'))
    monkeypatch.setattr('backend.integrations.httpx_scanner.parse',
                        lambda text, target: Results(assets=[asset(url, 'web', status_code=200, source='httpx')]))

    def router(argv, **kwargs):
        stem = Path(argv[0]).stem.lower()
        if stem == 'nmap':
            return ProcessResult('completed', NMAP, exit_code=0)
        if stem == 'httpx':
            return ProcessResult('completed', json.dumps({'url': url, 'status_code': 200}), exit_code=0)
        # Real Wapiti execution
        return run(argv, **kwargs)

    monkeypatch.setattr('backend.services.scan_service.run', router)

    try:
        response = create_wapiti_scan(client, 'wapiti-genuine-lab-key-01')
        assert response.status_code == 202, response.json
        result = finish(client, response.json['data']['id'], timeout_seconds=120)
        execution = next(item for item in result['executions'] if item['tool'] == 'wapiti')
        assert execution['state'] == 'completed', (execution, result)
        assert execution['version'] == version

        findings = [item for item in result['findings'] if item['details']['source_tool'] == 'wapiti']
        assert findings, 'Genuine Wapiti produced no findings in assessment.'
        for item in findings:
            assert item['severity'] in SEVERITIES
            assert item['details']['target'].startswith(url)
            assert item['details']['sources'][0]['tool'] == 'wapiti'

        # Post-assessment: workflow verification is now verified
        post_tools = client.get('/api/tools', headers=HEADERS).json['data']
        wapiti_post = next(item for item in post_tools if item['name'] == 'wapiti')
        assert wapiti_post['workflow_verification']['status'] == 'verified'
        assert wapiti_post['workflow_verification']['last_state'] == 'completed'
        assert wapiti_post['status'] == 'ready'
        assert 'successful assessment execution' in wapiti_post['reason']
    finally:
        application.extensions['scan_manager'].shutdown()
        application.extensions['database'].dispose()
        server.shutdown()
        server.server_close()
        thread.join()
