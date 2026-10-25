import json
import sys
import threading
import time
import pytest
from backend.services.process_runner import run
from backend.integrations import ADAPTERS as CURRENT_ADAPTERS, tls_scanner
ADAPTERS = dict(CURRENT_ADAPTERS, testssl=tls_scanner)
from backend.integrations.base import finding
from backend.services.results import normalize, deduplicate, redact

NMAP = '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8000"><state state="open"/><service name="http" method="table"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
FIXTURES = {
 'nmap': NMAP,
 'subfinder': '{"host":"sub.example.com"}\n{"host":"unrelated.example"}',
 'httpx': '{"url":"http://127.0.0.1:8000","status_code":200,"tech":["Python"]}',
 'whatweb': '[{"target":"http://127.0.0.1:8000","plugins":{"Python":{}}}]',
 'nuclei': '{"template-id":"ava-missing-nosniff","matched-at":"http://127.0.0.1:8000","info":{"name":"Header missing","severity":"info"}}',
 'testssl': '[{"id":"TLS1","severity":"HIGH","finding":"Obsolete protocol"}]',
 'wapiti': json.dumps({
   'classifications': {'Security Headers': {'desc': 'X-Frame-Options header not set',
                                             'sol': 'Set X-Frame-Options to DENY', 'ref': ['https://owasp.org/']}},
   'vulnerabilities': {'Security Headers': [{'level': 1, 'parameter': '', 'method': 'GET', 'path': '/',
     'referer': '', 'module': 'http_headers', 'info': 'X-Frame-Options header is missing',
     'http_request': 'GET / HTTP/1.1\nHost: 127.0.0.1:8000\n', 'curl_command': 'curl "http://127.0.0.1:8000/"',
     'wstg': ['WSTG-CONF-07']}]},
   'anomalies': {}, 'additionals': {}, 'infos': {'target': 'http://127.0.0.1:8000'},
   'suppressed_findings': {},
 }),
}


def test_process_success_and_secrets_not_inherited(monkeypatch):
    monkeypatch.setenv('AVA_API_TOKEN', 'secret-value')
    result = run([sys.executable, '-c', 'import os; print(os.environ.get("AVA_API_TOKEN", "absent"))'])
    assert result.state == 'completed' and result.stdout.strip() == 'absent'


def test_process_failures():
    assert run(['/nonexistent/ava-test-command']).state == 'unavailable'
    result = run([sys.executable, '-c', 'import sys; print("failure", file=sys.stderr); sys.exit(3)'])
    assert result.state == 'failed' and result.exit_code == 3 and 'failure' in result.stderr
    assert run([sys.executable, '-c', 'import time;time.sleep(10)'], timeout=.1).state == 'timed_out'
    result = run([sys.executable, '-c', 'print("x"*100000)'], max_output=100)
    assert result.state == 'output_limit' and len(result.stdout) <= 100


def test_process_cancel():
    event = threading.Event()
    timer = threading.Timer(.1, event.set); timer.start()
    try:
        result = run([sys.executable, '-c', 'import time;time.sleep(10)'], cancel=event)
        assert result.state == 'cancelled'
        assert run([sys.executable, '-c', 'raise RuntimeError()'], cancel=event).state == 'cancelled'
    finally: timer.join()


@pytest.mark.parametrize('name', list(FIXTURES))
def test_adapter_command_and_parser(name, tmp_path):
    module = ADAPTERS[name]
    target = '127.0.0.1' if name == 'nmap' else 'example.com' if name == 'subfinder' else ('https' if name == 'testssl' else 'http') + '://127.0.0.1:8000'
    argv = module.command('/bin/' + name, target, 'quick', tmp_path / 'output.json')
    assert isinstance(argv, list) and all(isinstance(x, str) for x in argv)
    assert argv[0] == '/bin/' + name
    result = module.parse(FIXTURES[name], target)
    assert result.assets or result.findings
    if name in {'nmap', 'subfinder', 'httpx', 'whatweb'}: assert not result.findings


@pytest.mark.parametrize('name', list(FIXTURES))
def test_adapter_malformed(name):
    with pytest.raises((ValueError, SyntaxError)):
        ADAPTERS[name].parse('this is not machine-readable', '127.0.0.1')


@pytest.mark.parametrize('name', ['nmap', 'httpx', 'whatweb', 'nuclei', 'testssl', 'wapiti'])
def test_commands_reject_injection(name, tmp_path):
    with pytest.raises(ValueError):
        ADAPTERS[name].command('/bin/tool', '127.0.0.1;touch /tmp/injected', 'quick', tmp_path/'out')


def test_scope_and_nmap_completion():
    with pytest.raises(ValueError): ADAPTERS['nmap'].parse(NMAP.replace('127.0.0.1', '8.8.8.8'), '127.0.0.1')
    with pytest.raises(ValueError): ADAPTERS['nmap'].parse('<nmaprun/>', '127.0.0.1')
    for name in ('httpx', 'whatweb', 'nuclei'):
        with pytest.raises(ValueError): ADAPTERS[name].parse(FIXTURES[name], 'http://127.0.0.2:8000')
    assert len(ADAPTERS['subfinder'].parse(FIXTURES['subfinder'], 'example.com').assets) == 1


def test_empty_valid_results():
    assert ADAPTERS['nuclei'].parse('', 'http://127.0.0.1').findings == []
    assert ADAPTERS['testssl'].parse('[]', 'https://127.0.0.1').findings == []
    assert ADAPTERS['wapiti'].parse('{"vulnerabilities": {}}', 'http://127.0.0.1').findings == []


def test_risk_and_dedupe_preserve_sources():
    first = finding('Issue', 'http://127.0.0.1:80', 'one', 'a', 'HIGH', classification={'cve-id': ['CVE-2024-12345']})
    second = finding('Same issue', 'http://127.0.0.1/', 'two', 'b', 'medium', classification={'cve-id': ['CVE-2024-12345']})
    values = deduplicate([first, second])
    assert len(values) == 1 and len(values[0]['sources']) == 2 and values[0]['severity'] == 'high'
    second['classification'] = {'cve-id': ['CVE-2024-12346']}
    assert len(deduplicate([first, second])) == 2
    first['classification'] = {'cvss-score': 9.8, 'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}
    result = normalize(first)
    assert result['severity'] == 'critical' and result['cvss_version'] == '3.1'
    first['classification']['cvss-score'] = float('nan')
    assert normalize(first)['cvss_score'] is None
    assert normalize(finding('Unknown', '127.0.0.1', 'x', '1', 'bogus'))['severity'] == 'unknown'
    assert redact({'Authorization': 'secret', 'evidence': 'Cookie: x=y\nproof'}) == {'Authorization': '[REDACTED]', 'evidence': 'Cookie: [REDACTED]\nproof'}


def test_output_file_limit(tmp_path):
    path = tmp_path / 'result'
    code = 'import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text("x"*10000);time.sleep(10)'
    result = run([sys.executable, '-c', code, str(path)], max_output=100, output_files=(path,))
    assert result.state == 'output_limit'


def test_httpx_identity_rejects_unrelated_binary(monkeypatch):
    from backend.services.tool_manager import verify
    from backend.services.process_runner import ProcessResult
    verify.cache_clear()
    monkeypatch.setattr('backend.services.tool_manager.run', lambda argv, **kw: ProcessResult('completed', 'Current Version: unrelated'))
    assert verify('httpx', '/fake-httpx')[0] is False
    verify.cache_clear()
