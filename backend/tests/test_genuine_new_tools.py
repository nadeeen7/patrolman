"""Genuine optional scanner tests. No replacement of runner, binaries or parsers.

Targets are fresh loopback services and test-only source directories. Never
scan external targets. Missing genuine binaries produce explicit skips.
"""
import json
import os
import shutil
import ssl
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest
from sqlalchemy.orm import Session

from backend.integrations import ADAPTERS
from backend.models import AuthorizedTarget
from backend.services.executables import find_argv
from backend.services.tool_manager import verify
from backend.services.process_runner import run
from backend.services.results import deduplicate


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



def binary(name):
    value=find_argv(ADAPTERS[name].COMMANDS)
    if not value:pytest.skip(f'Genuine {name} binary is not installed.')
    valid,version=verify(name,value)
    if not valid:pytest.fail(f'Installed {name} identity check failed.')
    return value


def invoke(name,target,tmp_path):
    module=ADAPTERS[name];exe=binary(name)
    output=tmp_path/(name+'.json')
    command=module.command(exe,target,'quick',output)
    result=run(command,cwd=str(tmp_path),timeout=150,output_files=(output,))
    assert result.state=='completed',(name,result.state,result.stderr[-1500:])
    raw=output.read_text() if getattr(module,'FILE_OUTPUT',False) else result.stdout
    return module.parse(raw,target), raw


class Handler(BaseHTTPRequestHandler):
    redirect=None
    hits=0
    def do_GET(self):
        type(self).hits+=1
        self.send_response(302 if self.redirect else 200)
        self.send_header('Content-Type','text/html')
        if self.redirect:self.send_header('Location',self.redirect)
        self.end_headers();self.wfile.write(b'<html><title>PATROLMAN local lab</title>authorized fixture</html>')
    def log_message(self,*args):pass


@pytest.fixture
def web_lab():
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield 'http://127.0.0.1:'+str(server.server_port)
    server.shutdown();server.server_close();thread.join()


def test_genuine_httpx_probe(web_lab,tmp_path):
    parsed,_=invoke('httpx',web_lab,tmp_path)
    assert parsed.assets and parsed.assets[0]['details']['status_code']==200


def test_genuine_nuclei_official_headers(web_lab,tmp_path):
    parsed,_=invoke('nuclei',web_lab,tmp_path)
    assert parsed.findings and all(f['source_identifier']=='http-missing-security-headers' for f in parsed.findings)
    assert len(deduplicate(parsed.findings))>=2


@pytest.mark.parametrize('name',['httpx','nuclei'])
def test_genuine_no_cross_port_redirect(name,tmp_path):
    binary(name)
    class Sink(Handler):hits=0
    sink=ThreadingHTTPServer(('127.0.0.1',0),Sink)
    class Redirect(Handler):redirect='http://127.0.0.1:'+str(sink.server_port)
    origin=ThreadingHTTPServer(('127.0.0.1',0),Redirect)
    threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (sink,origin)]
    for t in threads:t.start()
    try:
        invoke(name,'http://127.0.0.1:'+str(origin.server_port),tmp_path)
        assert Sink.hits==0,'Scanner followed a redirect outside the authorized service.'
    finally:
        for s in (sink,origin):s.shutdown();s.server_close()
        for t in threads:t.join()


def test_genuine_gitleaks_directory_and_persistence(tmp_path):
    binary('gitleaks')
    # Deliberately fabricated test credential, not a real secret.
    marker='Ab7xQ2mL9rT4kV8pN6zY3wF5eR0uB1sC'
    root=tmp_path/'source';root.mkdir();(root/'demo.py').write_text('api_key = "'+marker+'"\n')
    from backend.app import create_app
    from backend.config import Settings
    from backend.tests.test_workflow import HEADERS,TOKEN
    from backend.tests.test_workflow import finish
    app=create_app(Settings(tmp_path/'data',TOKEN,allowed_local_roots=(str(root),)))
    try:
        c=app.test_client()
        r=c.post('/api/scans',json={'target':str(root),'profile':'local','tools':['gitleaks'],'authorized':True},
            headers=dict(HEADERS,**{'Idempotency-Key':'genuine-gitleaks-scan'}))
        assert r.status_code==202
        data=finish(c,r.json['data']['id'],timeout_seconds=60)
        assert data['state']=='completed',data
        assert data['findings'] and marker not in json.dumps(data)
        html=c.get('/api/scans/'+data['id']+'/report',headers=HEADERS).text
        assert '[REDACTED]' in html and marker not in html
    finally:app.extensions['scan_manager'].shutdown();app.extensions['database'].dispose()


def test_genuine_sslyze_local_certificate(tmp_path):
    binary('sslyze')
    x509=pytest.importorskip('cryptography.x509')
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'PATROLMAN local lab')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .sign(key,hashes.SHA256()))
    (tmp_path/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(tmp_path/'cert.pem',tmp_path/'key.pem')
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        parsed,_=invoke('sslyze','https://127.0.0.1:'+str(server.server_port),tmp_path)
        assert any(f['title']=='TLS certificate validation failed' for f in parsed.findings)
        assert any(a['kind']=='tls_protocol' for a in parsed.assets)
    finally:server.shutdown();server.server_close();thread.join()


def test_genuine_sslyze_assessment_persists_results_and_report(tmp_path, monkeypatch):
    """Run genuine Nmap, HTTPX and SSLyze against an isolated loopback TLS server."""
    binary('sslyze')
    project = Path(__file__).resolve().parents[2]
    monkeypatch.setenv('AVA_HTTPX_PATH', str(project / 'tools' / 'httpx' / 'httpx.exe'))
    binary('httpx')
    binary('nmap')

    from backend.app import create_app
    from backend.config import Settings
    from backend.services.scan_service import TERMINAL
    from backend.tests.test_workflow import HEADERS, TOKEN
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress

    port = 8443
    try:
        server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    except OSError:
        pytest.skip('Loopback port 8443 is unavailable for the TLS fixture.')

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'PATROLMAN local TLS lab')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(key, hashes.SHA256()))
    (tmp_path / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / 'cert.pem', tmp_path / 'key.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    _register_target(app, ['port_scan', 'web_service_discovery', 'tls_audit'])
    try:
        client = app.test_client()
        response = client.post('/api/scans', json={
            'target': '127.0.0.1', 'profile': 'standard',
            'tools': ['nmap', 'httpx', 'sslyze'], 'authorized': True,
        }, headers=dict(HEADERS, **{'Idempotency-Key': 'genuine-sslyze-workflow'}))
        assert response.status_code == 202, response.json

        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            result = client.get('/api/scans/' + response.json['data']['id'], headers=HEADERS).json['data']
            if result['state'] in TERMINAL:
                break
            time.sleep(.25)
        assert result['state'] in {'completed', 'completed_with_errors'}, (
            result['state'], result['executions'])
        executions = {execution['tool']: execution for execution in result['executions']}
        assert all(executions[name]['state'] == 'completed' for name in ('nmap', 'httpx'))
        assert executions['sslyze']['state'] in {'completed', 'failed'}
        if executions['sslyze']['state'] == 'failed':
            assert 'requested checks did not complete' in executions['sslyze']['error']
        assert any(finding['details']['source_tool'] == 'sslyze' for finding in result['findings'])

        exported = client.get(f"/api/scans/{result['id']}/report?format=json", headers=HEADERS)
        assert exported.status_code == 200
        assert any(finding['details']['source_tool'] == 'sslyze' for finding in exported.json['findings'])
        html = client.get(f"/api/scans/{result['id']}/report", headers=HEADERS)
        assert html.status_code == 200 and 'sslyze' in html.text.lower()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_genuine_trivy_local_dependencies(tmp_path,monkeypatch):
    binary('trivy')
    from backend.integrations import trivy
    import os as _os
    from pathlib import Path as _Path
    # Check specifically for the vuln DB: this test requires AVA_TRIVY_CACHE_DIR set and
    # a trivy.db file present inside it, regardless of the current AVA_TRIVY_SCANNERS.
    _cache = _os.getenv('AVA_TRIVY_CACHE_DIR', '')
    if not _cache or not _Path(_cache).is_dir() or not (_Path(_cache) / 'db' / 'trivy.db').is_file():
        pytest.skip('Trivy official vulnerability DB not configured (trivy.db absent).')
    monkeypatch.setenv('AVA_TRIVY_SCANNERS','vuln,misconfig,secret')
    root=tmp_path/'project';root.mkdir()
    (root/'requirements.txt').write_text('Django==1.11.29\n')
    (root/'Dockerfile').write_text('FROM python:3.11\nUSER root\n')
    parsed,_=invoke('trivy',str(root),tmp_path)
    assert any(f.get('category')=='filesystem_dependency' for f in parsed.findings)
    assert all(f['source_tool']=='trivy' for f in parsed.findings)
    assert all('evidence' in f for f in parsed.findings)


def test_genuine_trivy_local_configuration(tmp_path, monkeypatch):
    binary('trivy')
    cache=tmp_path/'cache';cache.mkdir()
    monkeypatch.setenv('AVA_TRIVY_CACHE_DIR',str(cache))
    monkeypatch.setenv('AVA_TRIVY_SCANNERS','misconfig,secret')
    root=tmp_path/'project';root.mkdir();(root/'Dockerfile').write_text('FROM python:3.11\nUSER root\n')
    parsed,_=invoke('trivy',str(root),tmp_path)
    assert any(f.get('category')=='filesystem_configuration' for f in parsed.findings)


def test_genuine_trivy_local_assessment_persists_results_and_report(tmp_path, monkeypatch):
    """Exercise Trivy through authorized local snapshot, persistence and reports without a vuln DB."""
    binary('trivy')
    cache = tmp_path / 'cache'
    cache.mkdir()
    monkeypatch.setenv('AVA_TRIVY_CACHE_DIR', str(cache))
    monkeypatch.setenv('AVA_TRIVY_SCANNERS', 'misconfig,secret')
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'Dockerfile').write_text('FROM python:3.11\nUSER root\n')
    marker = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'
    (root / 'credential.txt').write_text('github_token = "' + marker + '"\n')

    from backend.app import create_app
    from backend.config import Settings
    from backend.tests.test_workflow import HEADERS, TOKEN, finish

    app = create_app(Settings(tmp_path / 'data', TOKEN, allowed_local_roots=(str(root),)))
    try:
        client = app.test_client()
        response = client.post(
            '/api/scans',
            json={'target': str(root), 'profile': 'local', 'tools': ['trivy'], 'authorized': True},
            headers=dict(HEADERS, **{'Idempotency-Key': 'genuine-trivy-local-scan'}),
        )
        assert response.status_code == 202, response.json
        result = finish(client, response.json['data']['id'], timeout_seconds=120)
        execution = next(item for item in result['executions'] if item['tool'] == 'trivy')
        assert execution['state'] == 'completed', result
        assert any(item['details']['source_tool'] == 'trivy' for item in result['findings'])
        secret_findings = [item for item in result['findings']
                           if item['details'].get('category') == 'local_source_secret']
        assert secret_findings and all(
            item['details']['evidence']['value'] == '[REDACTED]' for item in secret_findings)
        assert marker not in json.dumps(result)

        exported = client.get(f"/api/scans/{result['id']}/report?format=json", headers=HEADERS)
        assert exported.status_code == 200
        report = exported.get_json()
        assert any(item['details']['source_tool'] == 'trivy' for item in report['findings'])
        assert marker not in json.dumps(report)
        html = client.get(f"/api/scans/{result['id']}/report", headers=HEADERS)
        assert html.status_code == 200 and 'trivy' in html.text.lower()
        assert marker not in html.text
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()
