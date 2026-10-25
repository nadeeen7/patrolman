"""Fixture tests prove contracts, not genuine scanner execution."""
import json
import os
import threading
from pathlib import Path
import pytest
from backend.integrations import ADAPTERS, gitleaks, trivy, sslyze, nuclei
from backend.services.local_scope import validate_local, snapshot
from backend.services.target_validation import ScopeError, TargetError
from backend.services.results import deduplicate
from backend.services.tool_manager import diagnose, inventory
from backend.services.process_runner import ProcessResult
from backend.app import create_app
from backend.config import Settings
from backend.tests.test_workflow import HEADERS, TOKEN, finish


def tls_document():
    scans = {key: {'status':'COMPLETED', 'result': {'accepted_cipher_suites': []}} for key in sslyze.CHECKS}
    scans['tls_1_0_cipher_suites']['result']['accepted_cipher_suites'] = [{'cipher_suite':{'name':'TLS_RSA_WITH_AES_128_CBC_SHA'}}]
    scans['certificate_info']['result'] = {'certificate_deployments':[
        {'path_validation_results':[{'was_validation_successful':False, 'trust_store':{'name':'test'}}],
         'leaf_certificate_subject_matches_hostname':True}]}
    return {'server_scan_results':[{'server_location':{'ip_address':'127.0.0.1','port':443},
        'scan_status':'COMPLETED','connectivity_status':'COMPLETED','scan_result':scans}], 'invalid_server_strings':[]}


def test_exact_nine_tools():
    assert set(ADAPTERS) == {'nmap','whatweb','httpx','subfinder','nuclei','wapiti','gitleaks','trivy','sslyze'}


def test_local_scope_and_snapshot(tmp_path):
    root=tmp_path/'authorized';root.mkdir();(root/'file.txt').write_text('data')
    assert validate_local(str(root), (str(root),)) == str(root)
    with pytest.raises(ScopeError): validate_local(str(tmp_path), (str(root),))
    with pytest.raises(TargetError): validate_local('../escape', (str(root),))
    with pytest.raises(ScopeError): validate_local('//server/share', ())
    (root/'.git').mkdir();(root/'.git'/'history').write_text('not scanned')
    stats=snapshot(root,tmp_path/'copy')
    assert stats['files']==1 and not (tmp_path/'copy'/'.git').exists()
    try: (root/'outside').symlink_to(tmp_path/'copy',target_is_directory=True)
    except OSError: pytest.skip('This host cannot create links for the dedicated link-rejection portion of this test.')
    with pytest.raises(ScopeError): snapshot(root,tmp_path/'copy2')


def test_snapshot_limits_cancellation_hardlinks(tmp_path,monkeypatch):
    root=tmp_path/'src';root.mkdir();(root/'one').write_text('123')
    monkeypatch.setattr('backend.services.local_scope.MAX_FILE_BYTES',2)
    with pytest.raises(ValueError,match='limits'): snapshot(root,tmp_path/'size')
    event=threading.Event();event.set()
    with pytest.raises(ValueError,match='cancelled'): snapshot(root,tmp_path/'cancel',event)
    monkeypatch.setattr('backend.services.local_scope.MAX_FILE_BYTES',100)
    os.link(root/'one',root/'two')
    with pytest.raises(ScopeError,match='hardlinks'): snapshot(root,tmp_path/'hard')


def test_secret_parsers_never_copy_raw_values(tmp_path):
    marker='NOT_A_REAL_CREDENTIAL_DO_NOT_PERSIST'
    row={'RuleID':'test-rule','File':'config.txt','StartLine':2,'Secret':marker,'Match':marker,'Line':marker,'Description':marker}
    parsed=gitleaks.parse(json.dumps([row]),str(tmp_path))
    text=json.dumps(deduplicate(parsed.findings))
    assert marker not in text and 'config.txt' in text and '[REDACTED]' in text
    row['File']='../../outside'
    with pytest.raises(ValueError): gitleaks.parse(json.dumps([row]),str(tmp_path))
    report={'SchemaVersion':2,'ArtifactName':str(tmp_path),'Results':[{'Target':'requirements.txt','Secrets':[
        {'RuleID':'fake','StartLine':1,'Match':marker,'Code':{'Lines':[marker]}}]}]}
    assert marker not in json.dumps(trivy.parse(json.dumps(report),str(tmp_path)).findings)


def test_trivy_distinct_packages_and_locations(tmp_path):
    rows=[{'Target':file,'Vulnerabilities':[{'VulnerabilityID':'CVE-2024-12345','PkgName':pkg,
        'InstalledVersion':'1.0','Severity':'HIGH'}]} for file,pkg in [('a.lock','a'),('b.lock','a'),('b.lock','b')]]
    result=trivy.parse(json.dumps({'SchemaVersion':2,'ArtifactName':str(tmp_path),'Results':rows}),str(tmp_path))
    assert len(deduplicate(result.findings))==3
    assert all(f['category']=='filesystem_dependency' for f in result.findings)


@pytest.mark.parametrize('module',[gitleaks,trivy,sslyze])
@pytest.mark.parametrize('text',['bad','{}','null','[3]'])
def test_new_parser_malformed(module,text,tmp_path):
    with pytest.raises((ValueError,KeyError,TypeError,AttributeError)):
        module.parse(text,'https://127.0.0.1' if module is sslyze else str(tmp_path))


def test_tls_completion_scope_and_certificates():
    data=tls_document();result=sslyze.parse(json.dumps(data),'https://127.0.0.1')
    assert len(result.findings)==2 and result.findings[1]['source_tool']=='sslyze'
    data['server_scan_results'][0]['scan_result']['tls_1_3_cipher_suites']['status']='ERROR'
    incomplete=sslyze.parse(json.dumps(data),'https://127.0.0.1')
    assert 'tls_1_3_cipher_suites' in incomplete.errors
    assert incomplete.findings and incomplete.assets
    with pytest.raises(ValueError,match='scope'):sslyze.parse(json.dumps(tls_document()),'https://127.0.0.2')
    with pytest.raises(ValueError):sslyze.parse('{"server_scan_results":[]}','https://127.0.0.1')


def test_sslyze_incomplete_protocol_check_preserves_completed_results():
    data = tls_document()
    check = data['server_scan_results'][0]['scan_result']['ssl_3_0_cipher_suites']
    check.update(status='ERROR', result=None, error_reason='BUG_IN_SSLYZE',
                 error_trace='ServerRejectedConnection: Server rejected the connection')
    parsed = sslyze.parse(json.dumps(data), 'https://127.0.0.1')
    assert 'ssl_3_0_cipher_suites' in parsed.errors
    assert any(asset['kind'] == 'tls_protocol' for asset in parsed.assets)
    assert any(finding['title'] == 'TLS certificate validation failed' for finding in parsed.findings)


def test_nuclei_matchers_not_collapsed():
    text='\n'.join(json.dumps({'template-id':'headers','matched-at':'http://127.0.0.1','matcher-name':n,
        'info':{'name':'Headers missing','severity':'info'}}) for n in ['x-frame-options','csp'])
    assert len(deduplicate(nuclei.parse(text,'http://127.0.0.1').findings))==2


def test_no_hardcoded_wdac(monkeypatch):
    monkeypatch.setattr('backend.services.tool_manager.find_argv',lambda _:None)
    monkeypatch.setattr('backend.services.tool_manager.local_candidate',lambda _:None)
    monkeypatch.delenv('AVA_HTTPX_PATH', raising=False)
    assert next(r for r in inventory(True) if r['name']=='httpx')['state']=='NOT_INSTALLED'
    monkeypatch.setattr('backend.services.tool_manager.run',lambda *a,**k:ProcessResult('blocked',stderr='Windows policy blocked execution'))
    assert diagnose('httpx','fake')[2]=='blocked'
    monkeypatch.setattr('backend.services.tool_manager.run',lambda *a,**k:ProcessResult('failed',stderr='generic failure'))
    assert diagnose('httpx','fake')[2]=='unknown'


def test_windows_launcher_rejects_shell(monkeypatch,tmp_path):
    from backend.services.executables import resolve
    monkeypatch.setattr('backend.services.executables.WINDOWS',True)
    for suffix in ['.bat','.cmd','.ps1','.sh']:
        assert resolve(['C:/tool'+suffix]) is None
    script=tmp_path/'whatweb';script.write_text('#!/usr/bin/env ruby\n')
    monkeypatch.setattr('backend.services.executables.shutil.which',lambda _: 'C:/Ruby/bin/ruby.exe')
    assert resolve([str(script)])==['C:/Ruby/bin/ruby.exe',str(script)]


@pytest.mark.parametrize('name',['gitleaks','trivy','sslyze'])
@pytest.mark.parametrize('state',['unavailable','timed_out','failed','malformed','completed'])
def test_new_adapters_workflow_states(tmp_path,monkeypatch,name,state):
    root=tmp_path/'source';root.mkdir();(root/'a.txt').write_text('local fixture')
    app=create_app(Settings(tmp_path/'db',TOKEN,('127.0.0.1',),True,allowed_local_roots=(str(root),)))
    monkeypatch.setattr('backend.services.scan_service.find_argv',lambda _:None if state=='unavailable' else '/test/bin')
    monkeypatch.setattr('backend.services.scan_service.verify',lambda *a:(True,'fixture 1.0'))
    monkeypatch.setattr(trivy,'configuration_error',lambda:None)
    monkeypatch.setattr(trivy,'command',lambda exe,target,profile,out:[exe,str(out)])
    def run(argv,**kwargs):
        if state in {'failed','timed_out'}:return ProcessResult(state,stderr='SECRET_FROM_DIAGNOSTIC',exit_code=2)
        output=kwargs['output_files'][0]
        if state=='malformed':text='bad'
        elif name=='gitleaks':text=json.dumps([{'RuleID':'test','File':'a.txt','StartLine':1,'Secret':'NEVER_SAVE'}])
        elif name=='trivy':text=json.dumps({'SchemaVersion':2,'ArtifactName':str(root),'Results':[]})
        else:text=json.dumps(tls_document())
        output.write_text(text)
        return ProcessResult('completed',exit_code=0)
    monkeypatch.setattr('backend.services.scan_service.run',run)
    try:
        if name=='sslyze':
            from datetime import datetime, timedelta, timezone
            from sqlalchemy.orm import Session
            from backend.models import AuthorizedTarget
            now = datetime.now(timezone.utc)
            with Session(app.extensions['database']) as session:
                session.add(AuthorizedTarget(
                    name='Loopback SSLyze Target', target_type='internal_system',
                    owner_organization='Test Harness', scope_domains=['127.0.0.1'],
                    explicit_subdomains=[], excluded_scope=[],
                    permitted_methods=['port_scan', 'web_service_discovery', 'tls_audit'],
                    prohibited_methods=['dos', 'exploit'], rate_limit_rps=10,
                    valid_from=now - timedelta(days=1), valid_to=now + timedelta(days=30),
                    evidence_reference='SSLYZE-AUTH-2026', status='active',
                    created_by='admin', updated_by='admin',
                ))
                session.commit()
            # Seed approved discovery as persisted fixture assets via the normal prerequisite parsers.
            from backend.tests.test_execution import NMAP
            def network_run(argv,**kwargs):
                if '-oX' in argv:return ProcessResult('completed',NMAP.replace('8000','443'),exit_code=0)
                if '-json' in argv:return ProcessResult('completed','{"url":"https://127.0.0.1:443","status_code":200}',exit_code=0)
                return run(argv,**kwargs)
            monkeypatch.setattr('backend.services.scan_service.run',network_run)
            payload=dict(target='127.0.0.1',profile='standard',tools=['nmap','httpx','sslyze'],authorized=True)
        else:payload=dict(target=str(root),profile='local',tools=[name],authorized=True)
        client=app.test_client()
        response=client.post('/api/scans',json=payload,headers=dict(HEADERS,**{'Idempotency-Key':'local-workflow-test-key'}))
        assert response.status_code==202,response.json
        scan=finish(client,response.json['data']['id'])
        execution=next(e for e in scan['executions'] if e['tool']==name)
        expected='failed' if state=='malformed' else state
        assert execution['state']==expected,scan
        assert ('NEVER_SAVE' not in json.dumps(scan))
        if name!='sslyze':assert 'SECRET_FROM_DIAGNOSTIC' not in json.dumps(scan)
        html=client.get('/api/scans/'+scan['id']+'/report',headers=HEADERS).text
        assert 'Coverage and untested areas' in html and 'NEVER_SAVE' not in html
        if state=='completed':assert execution['version']=='fixture 1.0'
    finally:
        app.extensions['scan_manager'].shutdown();app.extensions['database'].dispose()


def test_local_api_rejects_web_and_unauthorized_paths(tmp_path):
    root=tmp_path/'source';root.mkdir()
    app=create_app(Settings(tmp_path/'data',TOKEN,allowed_local_roots=(str(root),)))
    try:
        c=app.test_client();h=dict(HEADERS,**{'Idempotency-Key':'reject-local-scans-key'})
        base=dict(target=str(root),profile='local',tools=['gitleaks'],authorized=True)
        assert c.post('/api/scans',json={**base,'target':str(tmp_path)},headers=h).status_code==403
        assert c.post('/api/scans',json={**base,'tools':['nmap']},headers=h).status_code==400
        assert c.post('/api/scans',json={**base,'authorized':False},headers=h).status_code==400
    finally:app.extensions['scan_manager'].shutdown();app.extensions['database'].dispose()


def test_nuclei_null_cve_list_is_supported():
    text=json.dumps({'template-id':'headers','matched-at':'http://127.0.0.1','info':{'classification':{'cve-id':None}}})
    assert deduplicate(nuclei.parse(text,'http://127.0.0.1').findings)[0]['cve_id'] is None


def test_subfinder_provider_and_normalization(tmp_path,monkeypatch):
    from backend.integrations import subfinder
    monkeypatch.setenv('AVA_SUBFINDER_PROVIDER_CONFIG',str(tmp_path/'missing.yaml'))
    assert subfinder.configuration_error()
    with pytest.raises(ValueError):subfinder.command('subfinder','example.com','standard',tmp_path/'out')
    monkeypatch.delenv('AVA_SUBFINDER_PROVIDER_CONFIG')
    result=subfinder.parse('{"host":"SUB.EXAMPLE.COM.","source":"provider"}','example.com')
    assert result.assets[0]['address']=='sub.example.com'
    assert result.assets[0]['details']['passive'] is True
    assert result.assets[0]['details']['authorized_for_scanning'] is False


def test_httpx_failed_probe_is_not_clean():
    with pytest.raises(ValueError,match='failed'):
        ADAPTERS['httpx'].parse('{"failed":true}','http://127.0.0.1')


def test_native_policy_error_is_specific(monkeypatch):
    from backend.services.process_runner import run
    def blocked(*a,**k):
        error=OSError('policy');error.winerror=1260;raise error
    monkeypatch.setattr('backend.services.process_runner.subprocess.Popen',blocked)
    assert run(['tool']).state=='blocked'


def test_trivy_requires_configured_database(monkeypatch,tmp_path):
    monkeypatch.setenv('AVA_TRIVY_CACHE_DIR',str(tmp_path/'missing'))
    monkeypatch.setenv('AVA_TRIVY_SCANNERS', 'vuln')
    assert 'Vulnerability database scanning is unavailable' in trivy.configuration_error()
    with pytest.raises(ValueError):trivy.command('trivy',str(tmp_path),'local',tmp_path/'out')


def test_trivy_configuration_only_status_discloses_missing_vulnerability_database(monkeypatch, tmp_path):
    cache = tmp_path / 'cache'
    cache.mkdir()
    monkeypatch.setenv('AVA_TRIVY_CACHE_DIR', str(cache))
    monkeypatch.setenv('AVA_TRIVY_SCANNERS', 'misconfig,secret')

    status, message = trivy.runtime_status()
    assert status == 'configured'
    assert 'offline configuration/secret scanners' in message.lower()
    assert 'vulnerability database scanning is unavailable' in message.lower()
    assert not trivy.configuration_error()


def test_trivy_cache_discovery_only_accepts_an_existing_database(monkeypatch, tmp_path):
    cache = tmp_path / 'existing-cache'
    database = cache / 'db' / 'trivy.db'
    database.parent.mkdir(parents=True)
    database.write_bytes(b'test fixture database marker')
    monkeypatch.setenv('USERPROFILE', str(tmp_path / 'profile'))
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    monkeypatch.setenv('APPDATA', str(tmp_path / 'roaming'))
    monkeypatch.delenv('TRIVY_CACHE_DIR', raising=False)
    assert trivy.discover_cache() is None

    discovered = tmp_path / 'profile' / '.cache' / 'trivy'
    discovered_db = discovered / 'db' / 'trivy.db'
    discovered_db.parent.mkdir(parents=True)
    discovered_db.write_bytes(b'local existing database marker')
    assert trivy.discover_cache() == discovered.resolve()
