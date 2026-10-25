"""Secret-redaction regression tests.

Every secret here is synthetic. The contract is: secrets never survive into
findings, stored history, API responses, HTML reports or JSON reports, while
ordinary scanner text is left untouched.

A genuine defect was found while writing these tests: `passwd=`, `credentials=`
and `private_key=` values leaked from free text (the dict-key rule knew them, the
string rule did not). `results.py` was fixed, and `test_value_spelling_is_redacted`
pins the whole spelling list so the gap cannot return.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from backend.app import create_app
from backend.config import Settings
from backend.models import AuthorizedTarget
from backend.services.process_runner import ProcessResult
from backend.services.results import deduplicate, normalize, redact
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

SECRETS = {
    'session': 'SYNTHSESSION01',
    'session_id': 'SYNTHSESSIONID02',
    'phpsessid': 'SYNTHPHPSESSID03',
    'jsessionid': 'SYNTHJSESSIONID04',
    'cookie': 'SYNTHCOOKIE05',
    'set_cookie': 'SYNTHSETCOOKIE06',
    'authorization_basic': 'SYNTHBASIC07',
    'authorization_bearer': 'SYNTHBEARER08',
    'api_key': 'SYNTHAPIKEY09',
    'api_key_dashed': 'SYNTHAPIKEYDASH10',
    'token': 'SYNTHTOKEN11',
    'access_token': 'SYNTHACCESSTOKEN12',
    'auth_token': 'SYNTHAUTHTOKEN13',
    'password': 'SYNTHPASSWORD14',
    'passwd': 'SYNTHPASSWD15',
    'credentials': 'SYNTHCREDENTIALS16',
    'client_secret': 'SYNTHCLIENTSECRET17',
    'private_key': 'SYNTHPRIVATEKEY18',
    'scanner_api_key_header': 'SYNTHSCANNERKEY19',
}

# (label, raw text, the spellings that must not survive)
VALUE_CASES = [
    ('session', 'GET http://127.0.0.1:8000/?session=' + SECRETS['session'], [SECRETS['session']]),
    ('session_id', 'session_id=' + SECRETS['session_id'], [SECRETS['session_id']]),
    ('PHPSESSID', 'PHPSESSID=' + SECRETS['phpsessid'], [SECRETS['phpsessid']]),
    ('JSESSIONID', 'JSESSIONID=' + SECRETS['jsessionid'], [SECRETS['jsessionid']]),
    ('cookie header', 'Cookie: sid=' + SECRETS['cookie'] + '; theme=dark', [SECRETS['cookie']]),
    ('set-cookie header', 'Set-Cookie: auth=' + SECRETS['set_cookie'] + '; Secure; HttpOnly', [SECRETS['set_cookie']]),
    ('authorization basic', 'Authorization: Basic ' + SECRETS['authorization_basic'], [SECRETS['authorization_basic']]),
    ('authorization bearer', 'Authorization: Bearer ' + SECRETS['authorization_bearer'], [SECRETS['authorization_bearer']]),
    ('inline bearer', 'sent Bearer ' + SECRETS['authorization_bearer'] + ' to the endpoint', [SECRETS['authorization_bearer']]),
    ('api_key', 'api_key=' + SECRETS['api_key'], [SECRETS['api_key']]),
    ('api-key', 'api-key=' + SECRETS['api_key_dashed'], [SECRETS['api_key_dashed']]),
    ('token', 'token=' + SECRETS['token'], [SECRETS['token']]),
    ('access_token', 'access_token=' + SECRETS['access_token'], [SECRETS['access_token']]),
    ('auth_token', 'auth_token=' + SECRETS['auth_token'], [SECRETS['auth_token']]),
    ('password', 'password=' + SECRETS['password'], [SECRETS['password']]),
    ('passwd', 'passwd=' + SECRETS['passwd'], [SECRETS['passwd']]),
    ('credentials', 'credentials=' + SECRETS['credentials'], [SECRETS['credentials']]),
    ('client_secret', 'client_secret=' + SECRETS['client_secret'], [SECRETS['client_secret']]),
    ('private_key', 'private_key=' + SECRETS['private_key'], [SECRETS['private_key']]),
    ('scanner API-key header', 'X-Scanner-API-Key: ' + SECRETS['scanner_api_key_header'], [SECRETS['scanner_api_key_header']]),
    ('query string with many secrets',
     'http://127.0.0.1:8000/x?a=1&api_key=' + SECRETS['api_key'] + '&password=' + SECRETS['password'],
     [SECRETS['api_key'], SECRETS['password']]),
    ('prose api key', 'Scanner API key=' + SECRETS['api_key'] + ' rejected', [SECRETS['api_key']]),
    ('prose private key', 'private key=' + SECRETS['private_key'], [SECRETS['private_key']]),
    ('prose access token', 'access token=' + SECRETS['access_token'], [SECRETS['access_token']]),
    ('prose session id', 'session id=' + SECRETS['session_id'], [SECRETS['session_id']]),
]

PRESERVED = [
    'Scanner observation: The anti-clickjacking X-Frame-Options header is not present.',
    'X-Frame-Options header is not set; add it to the response.',
    'The session was closed after the crawl completed.',
    'status=ok and count=3 and path=/index.html',
    'http://127.0.0.1:8000/index.html',
    'Server Leaks Version Information via "Server" HTTP Response Header Field.',
]


# --- 1. The shared helper ----------------------------------------------------

@pytest.mark.parametrize('label,text,spellings', VALUE_CASES, ids=[case[0] for case in VALUE_CASES])
def test_value_spelling_is_redacted(label, text, spellings):
    """Each value-carrying spelling is redacted, and no secret survives."""
    cleaned = redact(text)
    assert '[REDACTED]' in cleaned
    for secret in spellings:
        assert secret not in cleaned


@pytest.mark.parametrize('text', PRESERVED)
def test_ordinary_text_is_preserved(text):
    """Non-sensitive text must pass through unchanged, including the word 'session'."""
    assert redact(text) == text


def test_sensitive_dict_keys_are_redacted_but_ordinary_keys_survive():
    payload = {'Authorization': 'Bearer ' + SECRETS['authorization_bearer'], 'cookie': SECRETS['cookie'],
               'session_id': SECRETS['session_id'], 'api_key': SECRETS['api_key'], 'title': 'X-Frame-Options missing',
               'severity': 'low', 'count': 3, 'enabled': True, 'empty': None,
               'nested': {'password': SECRETS['password'], 'note': 'ordinary note'}}
    cleaned = redact(payload)
    assert cleaned['Authorization'] == cleaned['cookie'] == cleaned['session_id'] == cleaned['api_key'] == '[REDACTED]'
    assert cleaned['title'] == 'X-Frame-Options missing'
    assert cleaned['severity'] == 'low' and cleaned['count'] == 3 and cleaned['enabled'] is True and cleaned['empty'] is None
    assert cleaned['nested']['password'] == '[REDACTED]'
    assert cleaned['nested']['note'] == 'ordinary note'
    assert json.dumps(cleaned).count(SECRETS['password']) == 0


def test_structure_limits_and_non_strings_are_untouched():
    assert redact(5) == 5 and redact(None) is None and redact(True) is True
    assert redact(['a', 'token=' + SECRETS['token']]) == ['a', 'token=[REDACTED]']
    assert len(redact(['x'] * 1500)) == 1000
    assert len(redact('a' * 20000)) == 16000


def test_bare_unlabelled_value_is_out_of_scope_for_pattern_redaction():
    """Pinned limitation: redaction is label-driven, so a bare value is not detectable.

    `redact()` recognises secrets from a credential label or header, never from the
    value alone: any bare string could be ordinary scanner text, and blanket
    redaction would destroy findings. Callers that know a field is sensitive (a
    dict key, a header) are covered; a scanner reporting a naked secret value with
    no label is not. This is documented in the final report rather than pretended away.
    """
    assert redact(SECRETS['token']) == SECRETS['token']
    assert redact({'extracted': [SECRETS['api_key']]}) == {'extracted': [SECRETS['api_key']]}
    # The labelled form of the same data is redacted.
    assert redact({'extracted': 'api_key=' + SECRETS['api_key']}) == {'extracted': 'api_key=[REDACTED]'}


def test_secret_inside_an_exception_message_is_redacted():
    """Errors are logged and returned through redact(), so they must not leak either."""
    error = ValueError('Scanner API key=' + SECRETS['api_key'] + ' rejected while Authorization: Bearer ' + SECRETS['authorization_bearer'])
    cleaned = redact(str(error))
    assert SECRETS['api_key'] not in cleaned and SECRETS['authorization_bearer'] not in cleaned


# --- 2. Findings normalization ----------------------------------------------

def test_normalization_redacts_finding_text_and_evidence():
    """A finding carrying secrets is normalized with every field scrubbed."""
    finding = {
        'title': 'Leaked Authorization: Bearer ' + SECRETS['authorization_bearer'],
        'target': 'http://127.0.0.1:8000',
        'source_tool': 'nuclei',
        'source_identifier': 'synthetic-secret-probe',
        'severity': 'medium',
        'description': 'Cookie: sid=' + SECRETS['cookie'] + ' was not flagged',
        'remediation': 'Rotate the password=' + SECRETS['password'],
        'evidence': {'api_key': SECRETS['api_key'], 'self': 'private_key=' + SECRETS['private_key'], 'note': 'ordinary'},
    }
    normalized = normalize(finding)
    dumped = json.dumps(normalized)
    for secret in (SECRETS['authorization_bearer'], SECRETS['cookie'], SECRETS['password'],
                   SECRETS['api_key'], SECRETS['private_key']):
        assert secret not in dumped, secret
    assert '[REDACTED]' in dumped
    assert normalized['source_tool'] == 'nuclei' and normalized['severity'] == 'medium'
    assert normalized['sources'][0]['evidence']['note'] == 'ordinary'
    assert normalized['fingerprint']


def test_deduplication_keeps_distinct_issues_and_merges_identical_ones():
    """Redaction must not collapse or hide genuinely distinct findings."""
    def item(identifier, title='Header missing', evidence=None):
        return {'title': title, 'target': 'http://127.0.0.1:8000', 'source_tool': 'nuclei',
                'source_identifier': identifier, 'severity': 'low', 'evidence': evidence or {}}
    distinct = deduplicate([item('rule-a'), item('rule-b'), item('rule-a')])
    assert len(distinct) == 2
    merged = deduplicate([item('rule-a', title='X-Frame-Options missing'),
                          item('rule-a', title='X-Frame-Options missing'),
                          item('rule-a', title='Content-Security-Policy missing')])
    assert len(merged) == 1
    assert {source['title'] for source in merged[0]['sources']} == {'X-Frame-Options missing', 'Content-Security-Policy missing'}


# --- 3. Findings, history, API responses and reports ------------------------

NUCLEI_WITH_SECRETS = json.dumps({
    'template-id': 'synthetic-secret-probe',
    'matched-at': 'http://127.0.0.1:8000',
    'info': {'name': 'Cookie without Secure flag', 'severity': 'medium',
             'description': 'Cookie: sid=' + SECRETS['cookie'] + ' and Authorization: Bearer ' + SECRETS['authorization_bearer'],
             'remediation': 'Rotate credentials=' + SECRETS['credentials']},
    'extracted-results': ['api_key=' + SECRETS['api_key'], 'private_key=' + SECRETS['private_key']],
}) + '\n'


def _run_secret_scan(tmp_path, monkeypatch, nuclei_output):
    def fake_run(argv, **kwargs):
        name = Path(argv[0]).name
        if name == 'nmap':
            return ProcessResult('completed', NMAP, exit_code=0)
        if name == 'httpx':
            return ProcessResult('completed', '{"url":"http://127.0.0.1:8000","status_code":200}', exit_code=0)
        if name == 'nuclei':
            return ProcessResult('completed', nuclei_output, exit_code=0)
        raise AssertionError('Unexpected executable: ' + name)

    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    app.config['TESTING'] = True
    _register_target(app, ['port_scan', 'web_service_discovery', 'vulnerability_check'])
    client = app.test_client()
    created = client.post('/api/scans', json={'target': '127.0.0.1', 'profile': 'comprehensive',
        'tools': ['nmap', 'httpx', 'nuclei'], 'authorized': True},
        headers=dict(HEADERS, **{'Idempotency-Key': 'redaction-scan-0001'}))
    assert created.status_code == 202, created.json
    data = finish(client, created.json['data']['id'])
    return app, client, data


def test_secrets_never_reach_results_history_api_or_reports(tmp_path, monkeypatch):
    app, client, data = _run_secret_scan(tmp_path, monkeypatch, NUCLEI_WITH_SECRETS)
    try:
        assert data['state'] == 'completed', data['executions']
        assert data['findings'], 'the synthetic finding must still be reported'
        assert data['findings'][0]['details']['source_tool'] == 'nuclei'

        history = client.get('/api/scans/' + data['id'], headers=HEADERS).json['data']
        dashboard = client.get('/api/dashboard', headers=HEADERS).json['data']
        html = client.get('/api/scans/' + data['id'] + '/report', headers=HEADERS).text
        listing = client.get('/api/scans/' + data['id'] + '/findings', headers=HEADERS).json['data']
        directory = Path(app.extensions['database'].url.database).parent
        json_report = next(directory.glob('reports/*/*/vulnerabilities.json')).read_text(encoding='utf-8')
        scan_report = next(directory.glob('reports/*/*/scan.json')).read_text(encoding='utf-8')

        for surface, payload in (('scan payload', json.dumps(data)), ('history', json.dumps(history)),
                                ('dashboard', json.dumps(dashboard)), ('findings list', json.dumps(listing)),
                                ('html report', html), ('vulnerabilities.json', json_report),
                                ('scan.json', scan_report)):
            for label, secret in SECRETS.items():
                assert secret not in payload, f'{label} leaked {label}:{secret}'
            assert 'synthetic-secret-probe' in payload or surface == 'dashboard'
        # The scan is still a genuine finding, not an empty scrubbed one.
        assert 'Cookie without Secure flag' in json.dumps(history)
        assert '[REDACTED]' in json_report and '[REDACTED]' in html
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_malformed_response_cannot_leak_a_secret_through_the_error(tmp_path, monkeypatch):
    """Parser failures report the exception type, never the raw payload text."""
    app, client, data = _run_secret_scan(tmp_path, monkeypatch,
        'not json at all api_key=' + SECRETS['api_key'] + ' password=' + SECRETS['password'])
    try:
        execution = next(e for e in data['executions'] if e['tool'] == 'nuclei')
        assert execution['state'] == 'failed'
        assert execution['error'] == 'Unsupported or malformed nuclei output (JSONDecodeError).'
        assert data['state'] == 'completed_with_errors'
        assert data['findings'] == []
        assert SECRETS['api_key'] not in json.dumps(data) and SECRETS['password'] not in json.dumps(data)
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_tool_failure_output_is_redacted_in_the_execution_error(tmp_path, monkeypatch):
    """A failed tool's diagnostics are redacted before they are stored or returned."""
    def fake_run(argv, **kwargs):
        return ProcessResult('failed', stderr='login failed for api_key=' + SECRETS['api_key']
                             + ' using Authorization: Bearer ' + SECRETS['authorization_bearer'], exit_code=2)

    monkeypatch.setattr('backend.services.scan_service.find_argv', lambda commands: '/mock/' + commands[0])
    monkeypatch.setattr('backend.services.scan_service.verify', lambda *args: (True, 'mock version'))
    monkeypatch.setattr('backend.services.scan_service.run', fake_run)
    app = create_app(Settings(tmp_path / 'data', TOKEN, ('127.0.0.1',), True))
    app.config['TESTING'] = True
    _register_target(app, ['port_scan'])
    try:
        client = app.test_client()
        created = client.post('/api/scans', json={'target': '127.0.0.1', 'profile': 'comprehensive',
            'tools': ['nmap'], 'authorized': True}, headers=dict(HEADERS, **{'Idempotency-Key': 'redaction-error-scan'}))
        assert created.status_code == 202, created.json
        data = finish(client, created.json['data']['id'])
        execution = data['executions'][0]
        assert execution['state'] == 'failed'
        assert '[REDACTED]' in execution['error']
        assert SECRETS['api_key'] not in execution['error']
        assert SECRETS['authorization_bearer'] not in execution['error']
        assert SECRETS['api_key'] not in json.dumps(data)
    finally:
        app.extensions['scan_manager'].shutdown()
        app.extensions['database'].dispose()


def test_json_string_and_structured_secret_redaction():
    """Finding 4: Redaction covers JSON strings containing token, password, and api_key fields."""
    fake_token = 'FAKE_SYNTH_TOKEN_99'
    fake_pw = 'FAKE_SYNTH_PW_88'
    fake_key = 'FAKE_SYNTH_KEY_77'

    # Plain JSON string
    raw_json = json.dumps({'token': fake_token, 'password': fake_pw, 'endpoint': '/api/test'})
    cleaned = redact(raw_json)
    assert fake_token not in cleaned
    assert fake_pw not in cleaned
    assert '/api/test' in cleaned
    assert '[REDACTED]' in cleaned

    # JSON with api_key
    raw_api = f'{{"api_key": "{fake_key}", "public_info": "safe-value"}}'
    cleaned_api = redact(raw_api)
    assert fake_key not in cleaned_api
    assert 'safe-value' in cleaned_api
    assert '[REDACTED]' in cleaned_api


def test_basic_auth_url_redaction():
    """Finding 4: Basic Auth URLs redact embedded passwords without destroying the endpoint host/path."""
    fake_secret = 'super-secret-password-123'
    url = f'https://testuser:{fake_secret}@example.invalid/api/v1/resource?query=1'
    cleaned = redact(url)
    assert fake_secret not in cleaned
    assert 'testuser:[REDACTED]@example.invalid' in cleaned
    assert '/api/v1/resource?query=1' in cleaned


def test_colon_separated_key_values_redaction():
    """Finding 4: Colon-separated key:value formats are sanitized properly."""
    fake_val = 'SYNTH_SECRET_VAL_456'
    lines = f'api_key: {fake_val}\npassword: {fake_val}\nstatus: active'
    cleaned = redact(lines)
    assert fake_val not in cleaned
    assert 'status: active' in cleaned
    assert 'api_key: [REDACTED]' in cleaned
    assert 'password: [REDACTED]' in cleaned

