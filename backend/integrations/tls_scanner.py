import json
from urllib.parse import urlsplit
from .base import Results, finding, web_url, argv_prefix
NAME = 'testssl'
COMMANDS = ('testssl.sh', 'testssl')
VERSION_ARGS = ['--version']
IDENTITY = 'testssl'
FILE_OUTPUT = True


def command(executable, target, profile, output):
    parsed = urlsplit(web_url(target))
    if parsed.scheme != 'https':
        raise ValueError('TLS requires an HTTPS endpoint.')
    return [*argv_prefix(executable), '--quiet', '--warnings', 'off', '--color', '0', '--protocols',
            '--connect-timeout', '5', '--openssl-timeout', '5', '--jsonfile', str(output), parsed.netloc]



def parse(text, target):
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError('Expected flat testssl JSON array.')
    result = Results()
    for row in rows:
        severity = row.get('severity', '').lower()
        if severity in {'ok', 'info'}:
            continue
        if severity in {'fatal', 'error'}:
            raise ValueError('testssl reported an execution failure.')
        result.findings.append(finding(row.get('finding', 'TLS observation'), target, NAME, row['id'],
            severity, evidence=row, remediation='Review protocol support and disable obsolete TLS versions after compatibility testing.'))
    return result
