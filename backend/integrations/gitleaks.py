import json
from pathlib import Path
from .base import Results, finding, argv_prefix
from ..services.local_scope import relative_file
NAME = 'gitleaks'
COMMANDS = ('gitleaks',)
VERSION_ARGS = ['version']
IDENTITY = ''  # CLI version is numeric; identity is verified with help flags.
FILE_OUTPUT = True
PURPOSE = 'Potential secrets in authorized local working-tree files; no Git history.'


def command(executable, target, profile, output):
    if not Path(target).is_absolute() or not Path(target).is_dir(): raise ValueError('Local snapshot required.')
    return [*argv_prefix(executable), 'dir', '--redact=100', '--no-banner', '--exit-code=0',
            '--report-format=json', '--report-path=' + str(output), '--max-target-megabytes=10', target]


def parse(text, target):
    rows = json.loads(text)
    if not isinstance(rows, list): raise ValueError('Expected Gitleaks array.')
    result = Results()
    for row in rows:
        file = relative_file(row['File'], target)
        line = int(row['StartLine'])
        rule = str(row['RuleID'])
        # Whitelist location fields; Match, Secret, Line, Message and author metadata never persist.
        result.findings.append(finding('Potential exposed credential', target, NAME,
            f'{rule}:{file}:{line}:{row.get("StartColumn", 0)}', 'high',
            category='local_source_secret', evidence={'rule_id': rule, 'file': file, 'line': line,
            'value': '[REDACTED]'}, remediation='Validate locally, revoke or rotate exposed credentials, then remove them from source.'))
    return result
