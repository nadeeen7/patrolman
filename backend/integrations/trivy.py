import json
import os
from pathlib import Path
from .base import Results, asset, finding, argv_prefix
from ..services.local_scope import relative_file
NAME = 'trivy'
COMMANDS = ('trivy',)
VERSION_ARGS = ['--version']
IDENTITY = 'Version:'
FILE_OUTPUT = True
PURPOSE = 'Offline filesystem dependency vulnerabilities, configuration and secret checks; not a web penetration test.'


def discover_cache():
    """Find an already-existing Trivy cache with its official vulnerability DB."""
    candidates = []
    configured = os.getenv('TRIVY_CACHE_DIR')
    if configured:
        candidates.append(Path(configured))
    local = Path(os.getenv('LOCALAPPDATA', ''))
    user = Path(os.getenv('USERPROFILE', str(Path.home())))
    roaming = Path(os.getenv('APPDATA', ''))
    candidates.extend((
        local / 'trivy',
        local / 'Cache' / 'trivy',
        user / '.cache' / 'trivy',
        user / '.trivy',
        roaming / 'trivy',
    ))
    for candidate in candidates:
        try:
            if candidate.is_dir() and (candidate / 'db' / 'trivy.db').is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def configuration_error():
    scanners = os.getenv('AVA_TRIVY_SCANNERS', 'vuln').split(',')
    if not scanners or any(s not in {'vuln', 'misconfig', 'secret'} for s in scanners):
        return 'AVA_TRIVY_SCANNERS must select vuln,misconfig,secret.'
    path = Path(os.getenv('AVA_TRIVY_CACHE_DIR', ''))
    if not path.is_absolute() or not path.is_dir():
        if 'vuln' in scanners:
            return ('Vulnerability database scanning is unavailable until AVA_TRIVY_CACHE_DIR points to a '
                    'dedicated local cache containing the official db/trivy.db.')
        return 'Configure AVA_TRIVY_CACHE_DIR as a dedicated local cache directory.'
    if 'vuln' in scanners and not (path / 'db' / 'trivy.db').is_file():
        return 'Vulnerability database scanning is unavailable: the official db/trivy.db is absent from AVA_TRIVY_CACHE_DIR.'
    return None


def runtime_status():
    scanners = os.getenv('AVA_TRIVY_SCANNERS', 'vuln').split(',')
    cache = Path(os.getenv('AVA_TRIVY_CACHE_DIR', ''))
    database_available = (cache / 'db' / 'trivy.db').is_file()
    issue = configuration_error()
    if issue:
        return 'configuration_required', issue
    if 'vuln' not in scanners and not database_available:
        return 'configured', ('Offline configuration/secret scanners are configured. Vulnerability database scanning is '
                              'unavailable because no official db/trivy.db is present in the configured cache.')
    return 'configured', 'Configured offline scanners and their required local cache are available.'


def command(executable, target, profile, output):
    if not Path(target).is_absolute() or not Path(target).is_dir(): raise ValueError('Local snapshot required.')
    error = configuration_error()
    if error: raise ValueError(error)
    scanners = os.getenv('AVA_TRIVY_SCANNERS', 'vuln').split(',')
    if not scanners or any(s not in {'vuln', 'misconfig', 'secret'} for s in scanners):
        raise ValueError('AVA_TRIVY_SCANNERS must select vuln,misconfig,secret.')
    return [*argv_prefix(executable), 'filesystem', '--format', 'json', '--output', str(output),
            '--scanners', ','.join(scanners), '--cache-dir', os.environ['AVA_TRIVY_CACHE_DIR'],
            '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
            '--skip-version-check', '--skip-vex-repo-update', '--disable-telemetry', '--no-progress', '--timeout', '60s',
            '--parallel', '1', '--exit-code', '0', target]


def parse(text, target):
    data = json.loads(text)
    if not isinstance(data, dict) or data.get('SchemaVersion') != 2 or 'ArtifactName' not in data:
        raise ValueError('Unsupported Trivy schema.')
    rows = data.get('Results') or []
    if not isinstance(rows, list): raise ValueError('Expected Trivy results.')
    result = Results(assets=[asset(target, 'local_filesystem', source=NAME, category='filesystem_dependency',
                                  database=data.get('Metadata', {}).get('DB'))])
    for row in rows:
        file = relative_file(row['Target'], target)
        for v in row.get('Vulnerabilities') or []:
            result.findings.append(finding(v['VulnerabilityID'] + ' in ' + v['PkgName'], target, NAME,
                ':'.join([file, v['PkgName'], v.get('InstalledVersion', ''), v['VulnerabilityID'], v.get('PkgID', '')]),
                v.get('Severity', 'unknown'), category='filesystem_dependency',
                evidence={'file': file, 'package': v['PkgName'], 'installed_version': v.get('InstalledVersion'),
                          'fixed_version': v.get('FixedVersion'), 'vulnerability_id': v['VulnerabilityID']},
                remediation='Review the reported fixed version and dependency compatibility.'))
        for v in row.get('Misconfigurations') or []:
            if v.get('Status') == 'PASS': continue
            result.findings.append(finding('Configuration check: ' + v['ID'], target, NAME, file + ':' + v['ID'] + ':' + str((v.get('CauseMetadata') or {}).get('StartLine', '')),
                v.get('Severity', 'unknown'), category='filesystem_configuration',
                evidence={'file': file, 'id': v['ID'], 'status': v.get('Status'), 'start_line': (v.get('CauseMetadata') or {}).get('StartLine'), 'end_line': (v.get('CauseMetadata') or {}).get('EndLine')}, remediation='Review the configuration locally.'))
        for v in row.get('Secrets') or []:
            result.findings.append(finding('Potential exposed credential', target, NAME,
                f'{file}:{v["RuleID"]}:{v.get("StartLine")}', v.get('Severity', 'high'), category='local_source_secret',
                evidence={'file': file, 'rule_id': v['RuleID'], 'line': v.get('StartLine'), 'value': '[REDACTED]'},
                remediation='Validate locally and rotate the credential.'))
    return result
