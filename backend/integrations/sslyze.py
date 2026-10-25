"""SSLyze JSON v6 adapter. Only protocol/cipher and certificate checks.

SSLyze is installed as a Python package and invoked via ``python -m sslyze``
rather than its console-script wrapper (sslyze.exe), which is blocked by
Windows Application Control policy on this host. The MODULE_BASED flag tells
``executables.py`` to resolve this tool as ``[python_exe, "-m", "sslyze"]``
so the approved virtual-environment interpreter is always used.
"""
import json
from urllib.parse import urlsplit
from .base import Results, asset, finding, web_url, literal, argv_prefix
NAME = 'sslyze'
COMMANDS = ('sslyze',)
# Invoke via ``python -m sslyze``; the console-script exe is blocked by policy.
MODULE_BASED = True
MODULE_NAME = 'sslyze'
VERSION_ARGS = ['--help']
IDENTITY = 'SSLyze version'
FILE_OUTPUT = True
PURPOSE = 'TLS protocols, accepted cipher suites, and certificate validation (independent SSLyze tool).'
CHECKS = ('ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
          'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'certificate_info')


def matches_identity(output):
    """SSLyze 6.x --help prints 'SSLyze version X.Y.Z'; confirm the exact word."""
    return 'sslyze version' in output.lower() and bool(
        __import__('re').search(r'\d+\.\d+', output)
    )


def parse_version(output):
    """Read the installed version from package metadata (SSLyze has no --version flag).

    ``output`` is the combined stdout+stderr of the ``--help`` probe and is not
    used for the version number itself; the canonical source is
    ``importlib.metadata``, which reads the dist-info written by pip and is not
    affected by policy-blocked console scripts.
    """
    try:
        import importlib.metadata
        version = importlib.metadata.version('sslyze')
        if version:
            return version
    except Exception:  # pragma: no cover – metadata absent in some test envs
        pass
    # Fallback: parse 'SSLyze version X.Y.Z' from help text.
    import re
    m = re.search(r'SSLyze version\s+(\S+)', output, re.IGNORECASE)
    return m.group(1) if m else None


def command(executable, target, profile, output):
    url = urlsplit(web_url(target))
    if url.scheme != 'https': raise ValueError('SSLyze requires HTTPS.')
    return [*argv_prefix(executable), '--json_out', str(output), '--quiet',
            '--mozilla_config=disable', '--sslv2', '--sslv3', '--tlsv1', '--tlsv1_1', '--tlsv1_2', '--tlsv1_3',
            '--certinfo', url.netloc]


def parse(text, target):
    data = json.loads(text)
    if not isinstance(data, dict) or data.get('invalid_server_strings') or not data.get('server_scan_results'):
        raise ValueError('Missing or invalid SSLyze scan results.')
    wanted = urlsplit(web_url(target))
    result = Results()
    for server in data['server_scan_results']:
        loc = server['server_location']
        if literal(loc['ip_address']) != literal(wanted.hostname) or int(loc['port']) != (wanted.port or 443):
            raise ValueError('Out-of-scope SSLyze result.')
        if server.get('scan_status') != 'COMPLETED' or server.get('connectivity_status') != 'COMPLETED':
            raise ValueError('TLS connectivity or scan did not complete.')
        scans = server['scan_result']
        for check in CHECKS:
            attempt = scans.get(check) or {}
            if attempt.get('status') != 'COMPLETED':
                result.errors.append(check)
                continue
            if not isinstance(attempt.get('result'), dict):
                raise ValueError('Malformed SSLyze check result.')
            value = attempt['result']
            if check == 'certificate_info':
                deployments = value.get('certificate_deployments')
                if not deployments: raise ValueError('Certificate assessment missing.')
                for i, deployment in enumerate(deployments):
                    validations = deployment.get('path_validation_results') or []
                    if not validations: raise ValueError('Certificate trust checks missing.')
                    trusted = any(v.get('was_validation_successful') is True for v in validations)
                    hostname = deployment.get('leaf_certificate_subject_matches_hostname')
                    # SSLyze 6 validates the requested subject inside path validation.
                    # It no longer emits the separate legacy hostname boolean.
                    evidence = {'trusted_by_a_tested_store': trusted, 'subject_validation': 'included in trust-store path validation', 'hostname_matches_if_reported': hostname,
                                'trust_results': [{'store': v.get('trust_store', {}).get('name'),
                                                   'success': v.get('was_validation_successful'), 'error': v.get('validation_error')} for v in validations]}
                    result.assets.append(asset(target, 'tls_certificate', source=NAME, **evidence))
                    if not trusted or hostname is False:
                        result.findings.append(finding('TLS certificate validation failed', target, NAME,
                            f'certificate:{i}', 'medium', evidence=evidence,
                            remediation='Check certificate chain, expiry and subject names. IP-based checks can miss hostname/SNI certificates.'))
            else:
                accepted = value.get('accepted_cipher_suites')
                if not isinstance(accepted, list): raise ValueError('Missing cipher results.')
                ciphers = [v['cipher_suite']['name'] for v in accepted]
                result.assets.append(asset(target, 'tls_protocol', source=NAME, protocol=check, accepted_ciphers=ciphers))
                if accepted and check in CHECKS[:4]:
                    result.findings.append(finding('Obsolete TLS/SSL protocol supported', target, NAME, check,
                        'high' if check.startswith('ssl_') else 'medium', evidence={'protocol': check, 'ciphers': ciphers},
                        remediation='Disable obsolete protocols after compatibility testing.'))
    return result
