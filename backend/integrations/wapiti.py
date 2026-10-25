"""Wapiti web application scanner adapter.

Wapiti is an active web vulnerability scanner, so this adapter is deliberately
conservative:

* the tool stays safety-disabled until an operator sets ``AVA_WAPITI_ENABLED``;
* only an explicit, validated module list is ever passed (``-m``), never
  ``all``/``common``, and modules that need an out-of-band callback endpoint,
  that brute-force credentials or that probe unrelated network devices are
  refused outright;
* the crawl scope is forced to the exact base URL (``--scope url``), the
  request rate knobs are pinned (``-S paranoid``, ``--tasks 1``, ``-l 1``) and
  both a scan and per-module deadline are always supplied;
* every destination must be a literal IP address URL, so Wapiti can never be
  used to reach a host the framework has not already resolved and authorized.

The adapter does not claim network isolation. Wapiti's HTTP client follows
redirects for the requests it issues, and the application cannot inspect host
firewall state or prove egress isolation.
"""
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit, urlunsplit

from .base import Results, argv_prefix, asset, finding
from ..services.results import redact

NAME = 'wapiti'
COMMANDS = ('wapiti', 'wapiti3')
VERSION_ARGS = ['--version']
# ``wapiti --version`` prints only the bare version (for example ``3.3.2``),
# so identity is confirmed by parsing that value rather than by a product word.
IDENTITY = ''
FILE_OUTPUT = True
HELP_ARGS = ['--help']
# Every option this adapter builds must still be advertised by the installed
# release; an unsupported option is reported instead of being silently dropped.
HELP_FLAGS = ('--scope', '--flush-session', '-m', '-f', '-o', '--max-scan-time',
              '--max-attack-time', '--scan-force', '--tasks', '--no-bugreport')
OPT_IN_ENV = 'AVA_WAPITI_ENABLED'
REMOTE_ENV = 'AVA_WAPITI_ALLOW_REMOTE_TARGETS'
MODULES_ENV = 'AVA_WAPITI_MODULES'
SCAN_FORCE_ENV = 'AVA_WAPITI_SCAN_FORCE'
SCAN_TIME_ENV = 'AVA_WAPITI_MAX_SCAN_TIME'
ATTACK_TIME_ENV = 'AVA_WAPITI_MAX_ATTACK_TIME'
TIMEOUT_ENV = 'AVA_WAPITI_HTTP_TIMEOUT'
PURPOSE = 'Active web vulnerability assessment with an explicit, bounded module list.'

# Modules that only inspect the response of a normal request. Safe default set.
DEFAULT_MODULES = ('http_headers', 'cookieflags', 'csp', 'methods')
# Injection and enumerating modules: strictly opt-in, still bounded by the
# scope, level, scan-force and deadline arguments above.
ACTIVE_MODULES = ('sql', 'xss', 'permanentxss', 'timesql', 'file', 'exec', 'crlf',
                  'redirect', 'backup', 'buster', 'csrf', 'upload', 'htaccess')
# Everything outside these two tuples is refused, including modules that need an
# external callback endpoint (out-of-band SSRF/XXE/Log4Shell style checks),
# credential-brute-force modules, unrelated network-device probes and modules
# that download extra databases. There is no "all" and no "common" expansion.
ALLOWED_MODULES = DEFAULT_MODULES + ACTIVE_MODULES
REFUSAL_REASON = (
    'PATROLMAN only permits the reviewed module set listed above. Modules that need an out-of-band '
    'callback endpoint, brute-force credentials, probe unrelated network devices or download extra '
    'databases are never permitted.'
)
SAFE_SCAN_FORCE = ('paranoid', 'sneaky', 'polite')
CAPABILITIES = (
    'Installation and version verification',
    'Bounded active web crawler (exact base URL scope)',
    'Security header, cookie flag, CSP and HTTP method checks by default',
    'Optional injection modules only when listed explicitly',
    'JSON report parsed into PATROLMAN findings with evidence and remediation',
)
DISABLED = ('Wapiti is safety-disabled until the operator explicitly sets '
            f'{OPT_IN_ENV}=true. Installing Wapiti alone never enables active web scanning.')
SAFETY_RESTRICTIONS = (
    'Explicit operator opt-in and authorization are required. Wapiti only runs against a literal IP '
    'target URL that PATROLMAN already resolved and authorized; non-loopback targets additionally '
    f'require {REMOTE_ENV}=true. The crawl scope is the exact base URL, the module list is explicit '
    f'(no "all"/"common"), and {SCAN_FORCE_ENV} is limited to paranoid/sneaky/polite with level 1, '
    'one task, a hard scan deadline and a per-module deadline. Out-of-band modules (SSRF, XXE, '
    'Log4Shell, Shellshock, Spring4Shell), credential attacks, unrelated network-device probes and '
    f'the Wappalyzer database downloader are refused. The application does not firewall or isolate '
    'Wapiti: its HTTP client still follows redirects for the requests it issues, so only scan servers '
    'you control.'
)
VERSION_PATTERN = re.compile(
    r'^\s*(?:wapiti(?:3)?\s*(?:version\s*)?[:\s]*)?v?(\d+\.\d+(?:\.\d+)?)\s*(?:\([^)]*\))?\s*$',
    re.IGNORECASE | re.MULTILINE,
)
LEVELS = {0: 'informational', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
REQUEST_LINE = re.compile(r'^([A-Z]+)\s+(\S+)\s+HTTP/\d\.\d$')
MAX_FINDINGS = 2000
MAX_STRING = 4000


def parse_version(text):
    """Return the version from ``wapiti --version`` style output, else None."""
    if not isinstance(text, str):
        return None
    plain = re.sub(r'\x1b\[[0-9;]*m', '', text)
    found = VERSION_PATTERN.search(plain)
    return found.group(1) if found else None


def matches_identity(text):
    return parse_version(text) is not None


def opt_in_enabled():
    """Report the documented operator opt-in. Off unless explicitly true."""
    return os.getenv(OPT_IN_ENV, 'false').strip().lower() == 'true'


def remote_targets_enabled():
    """Report whether non-loopback destinations are explicitly allowed."""
    return os.getenv(REMOTE_ENV, 'false').strip().lower() == 'true'


def _module_issue(modules):
    unknown = [name for name in modules if name not in ALLOWED_MODULES]
    if unknown:
        return ('Unsupported Wapiti module(s) ' + ', '.join(unknown) +
                '. Supported modules: ' + ', '.join(ALLOWED_MODULES) + '. ' + REFUSAL_REASON)
    return None


def enabled_modules():
    """Return the explicit, validated module list. Never an implicit set."""
    raw = os.getenv(MODULES_ENV)
    values = tuple(item.strip().lower() for item in (raw or '').split(',') if item.strip())
    return values or DEFAULT_MODULES


def scan_force():
    return (os.getenv(SCAN_FORCE_ENV) or 'paranoid').strip().lower()


def _bounded_int(variable, default, low, high):
    raw = (os.getenv(variable) or str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return None
    if not low <= value <= high:
        return None
    return value


def max_scan_time():
    return _bounded_int(SCAN_TIME_ENV, 120, 10, 120)


def max_attack_time():
    return _bounded_int(ATTACK_TIME_ENV, 60, 10, 120)


def http_timeout():
    return _bounded_int(TIMEOUT_ENV, 10, 1, 30)


def configuration_error():
    """Fail-closed static configuration gate; returns a message or None."""
    modules = enabled_modules()
    issue = _module_issue(modules)
    if issue:
        return issue
    if scan_force() not in SAFE_SCAN_FORCE:
        return (f'{SCAN_FORCE_ENV} must be one of {", ".join(SAFE_SCAN_FORCE)}; aggressive or insane '
                'scan forces are not accepted by PATROLMAN.')
    if max_scan_time() is None:
        return f'{SCAN_TIME_ENV} must be an integer between 10 and 120 seconds.'
    if max_attack_time() is None:
        return f'{ATTACK_TIME_ENV} must be an integer between 10 and 120 seconds.'
    if http_timeout() is None:
        return f'{TIMEOUT_ENV} must be an integer between 1 and 30 seconds.'
    return None


def runtime_status():
    issue = configuration_error()
    if issue:
        return 'configuration_required', issue
    modules = enabled_modules()
    active = [name for name in modules if name in ACTIVE_MODULES]
    if active:
        return 'configured', ('Explicit module list includes active checks (' + ', '.join(active) +
                              '). Scan scope, level, scan force, task count and deadlines are pinned by PATROLMAN.')
    return 'configured', ('Conservative response-inspection modules only (' + ', '.join(modules) +
                          '); no injection module is enabled.')


def validate_scan_url(value):
    """Return a canonical base URL or raise ValueError.

    Hostnames are refused outright: the framework already resolved and
    authorized a literal address, so resolving a name again would allow DNS
    rebinding and would silently widen scope. Alternate loopback spellings
    (``localhost``, ``127.1``, decimal integers, IPv4-mapped IPv6) are refused
    because they are exactly the SSRF bypass spellings.
    """
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 2048:
        raise ValueError('Wapiti requires an http(s) base URL.')
    if any(ord(character) < 0x21 or ord(character) == 0x7f for character in value):
        raise ValueError('Wapiti target URL contains control or whitespace characters.')
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError('Wapiti target URL is invalid.') from exc
    if parts.scheme not in {'http', 'https'} or not host:
        raise ValueError('Wapiti requires an http(s) URL with a host.')
    if parts.username or parts.password:
        raise ValueError('Credential-bearing Wapiti target URLs are prohibited.')
    if parts.fragment:
        raise ValueError('Wapiti target URLs must not contain a fragment.')
    if parts.query:
        raise ValueError('Wapiti only accepts a base URL; query parameters are generated by its scope.')
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError('Wapiti target must be a literal IP address; hostnames are never re-resolved.') from exc
    if address.version == 6 and address.ipv4_mapped:
        raise ValueError('IPv4-mapped IPv6 Wapiti targets are prohibited.')
    if address.is_multicast or address.is_unspecified or address.is_link_local:
        raise ValueError('Multicast, unspecified and link-local Wapiti targets are prohibited.')
    if not address.is_loopback and not remote_targets_enabled():
        raise ValueError(f'Non-loopback Wapiti targets require explicit {REMOTE_ENV}=true authorization.')
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Wapiti target port is invalid.')
    path = parts.path or '/'
    if not path.startswith('/') or '..' in path.split('/') or len(path) > 512:
        raise ValueError('Wapiti target path is invalid.')
    return urlunsplit((parts.scheme, parts.netloc, path, '', ''))


def command(executable, target, profile, output):
    """Build a bounded, non-aggressive Wapiti invocation."""
    url = validate_scan_url(target)
    issue = configuration_error()
    if issue:
        raise ValueError(issue)
    return [
        *argv_prefix(executable),
        '-u', url,
        '--scope', 'url',
        '--flush-session',
        '--no-bugreport',
        '-m', ','.join(enabled_modules()),
        '-l', '1',
        '-f', 'json',
        '-o', str(output),
        '-S', scan_force(),
        '--max-scan-time', str(max_scan_time()),
        '--max-attack-time', str(max_attack_time()),
        '--tasks', '1',
        '-t', str(http_timeout()),
    ]


def _origin(value):
    """Return (scheme, host, port) for a URL, or None when it is not one."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parts = urlsplit(value.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in {'http', 'https'} or not host:
        return None
    return parts.scheme, host.lower(), port or (443 if parts.scheme == 'https' else 80)


def _host_port(value, default_port):
    """Parse a Host header or authority into (host, port)."""
    text = value.strip()
    if '://' in text:
        parts = urlsplit(text)
        port = parts.port or default_port
        return (parts.hostname or '').lower(), port
    authority = text.split('/')[0]
    if authority.startswith('['):
        host, _, rest = authority[1:].partition(']')
        raw_port = rest[1:] if rest.startswith(':') else ''
    elif authority.count(':') == 1:
        host, raw_port = authority.rsplit(':', 1)
    else:
        host, raw_port = authority, ''
    try:
        port = int(raw_port) if raw_port else default_port
    except ValueError as exc:
        raise ValueError('Wapiti reported a request with an invalid Host header.') from exc
    return host.lower(), port


def _request_details(text):
    """Return (request target, Host header) from a serialized HTTP request."""
    if not isinstance(text, str) or not text.strip():
        return None, None
    lines = text.splitlines()
    match = REQUEST_LINE.match(lines[0].strip())
    if not match:
        return None, None
    host = None
    for line in lines[1:40]:
        if not line.strip():
            break
        name, _, value = line.partition(':')
        if name.strip().lower() == 'host':
            host = value.strip()
            break
    return match.group(2), host


def _clip(value):
    if not isinstance(value, str):
        return value
    return value[:MAX_STRING]


def _references(value):
    if isinstance(value, str):
        return [value[:500]]
    if isinstance(value, list):
        return [item[:500] for item in value if isinstance(item, str)][:10]
    if isinstance(value, dict):
        return [item[:500] for item in value.values() if isinstance(item, str)][:10]
def _classification(category, metadata):
    cwe_ids = set()
    cve_ids = set()
    if isinstance(category, str):
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', category, re.IGNORECASE)
        if cve_match:
            cve_ids.add(cve_match.group(0).upper())
    refs = metadata.get('ref') if isinstance(metadata, dict) else None
    if isinstance(refs, dict):
        for key, val in refs.items():
            for text in (key, val):
                if isinstance(text, str):
                    for m in re.finditer(r'CWE-(\d+)', text, re.IGNORECASE):
                        cwe_ids.add(f'cwe-{m.group(1)}')
                    for m in re.finditer(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE):
                        cve_ids.add(m.group(0).upper())
    elif isinstance(refs, list):
        for text in refs:
            if isinstance(text, str):
                for m in re.finditer(r'CWE-(\d+)', text, re.IGNORECASE):
                    cwe_ids.add(f'cwe-{m.group(1)}')
                for m in re.finditer(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE):
                    cve_ids.add(m.group(0).upper())
    classification = {}
    if cwe_ids:
        classification['cwe-id'] = sorted(cwe_ids)
    if cve_ids:
        classification['cve-id'] = sorted(cve_ids)
    return classification or None


def parse(text, target):
    """Normalize a Wapiti JSON report into PATROLMAN findings.

    The report is fully validated before any finding is accepted: the target
    origin must match, every reported request must address that same origin and
    an off-scope referer fails closed. Malformed individual entries are counted
    and skipped rather than trusted.
    """
    base = validate_scan_url(target)
    base_origin = _origin(base)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'Unsupported Wapiti JSON schema: {exc}') from exc
    if not isinstance(data, dict):
        raise ValueError('Unsupported Wapiti JSON schema.')
    vulnerabilities = data.get('vulnerabilities')
    if not isinstance(vulnerabilities, dict):
        raise ValueError('Unsupported Wapiti JSON schema: no vulnerabilities object.')
    infos = data.get('infos')
    if isinstance(infos, dict) and infos.get('target'):
        reported = infos['target']
        if not isinstance(reported, str) or _origin(reported) != base_origin:
            raise ValueError('Out-of-scope Wapiti report target.')
    classifications = data.get('classifications')
    classifications = classifications if isinstance(classifications, dict) else {}

    result = Results()
    seen = set()
    skipped = 0
    usable = False
    has_entries = False
    for category, entries in vulnerabilities.items():
        if not isinstance(category, str) or not isinstance(entries, list):
            skipped += 1
            continue
        if entries:
            has_entries = True
        metadata = classifications.get(category)
        metadata = metadata if isinstance(metadata, dict) else {}
        for entry in entries:
            if len(result.findings) >= MAX_FINDINGS:
                result.assets.append(asset(base, 'wapiti_report_issue', source=NAME,
                                           note='Finding limit reached; remaining entries were not imported.'))
                break
            if not isinstance(entry, dict):
                skipped += 1
                continue
            path = entry.get('path')
            if not isinstance(path, str) or not path.startswith('/'):
                skipped += 1
                continue
            usable = True
            request_target, host_header = _request_details(entry.get('http_request'))
            if request_target is not None and not request_target.startswith('/'):
                raise ValueError('Wapiti reported an absolute-form request target.')
            if host_header:
                target_port = urlsplit(base).port or (443 if base_origin[0] == 'https' else 80)
                if _host_port(host_header, target_port) != (base_origin[1], base_origin[2]):
                    raise ValueError('Wapiti returned an out-of-scope request.')
            referer = entry.get('referer')
            if isinstance(referer, str) and referer.strip() and _origin(referer) != base_origin:
                raise ValueError('Wapiti returned an out-of-scope referer.')
            method = str(entry.get('method') or 'GET').upper()[:16]
            module = str(entry.get('module') or 'unknown')[:64]
            raw_parameter = entry.get('parameter')
            parameter = '' if raw_parameter in (None, '') else str(raw_parameter)[:200]
            level = entry.get('level')
            severity = LEVELS.get(level, 'unknown') if isinstance(level, int) and not isinstance(level, bool) else 'unknown'
            parts = urlsplit(base)
            url = urlunsplit((parts.scheme, parts.netloc, path, '', ''))
            identifier = ':'.join(value for value in (module, method, path, parameter) if value)
            key = (category, identifier)
            if key in seen:
                continue
            seen.add(key)
            evidence = redact({
                'module': module,
                'method': method,
                'path': path,
                'parameter': parameter or None,
                'info': _clip(entry.get('info')),
                'wstg': entry.get('wstg') or metadata.get('wstg'),
                'curl_command': _clip(entry.get('curl_command')),
                'request': _clip(entry.get('http_request')),
            })
            result.findings.append(finding(
                category,
                redact(url),
                NAME,
                identifier,
                severity=severity,
                description=redact(metadata.get('desc')),
                remediation=redact(metadata.get('sol')),
                evidence=evidence,
                references=_references(metadata.get('ref')),
                classification=_classification(category, metadata),
            ))
    if (has_entries or skipped > 0) and not usable:
        # A report that contains entries but none usable is not a clean report.
        raise ValueError('Unsupported Wapiti JSON schema: no usable vulnerability entries.')
    if skipped:
        result.assets.append(asset(base, 'wapiti_report_issue', source=NAME, skipped_entries=skipped))
    anomalies = data.get('anomalies')
    if isinstance(anomalies, dict):
        for category, entries in anomalies.items():
            if isinstance(entries, list) and entries:
                result.assets.append(asset(base, 'wapiti_anomaly', source=NAME,
                                           category=str(category)[:120], count=len(entries)))
    return result
