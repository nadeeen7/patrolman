"""Conservative normalization, redaction, stable identity and explained priority."""
import hashlib
import json
import math
import re
from urllib.parse import urlsplit, urlunsplit

SEVERITIES = ('critical', 'high', 'medium', 'low', 'informational', 'unknown')
BASE = {'critical': 90, 'high': 70, 'medium': 50, 'low': 25, 'informational': 0, 'unknown': 0}
SECRET = re.compile(
    r'(authorization|cookie|set[-_]?cookie|password|passwd|credentials?|secret|api[-_]?key|(?:access[-_]?|auth[-_]?)?token|session[-_]?id|bearer|private[-_]?key)',
    re.I,
)


def sanitize_secrets(value, max_length=None):
    """Sanitize secrets from dictionaries, lists, JSON payloads, URLs and text strings.
    
    If max_length is an integer, output strings are clamped to max_length (used by redact()).
    """
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if SECRET.search(str(k)) else sanitize_secrets(v, max_length) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_secrets(item, max_length) for item in value[:1000]]
    if isinstance(value, str):
        stripped = value.strip()
        if (stripped.startswith('{') and stripped.endswith('}')) or (stripped.startswith('[') and stripped.endswith(']')):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, (dict, list)):
                    serialized = json.dumps(sanitize_secrets(parsed, max_length))
                    return serialized[:max_length] if max_length else serialized
            except Exception:
                pass
        # Basic Auth in URLs: https://user:password@domain/ -> https://user:[REDACTED]@domain/
        value = re.sub(r'(?i)(https?://[^:/@\s]+):[^@\s/]+(@)', r'\1:[REDACTED]\2', value)
        # Sensitive HTTP headers
        value = re.sub(r'(?im)\b(Authorization|Cookie|Set-Cookie|X-[A-Za-z0-9-]*API-Key)\s*:[^\r\n]*', r'\1: [REDACTED]', value)
        # Bearer tokens
        value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', value)
        # JSON / quoted key-value pairs with colon
        value = re.sub(
            r'(?i)("(?:api[ _-]?key|(?:access[-_]?|auth[-_]?)?token|password|passwd|credentials?|private[ _-]?key|secret|session[ _-]?id|session|phpsessid|jsessionid)"\s*:\s*)"[^"]*"',
            r'\1"[REDACTED]"',
            value,
        )
        value = re.sub(
            r"(?i)('(?:api[ _-]?key|(?:access[-_]?|auth[-_]?)?token|password|passwd|credentials?|private[ _-]?key|secret|session[ _-]?id|session|phpsessid|jsessionid)'\s*:\s*)'[^']*'",
            r"\1'[REDACTED]'",
            value,
        )
        # Unquoted colon key-values (e.g. YAML or free-text lines)
        value = re.sub(
            r'(?i)\b((?:api[ _-]?key|(?:access[-_]?|auth[-_]?)?token|password|passwd|credentials?|private[ _-]?key|secret|session[ _-]?id|phpsessid|jsessionid)\s*:\s*)(?!\[REDACTED\])[^\s,;&}\r\n]+',
            r'\1[REDACTED]',
            value,
        )
        # Query parameter and prose key=value formats
        value = re.sub(
            r'(?i)((?:api[ _-]?key|(?:access[-_]?|auth[-_]?)?token|password|passwd|credentials?|private[ _-]?key|secret|session[ _-]?id|session|phpsessid|jsessionid)=)[^&\s]+',
            r'\1[REDACTED]',
            value,
        )
        return value[:max_length] if max_length else value
    return value


def redact(value):
    return sanitize_secrets(value, max_length=16000)


def canonical_endpoint(value):
    parts = urlsplit(value)
    if parts.scheme in {'http', 'https'}:
        host = (parts.hostname or '').lower()
        host = '[' + host + ']' if ':' in host else host
        port = parts.port
        if port and port != {'http': 80, 'https': 443}[parts.scheme]:
            host += ':' + str(port)
        return urlunsplit((parts.scheme, host, parts.path or '/', parts.query, ''))
    return value.lower()


def normalize(item):
    result = redact(dict(item))
    original = str(item.get('severity', 'unknown')).lower()
    severity = {'info': 'informational', 'warn': 'unknown', 'warning': 'unknown'}.get(original, original)
    if severity not in SEVERITIES:
        severity = 'unknown'
    classification = item.get('classification') or {}
    score = classification.get('cvss-score')
    vector = classification.get('cvss-metrics', '')
    version = next((v for v in ('3.0', '3.1', '4.0') if isinstance(vector, str) and vector.startswith('CVSS:' + v + '/')), None)
    valid_cvss = isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 10 and version
    if valid_cvss:
        severity = 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low' if score > 0 else 'informational'
    cves = classification.get('cve-id') or []
    if isinstance(cves, str):
        cves = [cves]
    cves = sorted({value.upper() for value in cves if isinstance(value, str) and re.fullmatch(r'CVE-\d{4}-\d{4,}', value, re.I)})
    endpoint = item['target'] if item.get('category', '').startswith(('local_', 'filesystem_')) else canonical_endpoint(item['target'])
    identity = '|'.join(cves) if cves and not item.get('category') else item['source_tool'] + ':' + str(item['source_identifier'])
    identity += ':' + str(item.get('matcher_name', ''))
    status = item.get('status')
    if severity == 'informational' and status in (None, '', 'potential'):
        status = 'informational'
    elif not status or status not in {'confirmed', 'potential', 'informational', 'inconclusive'}:
        status = 'informational' if severity == 'informational' else 'potential'
    fingerprint = hashlib.sha256((endpoint + '|' + identity).encode()).hexdigest()
    result.update(fingerprint=fingerprint, target=redact(endpoint), severity=severity,
                  original_severity=original, cve_id=cves or None,
                  cvss_score=score if valid_cvss else None, cvss_version=version if valid_cvss else None,
                  status=status, confidence=item.get('confidence', 'scanner-reported'),
                  priority=BASE[severity], risk_reason=('Scanner-provided CVSS score with versioned vector.' if valid_cvss else
                  'Severity mapping from scanner; no validated CVSS score available.') + ' Priority is a custom 0–100 ordering, not CVSS.',
                  sources=[{'tool': item['source_tool'], 'identifier': str(item['source_identifier']),
                            'evidence': redact(item.get('evidence')), 'original_severity': original,
                            'title': redact(item.get('title')), 'description': redact(item.get('description')),
                            'remediation': redact(item.get('remediation'))}])
    return result


def deduplicate(items):
    merged = {}
    for item in items:
        value = normalize(item)
        key = value['fingerprint']
        if key not in merged:
            merged[key] = value
        else:
            current = merged[key]
            sources = current['sources'] + [source for source in value['sources'] if source not in current['sources']]
            if value['priority'] > current['priority']:
                merged[key] = value
            merged[key]['sources'] = sources
    return list(merged.values())
