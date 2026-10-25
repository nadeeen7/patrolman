from pathlib import Path
import hashlib
import json
from urllib.parse import urlsplit
from .base import Results, finding, json_lines, web_url, argv_prefix

NAME = 'nuclei'
COMMANDS = ('nuclei',)
VERSION_ARGS = ['-version']
IDENTITY = 'Nuclei'


def _origin(value):
    """Return (scheme, host, port) for a URL or host target."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if '://' not in text:
        text = 'http://' + text
    try:
        parts = urlsplit(text)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in {'http', 'https'} or not host:
        return None
    return parts.scheme, host.lower(), port or (443 if parts.scheme == 'https' else 80)


def command(executable, target, profile, output, rate_limit=None):
    templates_dir = Path(__file__).resolve().parents[1] / 'nuclei_templates'
    metadata = json.loads((templates_dir / 'UPSTREAM.json').read_text())
    expected = metadata.get('templates', {})
    template_args = []
    if expected:
        for name, expected_hash in expected.items():
            template_path = templates_dir / name
            if not template_path.is_file():
                continue
            if hashlib.sha256(template_path.read_bytes()).hexdigest() != expected_hash:
                raise ValueError(f'Reviewed template checksum mismatch: {name}')
            template_args.extend(['-t', str(template_path)])
    if not template_args:
        single = templates_dir / 'http-missing-security-headers.yaml'
        if hashlib.sha256(single.read_bytes()).hexdigest() != metadata.get('sha256'):
            raise ValueError('Reviewed template checksum mismatch.')
        template_args = ['-t', str(single)]

    rl = str(min(2, max(1, int(rate_limit)))) if rate_limit is not None else '2'
    return [*argv_prefix(executable), '-u', web_url(target), *template_args, '-jsonl', '-silent', '-rl', rl, '-c', '1',
            '-bs', '1', '-timeout', '5', '-retries', '0', '-ni', '-dr', '-duc', '-omit-raw', '-no-stdin']


def parse(text, target):
    target_origin = _origin(target)
    result = Results()
    for row in json_lines(text):
        info = row.get('info', {})
        matched = row.get('matched-at', target)
        matched_origin = _origin(matched)
        if target_origin and matched_origin != target_origin:
            raise ValueError('Nuclei returned an out-of-scope endpoint.')
        elif not target_origin and matched.rstrip('/') != target.rstrip('/'):
            raise ValueError('Nuclei returned an out-of-scope endpoint.')

        name = info.get('name', 'Nuclei match')
        matcher_name = row.get('matcher-name')
        if matcher_name and str(matcher_name).lower() not in name.lower():
            title = f"{name} ({matcher_name})"
        else:
            title = name

        evidence = {}
        if matcher_name:
            evidence['matcher'] = matcher_name
        if row.get('curl-command'):
            evidence['curl_command'] = row.get('curl-command')
        if row.get('extracted-results'):
            evidence['extracted_results'] = row.get('extracted-results')
        if not evidence:
            evidence = None

        references = info.get('reference') or []
        if isinstance(references, str):
            references = [references]
        elif isinstance(references, dict):
            references = list(references.values())

        tags = info.get('tags') or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(',') if t.strip()]

        result.findings.append(finding(
            title,
            matched,
            NAME,
            row.get('template-id', 'nuclei-match'),
            severity=info.get('severity', 'unknown'),
            description=info.get('description'),
            matcher_name=matcher_name,
            remediation=info.get('remediation'),
            evidence=evidence,
            references=references,
            tags=tags,
            classification=info.get('classification', {})
        ))
    return result
