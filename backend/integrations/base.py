import ipaddress
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class Results:
    assets: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def argv_prefix(executable):
    if isinstance(executable, (list, tuple)):
        return list(executable)
    return [executable]



def json_lines(text):
    values = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not all(isinstance(row, dict) for row in values):
        raise ValueError('Expected JSON objects.')
    return values


def literal(value):
    return str(ipaddress.ip_address(value))


def web_url(value):
    parts = urlsplit(value)
    if parts.scheme not in {'http', 'https'} or parts.username or parts.password or parts.fragment:
        raise ValueError('Expected a literal-IP web URL.')
    literal(parts.hostname)
    if parts.path not in {'', '/'} or parts.query:
        raise ValueError('Only root service URLs are supported.')
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ValueError('Invalid port.')
    return value


def asset(address, kind, **details):
    return {'address': address, 'kind': kind, 'details': details}


def finding(title, target, source, identifier, severity='unknown', **details):
    default_status = 'informational' if str(severity).lower() in {'info', 'informational'} else 'potential'
    status = details.pop('status', default_status)
    return dict(title=title, target=target, source_tool=source, source_identifier=str(identifier),
                severity=severity, status=status, confidence='scanner-reported', **details)
