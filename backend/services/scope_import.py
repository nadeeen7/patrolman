"""Deterministic, provider-neutral parser for offline bug-bounty scope data."""
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

from .scope_validator import KNOWN_METHODS, TOOL_METHOD_MAP
from .target_validation import TargetError, normalize_scope_asset

MAX_ASSETS = 2000
MAX_RESTRICTIONS = 100
PERMITTED_METHODS = {category for categories in TOOL_METHOD_MAP.values() for category in categories}


def _metadata_string(value, field, max_length):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise ValueError(f'{field} must be a non-empty string of at most {max_length} characters.')
    clean = value.strip()
    if any(ord(char) < 32 for char in clean):
        raise ValueError(f'{field} contains unsupported control characters.')
    return clean


def _source_url(value):
    source = _metadata_string(value, 'source_url', 1024)
    parsed = urlsplit(source)
    if (
        parsed.scheme not in {'http', 'https'}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError('source_url must be an HTTP(S) URL without credentials, query, or fragment.')
    return source


def _asset(item, index):
    if not isinstance(item, dict) or set(item) != {'asset_type', 'value', 'scope'}:
        raise ValueError(f'Asset #{index} must contain only asset_type, value, and scope.')
    asset_type = item['asset_type']
    scope = item['scope']
    value = item['value']
    if asset_type not in {'domain', 'ip', 'cidr', 'path'}:
        raise ValueError(f'Asset #{index} uses unsupported asset_type.')
    if scope not in {'included', 'excluded'}:
        raise ValueError(f'Asset #{index} must be included or excluded.')
    if asset_type == 'path':
        if scope != 'excluded' or not isinstance(value, str) or not value.startswith('/'):
            raise ValueError(f'Asset #{index} path entries must be excluded absolute paths.')
        if any(char in value for char in '?#\r\n\t\0') or '//' in value:
            raise ValueError(f'Asset #{index} has an ambiguous excluded path.')
        normalized = '/' + value.strip('/')
        if normalized == '':
            normalized = '/'
    else:
        if not isinstance(value, str):
            raise ValueError(f'Asset #{index} value must be a string.')
        try:
            normalized = normalize_scope_asset(value)
        except TargetError as exc:
            raise ValueError(f'Asset #{index} is malformed or ambiguous: {exc}') from exc
        is_network = '/' in normalized
        try:
            ipaddress.ip_address(normalized)
            is_ip = True
        except ValueError:
            is_ip = False
        if asset_type == 'cidr' and not is_network:
            raise ValueError(f'Asset #{index} must be a canonical CIDR network.')
        if asset_type == 'ip' and (not is_ip or is_network):
            raise ValueError(f'Asset #{index} must be a literal IP address.')
        if asset_type == 'domain' and (is_ip or is_network):
            raise ValueError(f'Asset #{index} must be a hostname.')
    return {'asset_type': asset_type, 'value': normalized, 'scope': scope}


def parse_offline_scope(payload):
    """Validate a provider-neutral fixture; never performs network access."""
    if not isinstance(payload, dict) or set(payload) != {
        'provider', 'program_id', 'source_url', 'fixture'
    }:
        raise ValueError('Import must contain provider, program_id, source_url, and fixture only.')
    provider = _metadata_string(payload['provider'], 'provider', 64)
    program_id = _metadata_string(payload['program_id'], 'program_id', 255)
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', program_id):
        raise ValueError('program_id contains unsupported characters.')
    source_url = _source_url(payload['source_url'])
    fixture = payload['fixture']
    allowed_fixture_fields = {
        'version', 'assets', 'permitted_methods', 'prohibited_methods', 'restrictions'
    }
    if not isinstance(fixture, dict) or set(fixture) - allowed_fixture_fields:
        raise ValueError('fixture has an unsupported structure or field.')

    raw_assets = fixture.get('assets')
    if not isinstance(raw_assets, list) or not raw_assets or len(raw_assets) > MAX_ASSETS:
        raise ValueError(f'fixture.assets must contain between 1 and {MAX_ASSETS} entries.')
    assets, invalid_entries = [], []
    for index, raw_asset in enumerate(raw_assets, 1):
        try:
            assets.append(_asset(raw_asset, index))
        except ValueError as exc:
            invalid_entries.append({'index': index, 'error': str(exc)})
    if not any(asset['scope'] == 'included' for asset in assets):
        invalid_entries.append({'index': 'assets', 'error': 'At least one valid included asset is required.'})

    methods = {}
    for field in ('permitted_methods', 'prohibited_methods'):
        raw_methods = fixture.get(field)
        if not isinstance(raw_methods, list) or not all(
            isinstance(method, str) and method.strip() for method in raw_methods
        ):
            invalid_entries.append({'index': field, 'error': f'{field} must be a list of non-empty strings.'})
            methods[field] = []
            continue
        normalized_methods = list(dict.fromkeys(method.strip() for method in raw_methods))
        allowed_methods = PERMITTED_METHODS if field == 'permitted_methods' else KNOWN_METHODS
        unknown = sorted(set(normalized_methods) - allowed_methods)
        if unknown:
            invalid_entries.append({'index': field, 'error': f'Unsupported method categories: {", ".join(unknown)}.'})
        methods[field] = [method for method in normalized_methods if method in KNOWN_METHODS]
    if not methods['permitted_methods']:
        invalid_entries.append({'index': 'permitted_methods', 'error': 'At least one permitted method is required.'})

    restrictions = fixture.get('restrictions', [])
    if (
        not isinstance(restrictions, list)
        or len(restrictions) > MAX_RESTRICTIONS
        or not all(isinstance(item, str) and item.strip() and len(item.strip()) <= 500 for item in restrictions)
    ):
        invalid_entries.append({'index': 'restrictions', 'error': 'Restrictions must be a list of short, non-empty strings.'})
        restrictions = []
    restrictions = list(dict.fromkeys(item.strip() for item in restrictions))

    version = fixture.get('version', 'unspecified')
    if not isinstance(version, str) or not version.strip() or len(version.strip()) > 128:
        invalid_entries.append({'index': 'version', 'error': 'version must be a non-empty string of at most 128 characters.'})
        version = 'invalid'
    else:
        version = version.strip()

    canonical = {
        'provider': provider,
        'program_id': program_id,
        'source_url': source_url,
        'version': version,
        'assets': sorted(assets, key=lambda item: (item['scope'], item['asset_type'], item['value'])),
        'permitted_methods': sorted(methods['permitted_methods']),
        'prohibited_methods': sorted(methods['prohibited_methods']),
        'restrictions': sorted(restrictions),
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()
    return {
        **canonical,
        'included_assets': [asset for asset in canonical['assets'] if asset['scope'] == 'included'],
        'excluded_assets': [asset for asset in canonical['assets'] if asset['scope'] == 'excluded'],
        'invalid_entries': invalid_entries,
        'digest': digest,
        'import_status': 'valid' if not invalid_entries else 'invalid',
    }
