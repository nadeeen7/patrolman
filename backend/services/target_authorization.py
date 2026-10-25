"""Scope validation and management for authorized assessment targets."""
from datetime import datetime, timezone
import re
from ..models import AuthorizedTarget, TargetAuditEvent, now
from .target_validation import normalize_scope_asset, normalize_target, TargetError

VALID_TARGET_TYPES = {'organization', 'client', 'bug_bounty', 'lab'}
VALID_STATUSES = {'active', 'inactive', 'revoked', 'pending_approval'}
DEFAULT_PERMITTED_METHODS = ['port_scan', 'web_service_discovery', 'tls_audit', 'vulnerability_check']
DEFAULT_PROHIBITED_METHODS = ['dos', 'exploit', 'credential_attack', 'active_crawl']


def parse_iso_datetime(value, field_name='date'):
    if not isinstance(value, str) or not value.strip():
        raise TargetError(f'{field_name} must be a valid ISO 8601 date string.')
    value = value.strip()
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise TargetError(f'{field_name} must be a valid ISO 8601 timestamp.') from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def validate_scope_item(item, allow_wildcards=False):
    if not isinstance(item, str) or not item or not item.strip():
        raise TargetError('Scope entry must be a non-empty string.')
    item = item.strip()
    if allow_wildcards and item.startswith('*.'):
        # We reject wildcard assumption: prompt strictly states:
        # "Do not assume that a parent domain automatically covers every related domain"
        # and "Reject ambiguous targets."
        raise TargetError('Wildcard scopes are prohibited. List explicit domains or subdomains individually.')
    try:
        return normalize_scope_asset(item)
    except TargetError as exc:
        raise TargetError(f'Invalid scope asset "{item}": {exc}') from exc


def validate_excluded_item(item):
    if not isinstance(item, str) or not item or not item.strip():
        raise TargetError('Excluded scope entry must be a non-empty string.')
    clean = item.strip()
    if any(c in clean for c in '\0\r\n\t'):
        raise TargetError('Excluded scope entry contains illegal control characters.')
    if len(clean) > 255:
        raise TargetError('Excluded scope entry exceeds 255 characters.')
    if clean.startswith('/'):
        if '?' in clean or '#' in clean or '//' in clean:
            raise TargetError('Excluded paths must be plain absolute paths without query or fragment values.')
        return '/' + clean.strip('/')
    try:
        return normalize_scope_asset(clean)
    except TargetError as exc:
        raise TargetError(f'Unsupported or invalid excluded scope entry "{clean}". Use a host, IP, CIDR, or absolute path.') from exc


def validate_target_payload(payload, is_update=False):
    if not isinstance(payload, dict):
        raise TargetError('Target payload must be a JSON object.')

    validated = {}

    if not is_update or 'name' in payload:
        name = payload.get('name')
        if not isinstance(name, str) or len(name.strip()) < 2 or len(name.strip()) > 128:
            raise TargetError('Target name must be between 2 and 128 characters.')
        validated['name'] = name.strip()

    if not is_update or 'target_type' in payload:
        target_type = payload.get('target_type')
        if target_type not in VALID_TARGET_TYPES:
            raise TargetError(f'Target type must be one of: {", ".join(sorted(VALID_TARGET_TYPES))}.')
        validated['target_type'] = target_type

    if not is_update or 'owner_organization' in payload:
        owner = payload.get('owner_organization')
        if not isinstance(owner, str) or len(owner.strip()) < 2 or len(owner.strip()) > 255:
            raise TargetError('Owner or organization must be between 2 and 255 characters.')
        validated['owner_organization'] = owner.strip()

    if not is_update or 'scope_domains' in payload:
        raw_domains = payload.get('scope_domains')
        if not isinstance(raw_domains, list) or not raw_domains:
            raise TargetError('At least one authorized in-scope domain or IP address is required.')
        domains = []
        for item in raw_domains:
            normalized = validate_scope_item(item)
            if normalized not in domains:
                domains.append(normalized)
        validated['scope_domains'] = domains

    if 'explicit_subdomains' in payload:
        raw_subdomains = payload.get('explicit_subdomains', [])
        if not isinstance(raw_subdomains, list):
            raise TargetError('Explicit subdomains must be a list.')
        subdomains = []
        for item in raw_subdomains:
            if not item:
                continue
            normalized = validate_scope_item(item)
            if '/' in normalized:
                raise TargetError('Explicit subdomains must be exact hosts, not CIDR networks.')
            if normalized not in subdomains:
                subdomains.append(normalized)
        validated['explicit_subdomains'] = subdomains
    elif not is_update:
        validated['explicit_subdomains'] = []

    if 'excluded_scope' in payload:
        raw_excluded = payload.get('excluded_scope', [])
        if not isinstance(raw_excluded, list):
            raise TargetError('Excluded scope must be a list.')
        excluded = []
        for item in raw_excluded:
            if not item:
                continue
            clean = validate_excluded_item(item)
            if clean not in excluded:
                excluded.append(clean)
        validated['excluded_scope'] = excluded
    elif not is_update:
        validated['excluded_scope'] = []

    if 'permitted_methods' in payload:
        methods = payload.get('permitted_methods', [])
        if not isinstance(methods, list):
            raise TargetError('Permitted methods must be a list.')
        if not all(isinstance(m, str) for m in methods):
            raise TargetError('Permitted methods must contain strings only.')
        validated['permitted_methods'] = list(dict.fromkeys(m.strip() for m in methods if m.strip()))
    elif not is_update:
        validated['permitted_methods'] = DEFAULT_PERMITTED_METHODS

    if 'prohibited_methods' in payload:
        methods = payload.get('prohibited_methods', [])
        if not isinstance(methods, list):
            raise TargetError('Prohibited methods must be a list.')
        if not all(isinstance(m, str) for m in methods):
            raise TargetError('Prohibited methods must contain strings only.')
        validated['prohibited_methods'] = list(dict.fromkeys(m.strip() for m in methods if m.strip()))
    elif not is_update:
        validated['prohibited_methods'] = DEFAULT_PROHIBITED_METHODS

    # Reconcile permitted vs prohibited conflicts:
    if 'permitted_methods' in validated and 'prohibited_methods' in validated:
        if 'permitted_methods' in payload and 'prohibited_methods' not in payload:
            # Prohibited was defaulted: remove any explicitly permitted method from defaulted prohibitions
            validated['prohibited_methods'] = [m for m in validated['prohibited_methods'] if m not in validated['permitted_methods']]
        elif 'prohibited_methods' in payload and 'permitted_methods' not in payload:
            # Permitted was defaulted: remove any explicitly prohibited method from defaulted permissions
            validated['permitted_methods'] = [m for m in validated['permitted_methods'] if m not in validated['prohibited_methods']]
        else:
            # Both were explicitly submitted: reject if identical method is in both
            conflicts = set(validated['permitted_methods']) & set(validated['prohibited_methods'])
            if conflicts:
                raise TargetError(f"Methods cannot be both permitted and prohibited: {', '.join(sorted(conflicts))}.")

    if 'rate_limit_rps' in payload:
        try:
            val = payload.get('rate_limit_rps')
            if isinstance(val, bool):
                raise ValueError()
            rps = int(val)
            if not 1 <= rps <= 1000:
                raise ValueError()
            validated['rate_limit_rps'] = rps
        except (ValueError, TypeError):
            raise TargetError('Rate limit must be an integer between 1 and 1000 requests per second.')
    elif not is_update:
        validated['rate_limit_rps'] = 10

    if not is_update:
        valid_from = parse_iso_datetime(payload.get('valid_from'), 'valid_from')
        valid_to = parse_iso_datetime(payload.get('valid_to'), 'valid_to')
        if valid_to <= valid_from:
            raise TargetError('Authorization expiry date (valid_to) must be after the valid_from date.')
        validated['valid_from'] = valid_from
        validated['valid_to'] = valid_to
    else:
        if 'valid_from' in payload and 'valid_to' in payload:
            valid_from = parse_iso_datetime(payload.get('valid_from'), 'valid_from')
            valid_to = parse_iso_datetime(payload.get('valid_to'), 'valid_to')
            if valid_to <= valid_from:
                raise TargetError('Authorization expiry date (valid_to) must be after the valid_from date.')
            validated['valid_from'] = valid_from
            validated['valid_to'] = valid_to
        elif 'valid_from' in payload:
            validated['valid_from'] = parse_iso_datetime(payload.get('valid_from'), 'valid_from')
        elif 'valid_to' in payload:
            validated['valid_to'] = parse_iso_datetime(payload.get('valid_to'), 'valid_to')

    if not is_update or 'evidence_reference' in payload:
        evidence = payload.get('evidence_reference')
        if not isinstance(evidence, str) or not evidence.strip():
            raise TargetError('Documented authorization evidence reference is required (e.g., contract REF, letter ID, or program policy URL).')
        clean_evidence = evidence.strip()
        if len(clean_evidence) > 1024:
            raise TargetError('Evidence reference must not exceed 1024 characters.')
        # Strip potential authorization token leaks or raw base64 data
        if re.search(r'(Bearer\s+[A-Za-z0-9._~+/-]+|password\s*[:=]|token\s*[:=])', clean_evidence, re.IGNORECASE):
            raise TargetError('Evidence reference must not include embedded credentials or authorization tokens.')
        validated['evidence_reference'] = clean_evidence

    if 'status' in payload:
        status = payload.get('status')
        if status not in VALID_STATUSES:
            raise TargetError(f'Status must be one of: {", ".join(sorted(VALID_STATUSES))}.')
        validated['status'] = status
    elif not is_update:
        validated['status'] = 'active'

    return validated


def effective_status(target):
    if not target or not target.status:
        return 'inactive'
    if target.status in {'revoked', 'inactive', 'pending_approval'}:
        return target.status

    current = now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)

    if not target.valid_from or not target.valid_to:
        return 'invalid_dates'

    try:
        valid_from = target.valid_from
        if isinstance(valid_from, str):
            valid_from = datetime.fromisoformat(valid_from.replace('Z', '+00:00'))
        if valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)

        valid_to = target.valid_to
        if isinstance(valid_to, str):
            valid_to = datetime.fromisoformat(valid_to.replace('Z', '+00:00'))
        if valid_to.tzinfo is None:
            valid_to = valid_to.replace(tzinfo=timezone.utc)
    except Exception:
        return 'invalid_dates'

    if current < valid_from:
        return 'not_yet_valid'
    if current > valid_to:
        return 'expired'

    return target.status


def format_iso(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        try:
            clean = dt.replace('Z', '+00:00')
            parsed = datetime.fromisoformat(clean)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.isoformat()
        except Exception:
            return dt
    if hasattr(dt, 'tzinfo'):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    return str(dt)


def serialize_audit_event(event):
    return {
        'id': event.id,
        'target_id': event.target_id,
        'event_type': event.event_type,
        'actor': event.actor,
        'details': event.details,
        'created_at': format_iso(event.created_at),
    }


def serialize_target(target, include_audit=True):
    data = {
        'id': target.id,
        'name': target.name,
        'target_type': target.target_type,
        'owner_organization': target.owner_organization,
        'scope_domains': target.scope_domains or [],
        'explicit_subdomains': target.explicit_subdomains or [],
        'excluded_scope': target.excluded_scope or [],
        'permitted_methods': target.permitted_methods or [],
        'prohibited_methods': target.prohibited_methods or [],
        'rate_limit_rps': target.rate_limit_rps,
        'valid_from': format_iso(target.valid_from),
        'valid_to': format_iso(target.valid_to),
        'evidence_reference': target.evidence_reference,
        'status': target.status,
        'effective_status': effective_status(target),
        'created_by': target.created_by,
        'updated_by': target.updated_by,
        'created_at': format_iso(target.created_at),
        'updated_at': format_iso(target.updated_at),
    }
    if include_audit:
        data['audit_events'] = [serialize_audit_event(e) for e in getattr(target, 'audit_events', [])]
    return data
