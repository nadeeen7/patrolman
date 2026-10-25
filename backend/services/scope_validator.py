"""Phase 2 - Automatic Scope Validator.

Checks that every scan target is covered by an active, unexpired
AuthorizedTarget record in the database, and that the requested tools
fall within the target's permitted methods and do not include any
prohibited method.

Design invariants:
- Scope matching is EXACT-HOST only. Parent-domain entries never
  implicitly cover subdomains (Phase 1 requirement preserved).
- IP addresses must match literally; no reverse-DNS lookup is performed.
- All host normalisation is delegated to normalize_target() from
  target_validation to avoid duplicate logic.
- Multiple covering targets: most restrictive (fail closed).
- No Flask imports; fully standalone and unit-testable.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuthorizedTarget, TargetAuditEvent, now
from .target_authorization import effective_status
from .target_validation import ScopeError, TargetError, normalize_scope_asset, normalize_target

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Tool to method-category mapping
# ---------------------------------------------------------------------------
# A tool may map to multiple categories. The mapping is evaluated as follows:
#   prohibited_methods check: BLOCKS if ANY mapped category appears in the
#                             target's prohibited_methods list.
#   permitted_methods check:  PASSES if ANY mapped category appears in the
#                             target's permitted_methods list (or if the
#                             target's permitted_methods list is empty).

TOOL_METHOD_MAP: dict[str, list[str]] = {
    'nmap': ['port_scan'],
    'httpx': ['web_service_discovery'],
    'whatweb': ['web_service_discovery'],
    'subfinder': ['web_service_discovery'],
    'sslyze': ['tls_audit'],
    'nuclei': ['vulnerability_check'],
    # Wapiti is an active web vulnerability scanner: it needs a vulnerability
    # check permission, and a target that prohibits active crawling still blocks
    # it because the adapter crawls within the exact base-URL scope.
    'wapiti': ['vulnerability_check', 'active_crawl'],
    'gitleaks': ['local_scan'],
    'trivy': ['local_scan'],
}
KNOWN_METHODS = {category for categories in TOOL_METHOD_MAP.values() for category in categories}
KNOWN_METHODS.update({'dos', 'exploit', 'credential_attack', 'active_crawl'})


# ---------------------------------------------------------------------------
# Scope matching
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def is_host_excluded(host: str, target: AuthorizedTarget) -> bool:
    """Return True if *host* is explicitly listed in target.excluded_scope."""
    for entry in (target.excluded_scope or []):
        raw = str(entry).strip()
        if not raw or raw.startswith('/'):
            continue
        try:
            normalized = normalize_scope_asset(raw)
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                if '/' not in normalized and normalized == host:
                    return True
                continue
            if '/' in normalized:
                try:
                    if address in ipaddress.ip_network(normalized):
                        return True
                except (TypeError, ValueError):
                    continue
            if normalized == host:
                return True
        except (TypeError, ValueError, TargetError):
            return True
    return False


def check_destination_excluded(destination: str, target: AuthorizedTarget) -> str | None:
    """Check if a URL destination violates any host or path exclusion in target.excluded_scope.

    Returns a rejection reason string if excluded, or None if permitted.
    Safe path boundary matching: '/admin' matches '/admin', '/admin/', '/admin/sub',
    but does NOT match '/administrator'.
    """
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(destination if '://' in destination else f'http://{destination}')
        dest_host = parsed.hostname
        dest_path = parsed.path or '/'
    except Exception:
        dest_host = destination
        dest_path = '/'

    if dest_host and is_host_excluded(dest_host, target):
        return f'Destination host "{dest_host}" is explicitly in excluded_scope for "{target.name}".'

    for entry in (target.excluded_scope or []):
        raw = str(entry).strip()
        if not raw or not raw.startswith('/'):
            continue
        ep = '/' + raw.strip('/')
        dp = '/' + dest_path.strip().lstrip('/')
        if dp == ep or dp.startswith(ep.rstrip('/') + '/'):
            return f'Destination path "{dest_path}" matches excluded path "{raw}" for "{target.name}".'

    return None


def _asset_matches_host(entry: str, host: str) -> bool:
    try:
        normalized = normalize_scope_asset(entry)
    except (TargetError, ValueError):
        return False
    if '/' not in normalized:
        return normalized == host
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(normalized)
    except (TypeError, ValueError):
        return False


def host_is_included(host: str, target: AuthorizedTarget) -> bool:
    """Check included exact hosts and CIDRs, ignoring target exclusions."""
    return any(
        _asset_matches_host(str(entry), host)
        for entry in [*(target.scope_domains or []), *(target.explicit_subdomains or [])]
    )


def check_host_in_scope(host: str, target: AuthorizedTarget) -> bool:
    """Return True if *host* is explicitly listed in target scope and NOT excluded.

    Exact-host match only. No wildcard expansion. No parent-domain inference.
    *host* must already be normalised by normalize_target().
    """
    if is_host_excluded(host, target):
        return False

    return host_is_included(host, target)


def check_methods_permitted(
    tools: list[str],
    target: AuthorizedTarget,
) -> str | None:
    """Return an error message string if the tool set violates method policy.

    Returns None if all tools are permitted.

    Rules (fail-closed):
    - If a tool maps to ANY prohibited category -> reject with specific message.
    - If permitted_methods is non-empty and NO mapped category for a tool is
      listed -> reject with specific message.
    """
    prohibited = set(target.prohibited_methods or [])
    permitted = set(target.permitted_methods or [])

    for tool in tools:
        categories = TOOL_METHOD_MAP.get(tool)
        if not categories:
            return f'Tool "{tool}" has no authorization method mapping; refusing to establish permission.'

        blocked_categories = [c for c in categories if c in prohibited]
        if blocked_categories:
            return (
                'Tool "{}" maps to method categor{} {}, which {} explicitly prohibited '
                'by the authorization for "{}".'.format(
                    tool,
                    'y' if len(blocked_categories) == 1 else 'ies',
                    ', '.join(repr(c) for c in blocked_categories),
                    'is' if len(blocked_categories) == 1 else 'are',
                    target.name,
                )
            )

        if permitted and not any(c in permitted for c in categories):
            return (
                'Tool "{}" requires one of {}, none of which are in the permitted '
                'methods for "{}": {}.'.format(
                    tool,
                    [repr(c) for c in categories],
                    target.name,
                    sorted(permitted),
                )
            )

    return None


# ---------------------------------------------------------------------------
# Primary gate: find an authorizing target
# ---------------------------------------------------------------------------

class ScopeAuthorizationError(ScopeError):
    """Raised when no active AuthorizedTarget covers the requested host+tools."""


def find_authorizing_target(
    host: str,
    tools: list[str],
    session: Session,
    *,
    require: bool = True,
    preferred_target_id: str | None = None,
) -> AuthorizedTarget | None:
    """Look up an active AuthorizedTarget that covers *host* and permits *tools*.

    Parameters
    ----------
    host:
        Normalised hostname or IP (output of normalize_target()).
    tools:
        List of tool names from the scan request.
    session:
        SQLAlchemy session bound to the application database.
    require:
        If False and the authorized_targets table is empty, the function
        returns None instead of raising (backward-compatible permissive mode).
        If True, an empty table still raises.

    Returns
    -------
    The matched AuthorizedTarget, or None when require=False and no targets exist.

    Raises
    ------
    ScopeAuthorizationError
        When no active, unexpired, method-compatible target covers the host.
    """
    all_targets: list[AuthorizedTarget] = list(
        session.scalars(select(AuthorizedTarget)).all()
    )

    if not all_targets:
        if not require:
            return None
        raise ScopeAuthorizationError(
            'No authorized targets are registered. Register an authorized target '
            'for this host before submitting a scan, or set '
            'AVA_REQUIRE_AUTHORIZED_TARGET=false to disable the database scope gate.'
        )

    matching = [t for t in all_targets if host_is_included(host, t)]

    if not matching:
        raise ScopeAuthorizationError(
            'Host "{}" is not covered: it is not listed in the scope of any registered authorized target. '
            'Add this host to an existing target scope_domains or explicit_subdomains, '
            'or register a new authorized target.'.format(host)
        )

    active = [t for t in matching if effective_status(t) == 'active']

    if not active:
        statuses = ', '.join(
            '"{}" ({})'.format(t.name, effective_status(t)) for t in matching
        )
        raise ScopeAuthorizationError(
            'Host "{}" is covered by authorized target(s) but none are currently active. '
            'Matching targets and their status: {}.'.format(host, statuses)
        )

    excluded = [t for t in active if is_host_excluded(host, t)]
    if excluded:
        raise ScopeAuthorizationError(
            'Host "{}" is explicitly excluded by active authorization(s): {}.'.format(
                host, ', '.join(sorted(t.name for t in excluded))
            )
        )

    if preferred_target_id:
        preferred = next((t for t in active if t.id == preferred_target_id), None)
        if preferred is None:
            raise ScopeAuthorizationError(
                'The selected authorization does not actively cover "{}".'.format(host)
            )
        violation = check_methods_permitted(tools, preferred)
        if violation:
            raise ScopeAuthorizationError(
                'The requested tools are not permitted by the selected authorization for '
                '"{}": [{}] {}'.format(host, preferred.name, violation)
            )
        return preferred

    violations = [
        '[{}] {}'.format(t.name, violation)
        for t in active
        if (violation := check_methods_permitted(tools, t))
    ]
    if violations:
        raise ScopeAuthorizationError(
            'The requested tools are not permitted by every active authorization for '
            '"{}": '.format(host) + ' | '.join(violations)
        )

    # Stable restrictive precedence: smallest permission set, largest
    # prohibition set, lowest rate limit, then target ID.
    return min(
        active,
        key=lambda t: (
            len(t.permitted_methods) if t.permitted_methods else len(KNOWN_METHODS),
            -len(t.prohibited_methods or []),
            t.rate_limit_rps or 1,
            t.id,
        ),
    )


# ---------------------------------------------------------------------------
# Re-verification at execution time
# ---------------------------------------------------------------------------

def recheck_authorized_target(
    target_id: str,
    session: Session,
    host: str | None = None,
    tools: list[str] | None = None,
) -> AuthorizedTarget:
    """Verify the named AuthorizedTarget is still active at execution time.

    Called by ScanManager.work() before tool execution begins, to guard
    against targets that were revoked or expired while the scan was queued.

    Raises
    ------
    ScopeAuthorizationError
        If the target no longer exists, has been revoked, is inactive, or
        has expired since the scan was submitted.
    """
    target: AuthorizedTarget | None = session.get(AuthorizedTarget, target_id)
    if target is None:
        raise ScopeAuthorizationError(
            'Authorized target {} no longer exists. '
            'The authorization record may have been deleted after this scan was queued. '
            'Cancel this scan and create a new one with a valid authorization.'.format(
                repr(target_id)
            )
        )
    status = effective_status(target)
    if status != 'active':
        raise ScopeAuthorizationError(
            'Authorized target "{}" (ID: {}) is no longer active '
            '(current status: {}). The authorization may have expired or been revoked '
            'after this scan was queued. Cancel this scan and verify authorization before retrying.'.format(
                target.name, target_id, status
            )
        )
    if host is not None:
        try:
            from .target_validation import parse_target_endpoint
            host_bare = parse_target_endpoint(host).host
        except Exception:
            host_bare = host
        normalized_host = normalize_target(host_bare)
        if not check_host_in_scope(normalized_host, target):
            raise ScopeAuthorizationError(
                'Host "{}" is no longer in scope for authorization "{}".'.format(
                    normalized_host, target.name
                )
            )
        violation = check_methods_permitted(tools or [], target)
        if violation:
            raise ScopeAuthorizationError(violation)
        snapshots = sorted(
            target.scope_imports,
            key=lambda item: item.imported_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        if snapshots:
            snapshot = snapshots[0]
            validated_at = snapshot.last_successful_validation_at
            if validated_at and validated_at.tzinfo is None:
                validated_at = validated_at.replace(tzinfo=timezone.utc)
            if (
                snapshot.import_status != 'valid'
                or snapshot.approval_status != 'approved'
                or not validated_at
                or (_now_utc() - validated_at).total_seconds() > 30 * 24 * 60 * 60
            ):
                raise ScopeAuthorizationError(
                    'Imported authorization scope is pending review, invalid, or stale.'
                )
            approved_state = snapshot.approved_target_state or {}
            current_state = {
                'scope_domains': target.scope_domains or [],
                'explicit_subdomains': target.explicit_subdomains or [],
                'excluded_scope': target.excluded_scope or [],
                'permitted_methods': target.permitted_methods or [],
                'prohibited_methods': target.prohibited_methods or [],
            }
            if current_state != approved_state:
                raise ScopeAuthorizationError(
                    'Authorization scope or restrictions changed after imported scope approval.'
                )
    return target


def audit_authorization_failure(engine, target_id: str, scan_id: str, reason: str) -> None:
    """Persist a failed runtime authorization check before the worker continues."""
    from .audit_service import log_event
    from .results import redact

    safe_reason = redact(str(reason))[:1000]
    with Session(engine) as session:
        target = session.get(AuthorizedTarget, target_id)
        if target is not None:
            session.add(TargetAuditEvent(
                target_id=target_id,
                event_type='authorization_revalidation_failed',
                actor='worker',
                details={'scan_id': scan_id, 'reason': safe_reason},
                created_at=now(),
            ))
        log_event(
            session,
            event_type='authorization_revalidation_failed',
            actor='worker',
            resource_type='target',
            resource_id=target_id,
            details={'scan_id': scan_id, 'reason': safe_reason},
            commit_with_transaction=True,
        )
        session.commit()
