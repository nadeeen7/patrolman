"""Routes for Phase 1: Authorized Target and Scope Manager."""
from flask import Blueprint, abort, g, jsonify, request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AuthorizedTarget, ScopeImportSnapshot, TargetAuditEvent, now
from .services.target_authorization import (
    VALID_STATUSES,
    VALID_TARGET_TYPES,
    effective_status,
    serialize_target,
    validate_target_payload,
)
from .services.target_validation import TargetError
from .services.audit_service import log_event
from .services.scope_import import parse_offline_scope


def _scope_asset_key(asset):
    asset_type = 'host' if asset['asset_type'] in {'domain', 'ip', 'host'} else asset['asset_type']
    return (asset_type, asset['value'])


def _target_scope_snapshot(target):
    included = []
    for value in [*(target.scope_domains or []), *(target.explicit_subdomains or [])]:
        asset_type = 'cidr' if '/' in str(value) else 'host'
        included.append({'asset_type': asset_type, 'value': str(value)})
    excluded = [
        {'asset_type': 'path' if str(value).startswith('/') else ('cidr' if '/' in str(value) else 'host'),
         'value': str(value)}
        for value in (target.excluded_scope or [])
    ]
    return included, excluded


def _serialize_scope_import(item):
    return {
        'id': item.id,
        'target_id': item.target_id,
        'provider': item.provider,
        'program_id': item.program_id,
        'source_url': item.source_url,
        'imported_at': item.imported_at.isoformat() if item.imported_at else None,
        'last_successful_validation_at': (
            item.last_successful_validation_at.isoformat()
            if item.last_successful_validation_at else None
        ),
        'snapshot_version': item.snapshot_version,
        'digest': item.digest,
        'included_assets': item.included_assets or [],
        'excluded_assets': item.excluded_assets or [],
        'permitted_methods': item.permitted_methods or [],
        'prohibited_methods': item.prohibited_methods or [],
        'restrictions': item.restrictions or [],
        'invalid_entries': item.invalid_entries or [],
        'scope_diff': item.scope_diff or {},
        'import_status': item.import_status,
        'approval_status': item.approval_status,
        'approved_by': item.approved_by,
        'approved_at': item.approved_at.isoformat() if item.approved_at else None,
    }


def install_target_routes(app, engine, protected):
    api = Blueprint('targets', __name__)

    def pagination():
        try:
            page, size = int(request.args.get('page', 1)), int(request.args.get('page_size', 20))
        except ValueError:
            abort(400, 'Invalid pagination parameters.')
        if page < 1 or not 1 <= size <= 100:
            abort(400, 'Invalid pagination parameters.')
        return page, size

    def get_actor():
        return getattr(g, 'admin_username', None) or 'administrator'

    def log_scope_event(session, event_type, actor, target, snapshot, details):
        log_event(
            session,
            event_type=event_type,
            actor=actor,
            resource_type='scope_import',
            resource_id=snapshot.id if snapshot else target.id,
            details={'target_id': target.id, **details},
            ip_address=request.remote_addr,
            commit_with_transaction=True,
        )

    @api.get('/api/targets')
    @protected
    def list_targets():
        page, size = pagination()
        target_type = request.args.get('type')
        status_filter = request.args.get('status')
        search = request.args.get('search', '').strip().lower()

        with Session(engine) as session:
            query = select(AuthorizedTarget)
            if target_type:
                if target_type not in VALID_TARGET_TYPES:
                    abort(400, f'Invalid target type filter: {target_type}')
                query = query.where(AuthorizedTarget.target_type == target_type)

            all_targets = session.scalars(query.order_by(AuthorizedTarget.created_at.desc())).all()

            filtered = []
            for t in all_targets:
                eff = effective_status(t)
                if status_filter and eff != status_filter and t.status != status_filter:
                    continue
                if search:
                    match_name = search in (t.name or '').lower()
                    match_owner = search in (t.owner_organization or '').lower()
                    match_domain = any(search in str(d).lower() for d in (t.scope_domains or []))
                    match_subdomain = any(search in str(s).lower() for s in (t.explicit_subdomains or []))
                    if not (match_name or match_owner or match_domain or match_subdomain):
                        continue
                filtered.append(t)

            total = len(filtered)
            paged = filtered[(page - 1) * size : page * size]

            # Compute high level metrics
            metrics = {
                'total': len(all_targets),
                'active': sum(effective_status(t) == 'active' for t in all_targets),
                'expired': sum(effective_status(t) == 'expired' for t in all_targets),
                'revoked': sum(effective_status(t) == 'revoked' for t in all_targets),
                'inactive': sum(effective_status(t) == 'inactive' for t in all_targets),
            }

            return jsonify(
                data=[serialize_target(t, include_audit=False) for t in paged],
                meta={
                    'page': page,
                    'page_size': size,
                    'total': total,
                    'metrics': metrics,
                },
            )

    @api.post('/api/targets')
    @protected
    def create_target():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            abort(400, 'Expected a JSON object.')

        try:
            validated = validate_target_payload(payload, is_update=False)
        except TargetError as exc:
            abort(400, str(exc))

        actor = get_actor()
        current_time = now()

        target = AuthorizedTarget(
            name=validated['name'],
            target_type=validated['target_type'],
            owner_organization=validated['owner_organization'],
            scope_domains=validated['scope_domains'],
            explicit_subdomains=validated['explicit_subdomains'],
            excluded_scope=validated['excluded_scope'],
            permitted_methods=validated['permitted_methods'],
            prohibited_methods=validated['prohibited_methods'],
            rate_limit_rps=validated['rate_limit_rps'],
            valid_from=validated['valid_from'],
            valid_to=validated['valid_to'],
            evidence_reference=validated['evidence_reference'],
            status=validated['status'],
            created_by=actor,
            updated_by=actor,
            created_at=current_time,
            updated_at=current_time,
        )

        with Session(engine) as session:
            session.add(target)
            session.flush()

            audit = TargetAuditEvent(
                target_id=target.id,
                event_type='created',
                actor=actor,
                details={
                    'name': target.name,
                    'target_type': target.target_type,
                    'owner_organization': target.owner_organization,
                    'scope_domains': target.scope_domains,
                    'explicit_subdomains': target.explicit_subdomains,
                    'excluded_scope': target.excluded_scope,
                    'permitted_methods': target.permitted_methods,
                    'prohibited_methods': target.prohibited_methods,
                    'valid_from': target.valid_from.isoformat(),
                    'valid_to': target.valid_to.isoformat(),
                    'evidence_reference': target.evidence_reference,
                },
                created_at=current_time,
            )
            session.add(audit)
            log_event(
                session,
                event_type='target_created',
                actor=actor,
                resource_type='target',
                resource_id=target.id,
                details={'name': target.name, 'target_type': target.target_type, 'owner': target.owner_organization},
                ip_address=request.remote_addr,
                commit_with_transaction=True,
            )
            session.commit()
            return jsonify(data=serialize_target(target, include_audit=True)), 201

    @api.get('/api/targets/check')
    @protected
    def check_scope():
        """Dry-run scope check: does the given host+tools combination have an active authorization?

        Query parameters:
            host   - the hostname or IP address to check (required)
            tools  - comma-separated tool names to validate against permitted/prohibited methods (optional)

        Returns 200 with matched target details if covered, 403 if not authorized.
        """
        from .services.scope_validator import (
            ScopeAuthorizationError,
            check_host_in_scope,
            check_methods_permitted,
            find_authorizing_target,
            _asset_matches_host,
        )
        from .services.target_validation import parse_target_endpoint, TargetError

        host_raw = request.args.get('host', '').strip()
        tools_raw = request.args.get('tools', '').strip()
        tools = [t.strip() for t in tools_raw.split(',') if t.strip()] if tools_raw else []

        if not host_raw:
            abort(400, 'Supply a host query parameter.')
        try:
            endpoint = parse_target_endpoint(host_raw)
            host = endpoint.host
        except TargetError as exc:
            abort(400, str(exc))

        target_id = request.args.get('target_id', '').strip() or None

        with Session(engine) as session:
            try:
                matched = find_authorizing_target(host, tools, session, require=False, preferred_target_id=target_id)
            except ScopeAuthorizationError as exc:
                return jsonify(error={'code': 'scope_not_authorized', 'message': str(exc)}), 403

            if matched is None:
                return jsonify(data={
                    'covered': False,
                    'reason': 'No authorized targets are registered.',
                    'matched_target': None,
                    'tools': tools,
                    'host': host,
                    'canonical_endpoint': endpoint.canonical_endpoint,
                })

            # Explain which scope field matched
            match_source = None
            for entry in (matched.scope_domains or []):
                if _asset_matches_host(str(entry), host):
                    match_source = 'scope_domains'
                    break
            if not match_source:
                for entry in (matched.explicit_subdomains or []):
                    if _asset_matches_host(str(entry), host):
                        match_source = 'explicit_subdomains'
                        break

            # Method coverage summary per tool
            from .services.scope_validator import TOOL_METHOD_MAP, check_methods_permitted
            method_coverage = {}
            prohibited_set = set(matched.prohibited_methods or [])
            permitted_set = set(matched.permitted_methods or [])
            for tool in tools:
                violation = check_methods_permitted([tool], matched)
                cats = TOOL_METHOD_MAP.get(tool, [])
                blocked_cats = [c for c in cats if c in prohibited_set]
                missing_cats = [c for c in cats if permitted_set and not any(c in permitted_set for c in cats)]
                method_coverage[tool] = {
                    'permitted': violation is None,
                    'categories': cats,
                    'blocked_categories': blocked_cats,
                    'missing_categories': missing_cats,
                    'reason': violation,
                }

            return jsonify(data={
                'covered': True,
                'host': host,
                'canonical_endpoint': endpoint.canonical_endpoint,
                'match_source': match_source,
                'matched_target': serialize_target(matched, include_audit=False),
                'tools': tools,
                'method_coverage': method_coverage,
                'effective_status': effective_status(matched),
            })

    @api.get('/api/targets/<target_id>')
    @protected
    def get_target(target_id):
        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            if target is None:
                abort(404, 'Authorized target not found.')
            return jsonify(data=serialize_target(target, include_audit=True))

    @api.put('/api/targets/<target_id>')
    @protected
    def update_target(target_id):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            abort(400, 'Expected a JSON object.')

        try:
            validated = validate_target_payload(payload, is_update=True)
        except TargetError as exc:
            abort(400, str(exc))

        actor = get_actor()
        current_time = now()

        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            if target is None:
                abort(404, 'Authorized target not found.')

            changes = {}
            for field, new_value in validated.items():
                old_value = getattr(target, field)
                if old_value != new_value:
                    changes[field] = {
                        'old': old_value.isoformat() if hasattr(old_value, 'isoformat') else old_value,
                        'new': new_value.isoformat() if hasattr(new_value, 'isoformat') else new_value,
                    }
                    setattr(target, field, new_value)

            target.updated_by = actor
            target.updated_at = current_time

            if changes:
                audit = TargetAuditEvent(
                    target_id=target.id,
                    event_type='updated',
                    actor=actor,
                    details={'changes': changes},
                    created_at=current_time,
                )
                session.add(audit)
                log_event(
                    session,
                    event_type='target_updated',
                    actor=actor,
                    resource_type='target',
                    resource_id=target.id,
                    details={'changes': list(changes.keys())},
                    ip_address=request.remote_addr,
                    commit_with_transaction=True,
                )

            session.commit()

            from flask import current_app
            mgr = current_app.extensions.get('scan_manager')
            if mgr:
                if target.status in {'inactive', 'revoked'}:
                    mgr.cancel_target_scans(target.id, reason=f'Target status changed to {target.status}')
                    mgr.rate_coordinator.update_target_capacity(target.id, 0)
                elif 'rate_limit_rps' in validated:
                    mgr.rate_coordinator.update_target_capacity(target.id, target.rate_limit_rps)

            return jsonify(data=serialize_target(target, include_audit=True))

    @api.post('/api/targets/<target_id>/deactivate')
    @protected
    def deactivate_target(target_id):
        payload = request.get_json(silent=True) or {}
        new_status = payload.get('status', 'inactive')
        reason = payload.get('reason', 'Target scope deactivated by administrator.')

        if new_status not in {'inactive', 'revoked'}:
            abort(400, "Deactivation status must be either 'inactive' or 'revoked'.")

        actor = get_actor()
        current_time = now()

        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            if target is None:
                abort(404, 'Authorized target not found.')

            target.status = new_status
            target.updated_by = actor
            target.updated_at = current_time

            audit = TargetAuditEvent(
                target_id=target.id,
                event_type=new_status,
                actor=actor,
                details={'reason': str(reason).strip()[:500]},
                created_at=current_time,
            )
            session.add(audit)
            log_event(
                session,
                event_type=f'target_{new_status}',
                actor=actor,
                resource_type='target',
                resource_id=target.id,
                details={'reason': str(reason).strip()[:500]},
                ip_address=request.remote_addr,
                commit_with_transaction=True,
            )
            session.commit()

            from flask import current_app
            mgr = current_app.extensions.get('scan_manager')
            if mgr:
                mgr.cancel_target_scans(target.id, reason=f'Target deactivated: {reason}')
                mgr.rate_coordinator.update_target_capacity(target.id, 0)

            return jsonify(data=serialize_target(target, include_audit=True))

    @api.get('/api/targets/<target_id>/scope-imports')
    @protected
    def list_scope_imports(target_id):
        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            if target is None:
                abort(404, 'Authorized target not found.')
            return jsonify(data=[
                _serialize_scope_import(item)
                for item in sorted(target.scope_imports, key=lambda item: item.imported_at, reverse=True)
            ])

    @api.post('/api/targets/<target_id>/scope-imports/preview')
    @protected
    def preview_scope_import(target_id):
        payload = request.get_json(silent=True)
        actor = get_actor()
        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            if target is None:
                abort(404, 'Authorized target not found.')
            if target.target_type != 'bug_bounty':
                abort(400, 'External scope imports are supported only for bug bounty targets.')
            try:
                parsed = parse_offline_scope(payload)
            except ValueError as exc:
                log_event(
                    session,
                    event_type='scope_import_rejected',
                    actor=actor,
                    resource_type='target',
                    resource_id=target.id,
                    details={'reason': str(exc)[:1000]},
                    ip_address=request.remote_addr,
                    commit_with_transaction=True,
                )
                session.commit()
                abort(400, str(exc))

            current_included, current_excluded = _target_scope_snapshot(target)
            if target.scope_imports:
                prior_approved = next(
                    (item for item in sorted(
                        target.scope_imports,
                        key=lambda item: item.imported_at or now(),
                        reverse=True,
                    ) if item.approval_status == 'approved'),
                    None,
                )
                if prior_approved:
                    current_included = prior_approved.included_assets or []
                    current_excluded = prior_approved.excluded_assets or []

            old_included = {_scope_asset_key(asset) for asset in current_included}
            new_included = {_scope_asset_key(asset) for asset in parsed['included_assets']}
            old_excluded = {_scope_asset_key(asset) for asset in current_excluded}
            new_excluded = {_scope_asset_key(asset) for asset in parsed['excluded_assets']}
            diff = {
                'newly_included': [dict(asset_type=kind, value=value) for kind, value in sorted(new_included - old_included)],
                'removed': [dict(asset_type=kind, value=value) for kind, value in sorted(old_included - new_included)],
                'exclusions_added': [dict(asset_type=kind, value=value) for kind, value in sorted(new_excluded - old_excluded)],
                'exclusions_removed': [dict(asset_type=kind, value=value) for kind, value in sorted(old_excluded - new_excluded)],
                'methods_changed': (
                    sorted(target.permitted_methods or []) != parsed['permitted_methods']
                    or sorted(target.prohibited_methods or []) != parsed['prohibited_methods']
                ),
                'restrictions_changed': (
                    sorted(next(
                        (item.restrictions or [] for item in target.scope_imports if item.approval_status == 'approved'),
                        [],
                    )) != parsed['restrictions']
                ),
                'previous_restrictions': sorted(next(
                    (item.restrictions or [] for item in target.scope_imports if item.approval_status == 'approved'),
                    [],
                )),
                'new_restrictions': parsed['restrictions'],
                'previous_permitted_methods': sorted(target.permitted_methods or []),
                'new_permitted_methods': parsed['permitted_methods'],
                'previous_prohibited_methods': sorted(target.prohibited_methods or []),
                'new_prohibited_methods': parsed['prohibited_methods'],
                'review_required': True,
            }
            snapshot = ScopeImportSnapshot(
                target_id=target.id,
                provider=parsed['provider'],
                program_id=parsed['program_id'],
                source_url=parsed['source_url'],
                imported_at=now(),
                last_successful_validation_at=now() if parsed['import_status'] == 'valid' else None,
                snapshot_version=parsed['version'],
                digest=parsed['digest'],
                included_assets=parsed['included_assets'],
                excluded_assets=parsed['excluded_assets'],
                permitted_methods=parsed['permitted_methods'],
                prohibited_methods=parsed['prohibited_methods'],
                restrictions=parsed['restrictions'],
                invalid_entries=parsed['invalid_entries'],
                scope_diff=diff,
                import_status=parsed['import_status'],
                approval_status='pending_review',
            )
            session.add(snapshot)
            session.flush()
            target.audit_events.append(TargetAuditEvent(
                event_type='scope_import_previewed',
                actor=actor,
                details={
                    'snapshot_id': snapshot.id,
                    'digest': snapshot.digest,
                    'import_status': snapshot.import_status,
                    'invalid_entry_count': len(snapshot.invalid_entries),
                    'scope_diff': diff,
                },
                created_at=now(),
            ))
            log_scope_event(session, 'scope_import_previewed', actor, target, snapshot, {
                'digest': snapshot.digest,
                'provider': snapshot.provider,
                'program_id': snapshot.program_id,
                'import_status': snapshot.import_status,
                'invalid_entry_count': len(snapshot.invalid_entries),
            })
            session.commit()
            return jsonify(data=_serialize_scope_import(snapshot)), 201

    @api.post('/api/targets/<target_id>/scope-imports/<snapshot_id>/approve')
    @protected
    def approve_scope_import(target_id, snapshot_id):
        actor = get_actor()
        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            snapshot = session.get(ScopeImportSnapshot, snapshot_id)
            if target is None or snapshot is None or snapshot.target_id != target_id:
                abort(404, 'Scope import snapshot not found.')
            if snapshot.import_status != 'valid' or snapshot.invalid_entries:
                abort(400, 'Invalid scope snapshots cannot be approved.')
            if snapshot.approval_status != 'pending_review':
                abort(409, 'Scope snapshot is no longer pending review.')
            latest = max(
                target.scope_imports,
                key=lambda item: item.imported_at or now(),
                default=None,
            )
            if latest is not snapshot:
                abort(409, 'Only the latest scope snapshot can be approved.')
            if effective_status(target) != 'active':
                abort(409, 'Target authorization must be active and unexpired before approving imported scope.')
            current_permitted = set(target.permitted_methods or [])
            imported_permitted = set(snapshot.permitted_methods or [])
            effective_permitted = imported_permitted if not current_permitted else imported_permitted & current_permitted
            if not effective_permitted:
                abort(400, 'Imported methods conflict with the existing authorization; no methods remain permitted.')
            old_state = {
                'scope_domains': target.scope_domains or [],
                'explicit_subdomains': target.explicit_subdomains or [],
                'excluded_scope': target.excluded_scope or [],
                'permitted_methods': target.permitted_methods or [],
                'prohibited_methods': target.prohibited_methods or [],
            }
            target.scope_domains = [asset['value'] for asset in snapshot.included_assets]
            target.explicit_subdomains = []
            imported_exclusions = [asset['value'] for asset in snapshot.excluded_assets]
            target.excluded_scope = list(dict.fromkeys([*(target.excluded_scope or []), *imported_exclusions]))
            target.permitted_methods = sorted(effective_permitted)
            target.prohibited_methods = list(dict.fromkeys([
                *(target.prohibited_methods or []), *(snapshot.prohibited_methods or [])
            ]))
            snapshot.approved_target_state = {
                'scope_domains': target.scope_domains,
                'explicit_subdomains': target.explicit_subdomains,
                'excluded_scope': target.excluded_scope,
                'permitted_methods': target.permitted_methods,
                'prohibited_methods': target.prohibited_methods,
            }
            target.updated_by = actor
            target.updated_at = now()
            snapshot.approval_status = 'approved'
            snapshot.approved_by = actor
            snapshot.approved_at = now()
            snapshot.last_successful_validation_at = now()
            target.audit_events.append(TargetAuditEvent(
                event_type='scope_import_approved',
                actor=actor,
                details={
                    'snapshot_id': snapshot.id,
                    'digest': snapshot.digest,
                    'previous': old_state,
                    'new': {
                        'scope_domains': target.scope_domains,
                        'explicit_subdomains': target.explicit_subdomains,
                        'excluded_scope': target.excluded_scope,
                        'permitted_methods': target.permitted_methods,
                        'prohibited_methods': target.prohibited_methods,
                    },
                },
                created_at=now(),
            ))
            log_scope_event(session, 'scope_import_approved', actor, target, snapshot, {
                'digest': snapshot.digest,
                'scope_diff': snapshot.scope_diff,
            })
            session.commit()
            return jsonify(data={
                'snapshot': _serialize_scope_import(snapshot),
                'target': serialize_target(target, include_audit=True),
            })

    @api.post('/api/targets/<target_id>/scope-imports/<snapshot_id>/reject')
    @protected
    def reject_scope_import(target_id, snapshot_id):
        actor = get_actor()
        with Session(engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            snapshot = session.get(ScopeImportSnapshot, snapshot_id)
            if target is None or snapshot is None or snapshot.target_id != target_id:
                abort(404, 'Scope import snapshot not found.')
            if snapshot.approval_status != 'pending_review':
                abort(409, 'Scope snapshot is no longer pending review.')
            snapshot.approval_status = 'rejected'
            target.audit_events.append(TargetAuditEvent(
                event_type='scope_import_rejected',
                actor=actor,
                details={'snapshot_id': snapshot.id, 'digest': snapshot.digest},
                created_at=now(),
            ))
            log_scope_event(session, 'scope_import_rejected', actor, target, snapshot, {
                'digest': snapshot.digest,
                'invalid_entry_count': len(snapshot.invalid_entries or []),
            })
            session.commit()
            return jsonify(data=_serialize_scope_import(snapshot))
    app.register_blueprint(api)
