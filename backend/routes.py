import hashlib
import io
import json
import re
import shutil
import time
from flask import Blueprint, abort, jsonify, request, send_file, g, current_app
from werkzeug.exceptions import HTTPException
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .models import Scan, Finding, ScanRequest, ToolExecution, AuthorizedTarget, TargetAuditEvent, now
from .services.scan_service import PROFILES, TERMINAL, serialize
from .services.results import SEVERITIES
from .services.reports import write_reports, report_directory
from .services.local_scope import validate_local
from .services.target_validation import validate_target, ScopeError, TargetError
from .services.scope_validator import find_authorizing_target, recheck_authorized_target, ScopeAuthorizationError
from .services.target_authorization import effective_status
from .services.audit_service import log_event


def install_routes(app, engine, settings, protected, manager):
    api = Blueprint('scans', __name__)
    last_created = [float('-inf')]
    _require_auth_target = getattr(settings, 'require_authorized_target', False)

    def body():
        data = request.get_json()
        if not isinstance(data, dict): abort(400, 'Expected a JSON object.')
        return data

    def pagination():
        try:
            page, size = int(request.args.get('page', 1)), int(request.args.get('page_size', 20))
        except ValueError: abort(400, 'Invalid pagination.')
        if page < 1 or not 1 <= size <= 100: abort(400, 'Invalid pagination.')
        return page, size

    def current_user():
        if getattr(g, 'auth_mode', None) == 'bearer':
            return None
        return getattr(g, 'admin_username', None)

    def get_scan(session, scan_id, user=None):
        scan = session.get(Scan, scan_id)
        if scan is None: abort(404, 'Scan not found.')
        if getattr(g, 'auth_mode', None) == 'session':
            check_user = user if user is not None else current_user()
            if check_user and scan.created_by and scan.created_by != check_user:
                abort(404, 'Scan not found.')
        return scan

    @api.get('/api/profiles')
    @protected
    def profiles():
        return jsonify(data=PROFILES)

    @api.get('/api/dashboard')
    @protected
    def dashboard():
        user = current_user()
        with Session(engine) as session:
            scan_filter = [Scan.created_by == user] if user else []
            counts = dict(session.execute(
                select(Scan.state, func.count()).where(*scan_filter).group_by(Scan.state)
            ).all())
            severities = dict(session.execute(
                select(Finding.severity, func.count())
                .join(Scan, Finding.scan_id == Scan.id)
                .where(*scan_filter)
                .group_by(Finding.severity)
            ).all())
            execution_counts = dict(session.execute(
                select(ToolExecution.state, func.count())
                .join(Scan, ToolExecution.scan_id == Scan.id)
                .where(*scan_filter)
                .group_by(ToolExecution.state)
            ).all())
            executed = session.scalar(
                select(func.count())
                .select_from(ToolExecution)
                .join(Scan, ToolExecution.scan_id == Scan.id)
                .where(*scan_filter, ToolExecution.started_at.is_not(None))
            ) or 0
            recent = session.scalars(
                select(Scan).where(*scan_filter).order_by(Scan.created_at.desc()).limit(6)
            ).all()
            return jsonify(data=dict(total_scans=sum(counts.values()), states=counts,
                total_findings=sum(severities.values()), severities={key: severities.get(key, 0) for key in SEVERITIES},
                coverage={
                    'selected': sum(execution_counts.values()),
                    'executed': executed,
                    'successful': execution_counts.get('completed', 0),
                    'failed': execution_counts.get('failed', 0),
                    'timed_out': execution_counts.get('timed_out', 0),
                    'skipped': execution_counts.get('skipped', 0),
                    'blocked': execution_counts.get('blocked', 0),
                    'unavailable': execution_counts.get('unavailable', 0),
                    'configuration_required': execution_counts.get('configuration_required', 0),
                    'queued': execution_counts.get('queued', 0),
                    'running': execution_counts.get('running', 0),
                    'cancelled': execution_counts.get('cancelled', 0),
                },
                recent=[serialize(session, scan, False) for scan in recent]))

    @api.post('/api/scans')
    @protected
    def create_scan():
        payload = body()
        if set(payload) - {'target', 'profile', 'tools', 'authorized', 'target_id'}: abort(400, 'Unsupported request fields.')
        if payload.get('authorized') is not True: abort(400, 'Explicit authorization confirmation is required.')
        profile = payload.get('profile', 'quick')
        if not isinstance(profile, str) or profile not in PROFILES: abort(400, 'Unknown scan profile.')
        tools = payload.get('tools', PROFILES[profile]['tools'])
        if not isinstance(tools, list) or not tools or not all(isinstance(t, str) and t in PROFILES[profile]['tools'] for t in tools):
            abort(400, 'Select supported tools for this profile.')
        if len(set(tools)) != len(tools): abort(400, 'Duplicate tool selection.')
        if profile != 'local' and any(t not in {'nmap', 'subfinder'} for t in tools) and 'nmap' not in tools: abort(400, 'Web assessment requires Nmap discovery.')
        if any(t in {'whatweb', 'nuclei', 'sslyze'} for t in tools) and 'httpx' not in tools: abort(400, 'Web assessment requires httpx discovery.')
        key = request.headers.get('Idempotency-Key', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', key): abort(400, 'Supply an Idempotency-Key of 16–128 letters, digits, underscores or hyphens.')
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        with manager.lock, Session(engine) as session:
            previous = session.get(ScanRequest, key)
            if previous:
                if previous.request_hash != digest: abort(409, 'Idempotency key was used with different input.')
                return jsonify(data=serialize(session, get_scan(session, previous.scan_id))), 200
            if time.monotonic() - last_created[0] < 0.5: abort(429, 'Please wait a moment between scan requests.')
            try:
                local = validate_local(payload.get('target'), settings.allowed_local_roots) if profile == 'local' else None
                checked = None if local else validate_target(payload.get('target'), settings.allowed_targets, settings.allow_private_targets)
            except ScopeError as error: abort(403, str(error))
            except TargetError as error: abort(400, str(error))
            # Phase 2 & 3: database authorization gate.
            auth_target = None
            if not local:
                explicit_target_id = payload.get('target_id')
                try:
                    if explicit_target_id:
                        auth_target = session.get(AuthorizedTarget, explicit_target_id)
                        if not auth_target:
                            abort(404, f'Specified authorized target "{explicit_target_id}" was not found.')
                    auth_target = find_authorizing_target(
                        checked.host,
                        tools,
                        session,
                        require=_require_auth_target,
                        preferred_target_id=explicit_target_id,
                    )
                    if auth_target:
                        auth_target = recheck_authorized_target(
                            auth_target.id, session, checked.host, tools
                        )
                        from .services.scope_validator import check_destination_excluded
                        dest_check = checked.canonical_endpoint or checked.host
                        exclusion_msg = check_destination_excluded(dest_check, auth_target)
                        if exclusion_msg:
                            raise ScopeError(exclusion_msg)
                except ScopeError as error:
                    actor = getattr(g, 'admin_username', None) or 'operator'
                    log_event(
                        session,
                        event_type='scan_authorization_rejected',
                        actor=actor,
                        resource_type='target',
                        resource_id=explicit_target_id,
                        details={'host': checked.host, 'tools': tools, 'reason': str(error)},
                        ip_address=request.remote_addr,
                        commit_with_transaction=True,
                    )
                    session.commit()
                    abort(403, str(error))
            if checked and len(checked.addresses) > 4: abort(400, 'At most four resolved addresses are supported.')
            if not manager.capacity.acquire(blocking=False): abort(429, 'Scan queue is full.')
            try:
                creator = current_user() or getattr(g, 'admin_username', None) or 'operator'
                target_value = local or (checked.canonical_endpoint if checked else None) or (checked.host if checked else payload.get('target'))
                scan = Scan(target=target_value, profile=profile, created_by=creator, configuration={
                    'addresses': list(checked.addresses) if checked else [], 'tools': tools, 'authorized': True,
                    'authorized_target_id': auth_target.id if auth_target else None,
                    'authorized_target_name': auth_target.name if auth_target else None,
                    'target_port': checked.port if checked else None,
                    'target_scheme': checked.scheme if checked else None,
                    'canonical_endpoint': checked.canonical_endpoint if checked else None,
                    'scope': 'Exact authorized local directory; bounded snapshot; no Git history.' if local else 'Exact target only; discovered subdomains are inventory, not scan permission.',
                    'limitations': 'Local filesystem/dependencies only; no web penetration test. No Git history. Keep source quiescent; links/reparse points rejected.' if local else 'IP-based web checks; no crawling or authenticated testing.'})
                session.add(scan)
                session.flush()
                for name in PROFILES[profile]['tools']:
                    if name in tools: scan.executions.append(ToolExecution(tool=name))
                session.add(ScanRequest(key=key, request_hash=digest, scan_id=scan.id))
                if auth_target:
                    try:
                        actor = getattr(g, 'admin_username', None) or 'operator'
                        session.add(TargetAuditEvent(
                            target_id=auth_target.id,
                            event_type='scan_dispatched',
                            actor=actor,
                            details={'scan_id': scan.id, 'profile': profile, 'tools': tools, 'host': checked.host if checked else local},
                            created_at=now(),
                        ))
                    except Exception:
                        pass
                try:
                    log_event(
                        session,
                        event_type='scan_dispatched',
                        actor=getattr(g, 'admin_username', None) or 'operator',
                        resource_type='scan',
                        resource_id=scan.id,
                        details={'profile': profile, 'tools': tools, 'target': scan.target},
                        ip_address=request.remote_addr,
                    )
                except Exception:
                    pass
                session.commit()
                data = serialize(session, scan)
                manager.submit(scan.id)
                last_created[0] = time.monotonic()
            except (ScopeError, ScopeAuthorizationError) as exc:
                session.rollback()
                manager.capacity.release()
                abort(403, str(exc))
            except (TargetError, ValueError) as exc:
                session.rollback()
                manager.capacity.release()
                abort(400, str(exc))
            except HTTPException:
                session.rollback()
                manager.capacity.release()
                raise
            except Exception as exc:
                import logging
                logging.getLogger(__name__).exception('Error during scan creation: %s', exc)
                session.rollback()
                manager.capacity.release()
                abort(500, 'An unexpected error occurred while creating the scan.')
            return jsonify(data=data), 202

    @api.get('/api/scans')
    @protected
    def scans():
        page, size = pagination()
        user = current_user()
        with Session(engine) as session:
            query = select(Scan)
            if user:
                query = query.where(Scan.created_by == user)
            if request.args.get('state'): query = query.where(Scan.state == request.args['state'])
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            items = session.scalars(query.order_by(Scan.created_at.desc()).offset((page-1)*size).limit(size))
            return jsonify(data=[serialize(session, scan, False) for scan in items], meta={'page': page, 'page_size': size, 'total': total})

    @api.get('/api/scans/compare')
    @protected
    def compare():
        with Session(engine) as session:
            first, second = (get_scan(session, request.args.get(key, '')) for key in ('first', 'second'))
            if first.target != second.target: abort(400, 'Compare scans of the same target.')
            if first.state not in TERMINAL or second.state not in TERMINAL: abort(409, 'Both scans must finish before comparison.')
            left, right = ({f.fingerprint: {'title': f.title, 'fingerprint': f.fingerprint, 'severity': f.severity} for f in scan.findings} for scan in (first, second))
            return jsonify(data={'new': [right[k] for k in right.keys()-left.keys()],
                'resolved_candidates': [left[k] for k in left.keys()-right.keys()],
                'unchanged': [right[k] for k in left.keys() & right.keys()],
                'warning': 'Resolved candidates means absent in the second scan, not verified remediation. Compare execution coverage and configuration.',
                'coverage': {'first': serialize(session, first, False), 'second': serialize(session, second, False)}})

    @api.get('/api/scans/<scan_id>')
    @protected
    def scan_detail(scan_id):
        with Session(engine) as session:
            try:
                scan = get_scan(session, scan_id)
                return jsonify(data=serialize(session, scan))
            except HTTPException:
                raise
            except Exception as exc:
                current_app.logger.exception('Error loading scan %s: %s', scan_id, exc)
                abort(500, 'Unable to load scan details.')

    @api.get('/api/scans/<scan_id>/findings')
    @protected
    def findings(scan_id):
        page, size = pagination()
        sort = request.args.get('sort', 'priority')
        if sort not in {'priority', 'title', 'target'}: abort(400, 'Unsupported sort field.')
        with Session(engine) as session:
            values = serialize(session, get_scan(session, scan_id))['findings']
            for key in ('severity', 'status', 'target', 'scanner'):
                selected = request.args.get(key)
                if not selected: continue
                if key == 'severity': values = [v for v in values if v['severity'] == selected]
                elif key == 'scanner': values = [v for v in values if any(s['tool'] == selected for s in v['details']['sources'])]
                elif key == 'target': values = [v for v in values if selected.lower() in v['details']['target'].lower()]
                else: values = [v for v in values if v['details'].get('status') == selected]
            values.sort(key=lambda v: (-v['details'].get('priority', 0), v['title']) if sort == 'priority' else
                        v['title'].lower() if sort == 'title' else v['details']['target'])
            return jsonify(data=values[(page-1)*size:page*size], meta={'page': page, 'page_size': size, 'total': len(values)})

    @api.post('/api/scans/<scan_id>/cancel')
    @protected
    def cancel(scan_id):
        with manager.lock, Session(engine) as session:
            scan = get_scan(session, scan_id)
            if scan.state in TERMINAL: abort(409, 'Scan has already finished.')
            manager.cancel(scan_id)
            try:
                log_event(
                    engine,
                    event_type='scan_cancellation_requested',
                    actor=getattr(g, 'admin_username', None) or 'operator',
                    resource_type='scan',
                    resource_id=scan_id,
                    details={},
                    ip_address=request.remote_addr,
                )
            except Exception:
                pass
        return jsonify(data={'id': scan_id, 'cancellation_requested': True}), 202

    @api.get('/api/scans/<scan_id>/report')
    @protected
    def report(scan_id):
        format_name = request.args.get('format', 'html').lower().strip()
        filenames = {'html': 'report.html', 'json': 'scan.json', 'vulnerabilities': 'vulnerabilities.json', 'pdf': 'report.pdf'}
        if format_name not in filenames: abort(400, 'Unsupported report format.')
        with manager.lock, Session(engine) as session:
            scan = get_scan(session, scan_id)
            if scan.state not in TERMINAL: abort(409, 'Report is available after the scan finishes.')
            serialized_scan = serialize(session, scan)
            if format_name == 'pdf':
                from .services.assessment_report_pdf import generate_assessment_report_pdf
                pdf_bytes = generate_assessment_report_pdf(serialized_scan)
                try:
                    log_event(
                        engine,
                        event_type='report_downloaded',
                        actor=getattr(g, 'admin_username', None) or 'operator',
                        resource_type='scan',
                        resource_id=scan_id,
                        details={'format': 'pdf'},
                        ip_address=request.remote_addr,
                    )
                except Exception:
                    pass
                safe_target = re.sub(r'[^a-zA-Z0-9_.-]', '_', scan.target)[:40]
                download_name = f"PATROLMAN_{safe_target}_{scan.id[:8]}_report.pdf"
                return send_file(io.BytesIO(pdf_bytes), as_attachment=True, download_name=download_name, mimetype='application/pdf')
            directory = write_reports(settings.data_dir, serialized_scan)
            try:
                log_event(
                    engine,
                    event_type='report_downloaded',
                    actor=getattr(g, 'admin_username', None) or 'operator',
                    resource_type='scan',
                    resource_id=scan_id,
                    details={'format': format_name},
                    ip_address=request.remote_addr,
                )
            except Exception:
                pass
            return send_file(directory / filenames[format_name], as_attachment=True, download_name=filenames[format_name])

    @api.delete('/api/scans/<scan_id>')
    @protected
    def delete(scan_id):
        if request.headers.get('X-Confirm-Delete') != scan_id: abort(400, 'Explicit scan-ID confirmation is required.')
        with manager.lock, Session(engine) as session:
            scan = get_scan(session, scan_id)
            if scan.state not in TERMINAL: abort(409, 'Cancel and finish the scan before deleting.')
            directory = report_directory(settings.data_dir, serialize(session, scan, False))
            # Forensic retention: preserve evidence records and physical artifacts
            retained_count = 0
            for ev in scan.evidence:
                ev.archived_scan_id = scan.id
                ev.scan_id = None
                retained_count += 1
            session.delete(scan); session.commit()
            shutil.rmtree(directory, ignore_errors=True)
            try:
                log_event(
                    engine,
                    event_type='scan_deleted',
                    actor=getattr(g, 'admin_username', None) or 'operator',
                    resource_type='scan',
                    resource_id=scan_id,
                    details={'evidence_retained': retained_count},
                    ip_address=request.remote_addr,
                )
            except Exception:
                pass
        return jsonify(data={'deleted': scan_id})

    app.register_blueprint(api)
