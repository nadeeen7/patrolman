from flask import Flask, abort, jsonify, request, send_from_directory
from pathlib import Path
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session
from werkzeug.exceptions import HTTPException
from .config import Settings
from .models import Base, Scan, ToolExecution, AuthorizedTarget, TargetAuditEvent, AuditEvent, Evidence, ToolVerification, migrate_schema
from .routes import install_routes
from .target_routes import install_target_routes
from .audit_routes import install_audit_routes
from .auth import install_auth
from .services.scan_service import ScanManager
from .services.target_validation import ScopeError, TargetError, validate_target, normalize_target
from .services.target_authorization import format_iso
from .services.tool_manager import (
    inventory, normalize_version, versions_match,
    seed_verified_cache_from_db, backfill_verifications_from_scans, persist_tool_verification,
)

# The built SPA uses external scripts only (the theme bootstrap lives in
# frontend/public/theme-init.js). Inline style attributes are used by React,
# so style-src keeps 'unsafe-inline'; script-src does not.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

_normalize_version = normalize_version
_versions_match = versions_match


def create_app(settings=None):
    settings = settings or Settings.from_env()
    settings.validate()
    for host in settings.allowed_targets:
        normalize_target(host)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=256 * 1024)
    engine = create_engine(URL.create('sqlite', database=str(settings.data_dir / 'assessment.sqlite3')), connect_args={'timeout': 15})

    @event.listens_for(engine, 'connect')
    def configure_sqlite(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA busy_timeout=15000')

    Base.metadata.create_all(engine)
    migrate_schema(engine)

    # Seed in-memory cache from durable tool verification records
    backfill_verifications_from_scans(engine)
    seed_verified_cache_from_db(engine)

    # Additive schema migration and database triggers
    with engine.begin() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(evidence)")).fetchall()]
        if cols and 'archived_scan_id' not in cols:
            conn.execute(text("ALTER TABLE evidence ADD COLUMN archived_scan_id VARCHAR(36)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_archived_scan_id ON evidence (archived_scan_id)"))

        # Finding 7: Database-level append-only protection for audit_events
        conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS prevent_audit_events_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(FAIL, 'audit_events is append-only and cannot be modified');
            END;
        """))
        conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS prevent_audit_events_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(FAIL, 'audit_events is append-only and cannot be deleted');
            END;
        """))

    app.extensions['database'] = engine

    protected = install_auth(app, engine, settings)

    @app.after_request
    def response_headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers.setdefault('Content-Security-Policy', CONTENT_SECURITY_POLICY)
        # Only sent when the request actually arrived over TLS; deploying behind
        # a TLS-terminating proxy requires placing this header at the proxy.
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error={'code': error.name.lower().replace(' ', '_'), 'message': error.description}), error.code

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.exception('Internal server error processing request to %s: %s', getattr(request, 'path', 'unknown'), error)
        return jsonify(error={'code': 'internal_error', 'message': 'An internal operation failed.'}), 500

    @app.errorhandler(SQLAlchemyError)
    def database_error(error):
        app.logger.exception('Database error processing request to %s: %s', getattr(request, 'path', 'unknown'), error)
        return jsonify(error={'code': 'database_unavailable', 'message': 'Database operation failed.'}), 503

    @app.get('/api/health')
    def health():
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        return jsonify(data={'status': 'ok', 'phase': 'integrated', 'scanning_enabled': True})

    @app.get('/api/tools')
    @protected
    def tools():
        # check_versions=false allows the frontend to render the dashboard shell
        # immediately using only filesystem-based tool discovery (instant), then
        # trigger a full version probe separately via the "Check availability"
        # button.  The default is true for backward compatibility.
        check_versions = request.args.get('check_versions', 'true').lower() != 'false'
        tool_inventory = inventory(
            check_versions=check_versions,
            allowed_local_roots=settings.allowed_local_roots,
        )

        latest_all = (
            select(ToolExecution.tool, func.max(ToolExecution.id).label('execution_id'))
            .group_by(ToolExecution.tool)
            .subquery()
        )
        latest_completed = (
            select(ToolExecution.tool, func.max(ToolExecution.id).label('execution_id'))
            .where(ToolExecution.state == 'completed')
            .group_by(ToolExecution.tool)
            .subquery()
        )
        with Session(engine) as session:
            all_rows = session.execute(
                select(ToolExecution, Scan)
                .join(latest_all, ToolExecution.id == latest_all.c.execution_id)
                .join(Scan, Scan.id == ToolExecution.scan_id)
            ).all()
            completed_rows = session.execute(
                select(ToolExecution, Scan)
                .join(latest_completed, ToolExecution.id == latest_completed.c.execution_id)
                .join(Scan, Scan.id == ToolExecution.scan_id)
            ).all()
            persisted_verifs = {
                v.tool: v
                for v in session.scalars(select(ToolVerification)).all()
            }

        all_map = {execution.tool: (execution, scan) for execution, scan in all_rows}
        completed_map = {execution.tool: (execution, scan) for execution, scan in completed_rows}

        workflow = {}
        for item in tool_inventory:
            tool_name = item['name']
            current_version = item.get('version')
            persisted = persisted_verifs.get(tool_name)

            all_tuple = all_map.get(tool_name)
            comp_tuple = completed_map.get(tool_name)

            if not all_tuple:
                if persisted and persisted.verification_status == 'verified':
                    last_version = persisted.verified_version
                    if current_version and last_version and _versions_match(last_version, current_version):
                        workflow[tool_name] = {
                            'status': 'verified',
                            'last_state': 'completed',
                            'last_checked_at': format_iso(persisted.verified_at),
                        }
                        continue
                    elif current_version and last_version and not _versions_match(last_version, current_version):
                        workflow[tool_name] = {
                            'status': 'version_changed',
                            'last_state': None,
                            'last_checked_at': format_iso(persisted.verified_at),
                        }
                        continue
                    elif not check_versions:
                        workflow[tool_name] = {
                            'status': 'verified',
                            'last_state': 'completed',
                            'last_checked_at': format_iso(persisted.verified_at),
                        }
                        continue
                workflow[tool_name] = {
                    'status': 'not_verified',
                    'last_state': None,
                    'last_checked_at': None,
                }
                continue

            last_execution, last_scan = all_tuple

            if last_execution.state == 'failed':
                verification_status = 'failed'
                last_state = 'failed'
                last_checked = last_execution.ended_at
            elif last_execution.state == 'timed_out':
                verification_status = 'timed_out'
                last_state = 'timed_out'
                last_checked = last_execution.ended_at
            elif comp_tuple or (persisted and persisted.verification_status == 'verified'):
                if comp_tuple:
                    comp_exec, comp_scan = comp_tuple
                    metadata = (comp_scan.configuration or {}).get('tool_metadata', {}).get(tool_name, {})
                    last_version = metadata.get('version') or (persisted.verified_version if persisted else None)
                    last_state = last_execution.state
                    last_checked = comp_exec.ended_at or last_execution.ended_at
                else:
                    comp_exec, comp_scan = None, None
                    last_version = persisted.verified_version
                    last_state = last_execution.state
                    last_checked = persisted.verified_at or last_execution.ended_at

                if current_version and last_version and _versions_match(last_version, current_version):
                    verification_status = 'verified'
                    if check_versions and comp_exec and comp_scan:
                        persist_tool_verification(
                            engine, tool_name, current_version,
                            execution_id=comp_exec.id, evidence_reference=f"scan:{comp_scan.id}"
                        )
                elif current_version and last_version and not _versions_match(last_version, current_version):
                    verification_status = 'version_changed'
                elif not check_versions:
                    if persisted and persisted.verification_status == 'verified' and last_version and _versions_match(last_version, persisted.verified_version):
                        verification_status = 'verified'
                    else:
                        verification_status = 'pending_check'
                else:
                    verification_status = 'not_verified'
            else:
                verification_status = 'not_verified'
                last_state = last_execution.state
                last_checked = last_execution.ended_at

            workflow[tool_name] = {
                'status': verification_status,
                'last_state': last_state,
                'last_checked_at': format_iso(last_checked),
            }

        result = []
        for item in tool_inventory:
            item = dict(item)
            tool_name = item['name']
            evidence = workflow.get(tool_name, {
                'status': 'not_verified',
                'last_state': None,
                'last_checked_at': None,
            })
            item['workflow_verification'] = evidence

            persisted = persisted_verifs.get(tool_name)
            if not item.get('version') and persisted and persisted.verification_status == 'verified' and evidence['status'] == 'verified':
                item['version'] = persisted.verified_version
                if item.get('version_verification', {}).get('message') == 'Version check not requested.':
                    item['version_verification'] = {
                        'status': 'verified',
                        'version': persisted.verified_version,
                        'message': f'Executable version {persisted.verified_version} verified (persisted).'
                    }

            if evidence['status'] == 'version_changed':
                item['status'] = 'unverified'
                item['state'] = 'UNVERIFIED'
                item['integration_ready'] = False
                item['reason'] = 'The current executable version differs from the last successful assessment.'
            elif item['status'] == 'ready' and evidence['status'] != 'verified':
                item['status'] = 'unverified'
                item['state'] = 'UNVERIFIED'
                item['integration_ready'] = False
                item['reason'] = (
                    'Executable identity and configuration checks passed, but the latest workflow '
                    'evidence does not confirm a successful assessment and result parse for this version.'
                )
            elif item['status'] == 'ready' and evidence['status'] == 'verified':
                item['reason'] = (
                    'A successful assessment execution and result parsing record exists for '
                    'this version; future availability is not guaranteed.'
                )
            elif not check_versions and item['status'] == 'unverified' and evidence['status'] == 'verified' and item.get('executable_found'):
                runtime_blocked = item.get('runtime_configuration', {}).get('status') == 'configuration_required'
                opt_in_disabled = item.get('operator_opt_in', {}).get('status') == 'disabled'
                if not runtime_blocked and not opt_in_disabled:
                    item['status'] = 'ready'
                    item['state'] = 'READY'
                    item['integration_ready'] = True
                    item['reason'] = (
                        'A successful assessment execution and result parsing record exists for '
                        'this version; future availability is not guaranteed.'
                    )
            result.append({key: value for key, value in item.items() if key != 'executable'})
        return jsonify(data=result)


    @app.post('/api/targets/validate')
    @protected
    def target_check():
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != {'target'}:
            return jsonify(error={'code': 'invalid_input', 'message': 'Expected a JSON object containing only target.'}), 400
        try:
            target = validate_target(payload['target'], settings.allowed_targets, settings.allow_private_targets)
        except ScopeError as error:
            return jsonify(error={'code': 'out_of_scope', 'message': str(error)}), 403
        except TargetError as error:
            return jsonify(error={'code': 'invalid_target', 'message': str(error)}), 400
        return jsonify(data={'host': target.host, 'addresses': target.addresses, 'scanning_enabled': True})

    manager = ScanManager(engine, settings)
    app.extensions['scan_manager'] = manager
    install_routes(app, engine, settings, protected, manager)
    install_target_routes(app, engine, protected)
    install_audit_routes(app, engine, settings, protected)
    frontend = Path(__file__).resolve().parents[1] / 'frontend' / 'dist'

    @app.get('/')
    @app.get('/<path:path>')
    def frontend_route(path=''):
        from flask import abort
        if path.startswith('api/') or path == 'api': abort(404)
        if not (frontend / 'index.html').is_file():
            return jsonify(error={'code': 'frontend_not_built', 'message': 'Run npm install and npm run build in frontend.'}), 503
        if path.startswith('assets/'):
            return send_from_directory(frontend, path)
        return send_from_directory(frontend, 'index.html')

    return app


if __name__ == '__main__':
    from .server import run
    run()
