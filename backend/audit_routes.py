"""Routes for Phase 4: Audit Trail and Evidence Locker."""
import io
from pathlib import Path
from flask import Blueprint, abort, g, jsonify, request, send_file
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .services.audit_service import log_event, query_events
from .services.evidence_service import (
    EvidenceIntegrityError,
    EvidencePathTraversalError,
    get_evidence_file,
    query_evidence,
    serialize_evidence,
)
from .services.evidence_pdf import generate_evidence_pdf
from .models import Finding, Scan, ToolVerification, now


def install_audit_routes(app, engine: Engine, settings, protected):
    api = Blueprint('audit_evidence', __name__)

    def get_actor():
        return getattr(g, 'admin_username', None) or 'administrator'

    def pagination():
        try:
            page, size = int(request.args.get('page', 1)), int(request.args.get('page_size', 20))
        except ValueError:
            abort(400, 'Invalid pagination parameters.')
        if page < 1 or not 1 <= size <= 100:
            abort(400, 'Invalid pagination parameters.')
        return page, size

    @api.get('/api/audit-events')
    @protected
    def list_audit_events():
        page, size = pagination()
        event_type = request.args.get('event_type')
        actor = request.args.get('actor')
        resource_type = request.args.get('resource_type')
        resource_id = request.args.get('resource_id')
        start_date = request.args.get('start_date') or request.args.get('from')
        end_date = request.args.get('end_date') or request.args.get('to')

        try:
            result = query_events(
                engine=engine,
                page=page,
                page_size=size,
                event_type=event_type,
                actor=actor,
                resource_type=resource_type,
                resource_id=resource_id,
                start_date=start_date,
                end_date=end_date,
            )
        except ValueError as err:
            abort(400, str(err))

        return jsonify(
            data=result['items'],
            meta={
                'page': result['page'],
                'page_size': result['page_size'],
                'total': result['total'],
            },
        )

    @api.get('/api/evidence')
    @protected
    def list_evidence():
        page, size = pagination()
        scan_id = request.args.get('scan_id')
        tool = request.args.get('tool')
        evidence_type = request.args.get('evidence_type')

        finding_id = None
        if request.args.get('finding_id'):
            try:
                finding_id = int(request.args['finding_id'])
            except ValueError:
                abort(400, 'finding_id must be an integer.')

        execution_id = None
        if request.args.get('execution_id'):
            try:
                execution_id = int(request.args['execution_id'])
            except ValueError:
                abort(400, 'execution_id must be an integer.')

        actor = get_actor()
        if scan_id:
            with Session(engine) as s:
                target_scan = s.get(Scan, scan_id.strip())
                if target_scan and target_scan.created_by and target_scan.created_by != actor:
                    abort(404, 'Scan not found.')

        try:
            result = query_evidence(
                engine=engine,
                page=page,
                page_size=size,
                scan_id=scan_id,
                tool=tool,
                evidence_type=evidence_type,
                finding_id=finding_id,
                execution_id=execution_id,
                created_by=get_actor(),
            )
        except ValueError as err:
            abort(400, str(err))

        return jsonify(
            data=result['items'],
            meta={
                'page': result['page'],
                'page_size': result['page_size'],
                'total': result['total'],
            },
        )

    @api.get('/api/evidence/<evidence_id>')
    @protected
    def get_evidence_detail(evidence_id):
        try:
            res = get_evidence_file(engine, settings.data_dir, evidence_id)
        except EvidenceIntegrityError:
            log_event(
                engine,
                event_type='evidence_integrity_failure',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={'reason': 'Cryptographic integrity failure'},
                ip_address=request.remote_addr,
            )
            abort(409, 'Evidence cryptographic integrity verification failed.')
        except EvidencePathTraversalError:
            log_event(
                engine,
                event_type='evidence_path_traversal',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={'reason': 'Path confinement violation'},
                ip_address=request.remote_addr,
            )
            abort(400, 'Invalid evidence storage path.')
        except FileNotFoundError:
            abort(404, 'Evidence file is missing on disk.')
        except ValueError as err:
            abort(400, str(err))

        if res is None:
            abort(404, 'Evidence not found.')
        _, evidence = res
        actor = get_actor()
        if actor and getattr(evidence, 'created_by', None) and evidence.created_by != actor:
            abort(404, 'Evidence not found.')
        return jsonify(data=serialize_evidence(evidence))

    @api.get('/api/evidence/<evidence_id>/download')
    @api.get('/api/evidence/<evidence_id>/pdf')
    @protected
    def download_evidence(evidence_id):
        format_param = request.args.get('format', '').lower().strip()
        is_pdf = request.path.endswith('/pdf') or format_param == 'pdf'

        try:
            res = get_evidence_file(engine, settings.data_dir, evidence_id)
        except EvidenceIntegrityError:
            log_event(
                engine,
                event_type='evidence_integrity_failure',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={'reason': 'Cryptographic integrity failure'},
                ip_address=request.remote_addr,
            )
            abort(409, 'Evidence cryptographic integrity verification failed.')
        except EvidencePathTraversalError:
            log_event(
                engine,
                event_type='evidence_path_traversal',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={'reason': 'Path confinement violation'},
                ip_address=request.remote_addr,
            )
            abort(400, 'Invalid evidence storage path.')
        except FileNotFoundError:
            abort(404, 'Evidence file is missing on disk.')
        except ValueError as err:
            abort(400, str(err))

        if res is None:
            abort(404, 'Evidence not found.')

        full_path, evidence = res
        actor = get_actor()
        if actor and getattr(evidence, 'created_by', None) and evidence.created_by != actor:
            abort(404, 'Evidence not found.')

        download_filename = Path(evidence.file_path).name
        # Strip internal uuid prefix from filename if present
        if '_' in download_filename:
            download_filename = download_filename.split('_', 1)[1]

        if is_pdf:
            # Query contextual scan and associated findings
            with Session(engine) as session:
                scan = session.get(Scan, evidence.scan_id) if evidence.scan_id else None
                if not scan and getattr(evidence, 'archived_scan_id', None):
                    scan = session.get(Scan, evidence.archived_scan_id)

                tool_ver = session.get(ToolVerification, evidence.tool)
                tool_version = tool_ver.verified_version if tool_ver else None

                findings = []
                if evidence.finding_id:
                    f = session.get(Finding, evidence.finding_id)
                    if f:
                        findings.append(f)
                elif scan and scan.findings:
                    for f in scan.findings:
                        sources = f.details.get('sources', [])
                        if any(s.get('tool') == evidence.tool for s in sources):
                            findings.append(f)

            raw_bytes = full_path.read_bytes()
            pdf_bytes = generate_evidence_pdf(
                evidence=evidence,
                raw_bytes=raw_bytes,
                filename=download_filename,
                scan=scan,
                findings=findings,
                tool_version=tool_version,
            )

            # Audit log the evidence PDF export
            try:
                log_event(
                    engine,
                    event_type='evidence_pdf_exported',
                    actor=get_actor(),
                    resource_type='evidence',
                    resource_id=evidence_id,
                    details={
                        'tool': evidence.tool,
                        'type': evidence.evidence_type,
                        'source_sha256': evidence.sha256_hash,
                        'pdf_size': len(pdf_bytes),
                    },
                    ip_address=request.remote_addr,
                )
            except Exception:
                pass

            pdf_filename = f"{Path(download_filename).stem}_report.pdf"
            return send_file(
                io.BytesIO(pdf_bytes),
                as_attachment=True,
                download_name=pdf_filename,
                mimetype='application/pdf',
            )

        # Audit log the evidence raw download
        try:
            log_event(
                engine,
                event_type='evidence_downloaded',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={'tool': evidence.tool, 'type': evidence.evidence_type, 'sha256': evidence.sha256_hash},
                ip_address=request.remote_addr,
            )
        except Exception:
            pass

        return send_file(
            full_path,
            as_attachment=True,
            download_name=download_filename,
            mimetype='application/octet-stream',
        )

    @api.get('/api/evidence/<evidence_id>/preview')
    @protected
    def preview_evidence(evidence_id):
        try:
            res = get_evidence_file(engine, settings.data_dir, evidence_id)
        except EvidenceIntegrityError:
            log_event(
                engine,
                event_type='evidence_integrity_failure',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={'reason': 'Cryptographic integrity failure'},
                ip_address=request.remote_addr,
            )
            abort(409, 'Evidence cryptographic integrity verification failed.')
        except EvidencePathTraversalError:
            log_event(
                engine,
                event_type='evidence_path_traversal',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={'reason': 'Path confinement violation'},
                ip_address=request.remote_addr,
            )
            abort(400, 'Invalid evidence storage path.')
        except FileNotFoundError:
            abort(404, 'Evidence file is missing on disk.')
        except ValueError as err:
            abort(400, str(err))

        if res is None:
            abort(404, 'Evidence not found.')

        full_path, evidence = res
        actor = get_actor()
        if actor and getattr(evidence, 'created_by', None) and evidence.created_by != actor:
            abort(404, 'Evidence not found.')

        download_filename = Path(evidence.file_path).name
        if '_' in download_filename:
            download_filename = download_filename.split('_', 1)[1]

        with Session(engine) as session:
            scan = session.get(Scan, evidence.scan_id) if evidence.scan_id else None
            if not scan and getattr(evidence, 'archived_scan_id', None):
                scan = session.get(Scan, evidence.archived_scan_id)

            tool_ver = session.get(ToolVerification, evidence.tool)
            tool_version = tool_ver.verified_version if tool_ver else None

            findings = []
            if evidence.finding_id:
                f = session.get(Finding, evidence.finding_id)
                if f:
                    findings.append(f)
            elif scan and scan.findings:
                for f in scan.findings:
                    sources = f.details.get('sources', [])
                    if any(s.get('tool') == evidence.tool for s in sources):
                        findings.append(f)

        raw_bytes = full_path.read_bytes()
        pdf_bytes = generate_evidence_pdf(
            evidence=evidence,
            raw_bytes=raw_bytes,
            filename=download_filename,
            scan=scan,
            findings=findings,
            tool_version=tool_version,
        )

        try:
            log_event(
                engine,
                event_type='evidence_pdf_previewed',
                actor=get_actor(),
                resource_type='evidence',
                resource_id=evidence_id,
                details={
                    'tool': evidence.tool,
                    'type': evidence.evidence_type,
                    'source_sha256': evidence.sha256_hash,
                    'pdf_size': len(pdf_bytes),
                },
                ip_address=request.remote_addr,
            )
        except Exception:
            pass

        pdf_filename = f"{Path(download_filename).stem}_report.pdf"
        response = send_file(
            io.BytesIO(pdf_bytes),
            as_attachment=False,
            download_name=pdf_filename,
            mimetype='application/pdf',
        )
        response.headers['Content-Disposition'] = f'inline; filename="{pdf_filename}"'
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Length'] = str(len(pdf_bytes))
        return response

    app.register_blueprint(api)
