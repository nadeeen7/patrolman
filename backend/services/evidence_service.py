"""Cryptographically verifiable evidence management service with path traversal defense."""
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union
from uuid import uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ..models import Evidence, Scan, now
from .results import sanitize_secrets

MAX_EVIDENCE_SIZE = 10 * 1024 * 1024  # 10 MB limit
MAX_TOOL_NAME_LENGTH = 32
MAX_EVIDENCE_TYPE_LENGTH = 64
FILENAME_CLEAN_RE = re.compile(r'[^a-zA-Z0-9._-]')


class EvidenceSecurityError(ValueError):
    """Base exception for evidence security violations."""
    pass


class EvidenceIntegrityError(EvidenceSecurityError):
    """Raised when an evidence file's cryptographic hash does not match its record."""
    pass


class EvidencePathTraversalError(EvidenceSecurityError):
    """Raised when an evidence storage path attempts directory traversal."""
    pass


def _sanitize_filename(name: Optional[str], default: str = 'evidence.bin') -> str:
    """Sanitize filename to prevent directory traversal and invalid characters."""
    if not name or not isinstance(name, str):
        return default
    basename = Path(name).name
    cleaned = FILENAME_CLEAN_RE.sub('_', basename).strip('._')
    return cleaned[:128] if cleaned else default


def get_evidence_root(data_dir: Path) -> Path:
    """Return and ensure the canonical evidence storage root directory."""
    root = (Path(data_dir) / 'evidence').resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def store_evidence(
    target: Union[Engine, Session],
    data_dir: Path,
    scan_id: str,
    tool: str,
    evidence_type: str,
    content: Union[bytes, str],
    filename: Optional[str] = None,
    finding_id: Optional[int] = None,
    execution_id: Optional[int] = None,
    redacted: bool = False,
    created_by: Optional[str] = None,
) -> Evidence:
    """Store evidence safely on disk and record cryptographic hash in the database.
    
    If redacted is True, secrets are sanitized BEFORE bytes are written to disk,
    and cryptographic hash is computed from the exact stored bytes.
    """
    if not scan_id or not isinstance(scan_id, str):
        raise ValueError('scan_id must be a non-empty string.')
    if not tool or not isinstance(tool, str):
        raise ValueError('tool must be a non-empty string.')
    if not evidence_type or not isinstance(evidence_type, str):
        raise ValueError('evidence_type must be a non-empty string.')

    tool_str = tool.strip()[:MAX_TOOL_NAME_LENGTH]
    type_str = evidence_type.strip()[:MAX_EVIDENCE_TYPE_LENGTH]

    # Finding 1: Secret sanitization before storage
    if redacted:
        if isinstance(content, str):
            content = sanitize_secrets(content)
            raw_bytes = content.encode('utf-8')
        elif isinstance(content, (bytes, bytearray)):
            try:
                decoded = bytes(content).decode('utf-8')
                sanitized = sanitize_secrets(decoded)
                raw_bytes = sanitized.encode('utf-8')
            except UnicodeDecodeError:
                raw_bytes = bytes(content)
        else:
            raise TypeError('content must be bytes or str.')
    else:
        if isinstance(content, str):
            raw_bytes = content.encode('utf-8')
        elif isinstance(content, (bytes, bytearray)):
            raw_bytes = bytes(content)
        else:
            raise TypeError('content must be bytes or str.')

    size = len(raw_bytes)
    if size > MAX_EVIDENCE_SIZE:
        raise ValueError(f'Evidence size ({size} bytes) exceeds maximum allowed 10 MB limit.')

    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    evidence_id = str(uuid4())

    safe_name = _sanitize_filename(filename, default=f'{tool_str}_{type_str}.txt')
    safe_rel_dir = Path('scans') / scan_id.strip()
    safe_rel_path = safe_rel_dir / f'{evidence_id}_{safe_name}'

    root = get_evidence_root(data_dir)
    target_path = (root / safe_rel_path).resolve()

    # Path traversal validation: target path must be strictly within evidence root
    try:
        target_path.relative_to(root)
    except ValueError as err:
        raise EvidencePathTraversalError(f'Path traversal attempt detected: {err}')

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(raw_bytes)

    if not created_by and scan_id:
        try:
            if isinstance(target, Session):
                s_obj = target.get(Scan, scan_id.strip())
                if s_obj and s_obj.created_by:
                    created_by = s_obj.created_by
            elif isinstance(target, Engine):
                with Session(target) as sess:
                    s_obj = sess.get(Scan, scan_id.strip())
                    if s_obj and s_obj.created_by:
                        created_by = s_obj.created_by
        except Exception:
            pass

    evidence = Evidence(
        id=evidence_id,
        scan_id=scan_id.strip(),
        finding_id=finding_id,
        execution_id=execution_id,
        tool=tool_str,
        evidence_type=type_str,
        file_path=str(safe_rel_path.as_posix()),
        file_size=size,
        sha256_hash=sha256_hash,
        redacted=bool(redacted),
        created_at=now(),
        created_by=created_by,
    )

    if isinstance(target, Session):
        target.add(evidence)
    elif isinstance(target, Engine):
        with Session(target, expire_on_commit=False) as session:
            session.add(evidence)
            session.commit()
    else:
        raise TypeError('target must be an SQLAlchemy Session or Engine.')

    return evidence


def get_evidence_file(engine: Engine, data_dir: Path, evidence_id: str) -> Optional[tuple[Path, Evidence]]:
    """Retrieve an evidence record and verify its storage path and cryptographic hash."""
    if not evidence_id or not isinstance(evidence_id, str):
        return None

    with Session(engine) as session:
        evidence = session.get(Evidence, evidence_id)
        if evidence is None:
            return None

        root = get_evidence_root(data_dir)
        full_path = (root / evidence.file_path).resolve()

        # Path traversal prevention
        try:
            full_path.relative_to(root)
        except ValueError:
            raise EvidencePathTraversalError('Path traversal attempt detected in evidence storage path.')

        if not full_path.is_file():
            raise FileNotFoundError(f'Evidence artifact for ID {evidence_id} is missing on disk.')

        # Cryptographic integrity verification
        actual_hash = hashlib.sha256(full_path.read_bytes()).hexdigest()
        if actual_hash != evidence.sha256_hash:
            raise EvidenceIntegrityError(f'Cryptographic integrity failure for evidence ID {evidence_id}.')

        # Detach/copy evidence data for safe consumption outside session
        detached_evidence = Evidence(
            id=evidence.id,
            scan_id=evidence.scan_id,
            archived_scan_id=getattr(evidence, 'archived_scan_id', None),
            finding_id=evidence.finding_id,
            execution_id=evidence.execution_id,
            tool=evidence.tool,
            evidence_type=evidence.evidence_type,
            file_path=evidence.file_path,
            file_size=evidence.file_size,
            sha256_hash=evidence.sha256_hash,
            redacted=evidence.redacted,
            created_at=evidence.created_at,
            created_by=getattr(evidence, 'created_by', None),
        )

        return full_path, detached_evidence


def serialize_evidence(evidence: Evidence) -> dict[str, Any]:
    """Serialize an Evidence record for API responses."""
    return {
        'id': evidence.id,
        'scan_id': evidence.scan_id or getattr(evidence, 'archived_scan_id', None),
        'finding_id': evidence.finding_id,
        'execution_id': evidence.execution_id,
        'tool': evidence.tool,
        'evidence_type': evidence.evidence_type,
        'file_path': evidence.file_path,
        'file_size': evidence.file_size,
        'sha256_hash': evidence.sha256_hash,
        'redacted': evidence.redacted,
        'created_at': evidence.created_at.isoformat() if evidence.created_at else None,
        'created_by': getattr(evidence, 'created_by', None),
    }


def query_evidence(
    engine: Engine,
    page: int = 1,
    page_size: int = 20,
    scan_id: Optional[str] = None,
    tool: Optional[str] = None,
    evidence_type: Optional[str] = None,
    finding_id: Optional[int] = None,
    execution_id: Optional[int] = None,
    created_by: Optional[str] = None,
) -> dict[str, Any]:
    """Query evidence items with filtering and pagination."""
    if page < 1:
        raise ValueError('page must be at least 1.')
    if not 1 <= page_size <= 100:
        raise ValueError('page_size must be between 1 and 100.')

    with Session(engine) as session:
        query = select(Evidence)

        if created_by:
            query = query.where(or_(Evidence.created_by == created_by, Evidence.created_by.is_(None)))
        if scan_id:
            query = query.where(or_(Evidence.scan_id == scan_id.strip(), Evidence.archived_scan_id == scan_id.strip()))
        if tool:
            query = query.where(Evidence.tool == tool)
        if evidence_type:
            query = query.where(Evidence.evidence_type == evidence_type)
        if finding_id is not None:
            query = query.where(Evidence.finding_id == finding_id)
        if execution_id is not None:
            query = query.where(Evidence.execution_id == execution_id)

        total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = session.scalars(
            query.order_by(Evidence.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()

        return {
            'items': [serialize_evidence(item) for item in items],
            'total': total,
            'page': page,
            'page_size': page_size,
        }
