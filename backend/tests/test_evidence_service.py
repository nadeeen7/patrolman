"""Unit tests for Evidence Service."""
import hashlib
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.models import Base, Scan, Evidence
from backend.services.evidence_service import (
    MAX_EVIDENCE_SIZE,
    get_evidence_file,
    get_evidence_root,
    query_evidence,
    serialize_evidence,
    store_evidence,
)


@pytest.fixture
def test_setup(tmp_path):
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    data_dir = tmp_path / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)
    with Session(engine) as session:
        scan = Scan(id='scan-test-1', target='127.0.0.1', profile='quick', configuration={})
        session.add(scan)
        session.commit()
    return engine, data_dir


def test_store_and_retrieve_evidence(test_setup):
    engine, data_dir = test_setup
    content = b"Nmap scan report for 127.0.0.1\nPORT 80/tcp open http\n"
    expected_hash = hashlib.sha256(content).hexdigest()

    ev = store_evidence(
        target=engine,
        data_dir=data_dir,
        scan_id='scan-test-1',
        tool='nmap',
        evidence_type='raw_output',
        content=content,
        filename='nmap_output.txt',
    )

    assert ev.id is not None
    assert ev.scan_id == 'scan-test-1'
    assert ev.tool == 'nmap'
    assert ev.sha256_hash == expected_hash
    assert ev.file_size == len(content)

    # Retrieve and verify cryptographic hash
    file_path, retrieved = get_evidence_file(engine, data_dir, ev.id)
    assert file_path.is_file()
    assert file_path.read_bytes() == content
    assert retrieved.sha256_hash == expected_hash


def test_oversized_evidence_rejected(test_setup):
    engine, data_dir = test_setup
    oversized = b"x" * (MAX_EVIDENCE_SIZE + 1)
    with pytest.raises(ValueError, match='exceeds maximum allowed 10 MB limit'):
        store_evidence(
            target=engine,
            data_dir=data_dir,
            scan_id='scan-test-1',
            tool='nmap',
            evidence_type='raw_output',
            content=oversized,
        )


def test_path_traversal_prevention(test_setup):
    engine, data_dir = test_setup
    # Attempting to supply ../../evil.txt as filename should be sanitized safely
    ev = store_evidence(
        target=engine,
        data_dir=data_dir,
        scan_id='scan-test-1',
        tool='nmap',
        evidence_type='raw_output',
        content=b"test data",
        filename='../../evil.txt',
    )
    # File must be stored strictly within data_dir/evidence
    root = get_evidence_root(data_dir)
    file_path, _ = get_evidence_file(engine, data_dir, ev.id)
    assert file_path.is_relative_to(root)
    assert '..' not in ev.file_path


def test_tampered_evidence_fails_integrity(test_setup):
    engine, data_dir = test_setup
    content = b"original unmodified output"
    ev = store_evidence(
        target=engine,
        data_dir=data_dir,
        scan_id='scan-test-1',
        tool='httpx',
        evidence_type='raw_output',
        content=content,
    )

    file_path, _ = get_evidence_file(engine, data_dir, ev.id)
    # Tamper with the file on disk
    file_path.write_bytes(b"TAMPERED CONTENT")

    with pytest.raises(ValueError, match='Cryptographic integrity failure'):
        get_evidence_file(engine, data_dir, ev.id)


def test_query_evidence(test_setup):
    engine, data_dir = test_setup
    store_evidence(engine, data_dir, 'scan-test-1', 'nmap', 'raw_output', b"content 1")
    store_evidence(engine, data_dir, 'scan-test-1', 'nuclei', 'raw_output', b"content 2")
    store_evidence(engine, data_dir, 'scan-test-1', 'sslyze', 'certificate', b"content 3")

    # Query all
    res = query_evidence(engine, page=1, page_size=10)
    assert res['total'] == 3

    # Query by tool
    res_tool = query_evidence(engine, tool='nuclei')
    assert res_tool['total'] == 1
    assert res_tool['items'][0]['tool'] == 'nuclei'

    # Query by evidence_type
    res_type = query_evidence(engine, evidence_type='certificate')
    assert res_type['total'] == 1
    assert res_type['items'][0]['tool'] == 'sslyze'


def test_redacted_evidence_sanitization_and_byte_exact_hash(test_setup):
    """Finding 1: Redacted evidence must sanitize secrets before writing to disk and calculate byte-exact hashes."""
    engine, data_dir = test_setup
    fake_token = "SYNTH_TOKEN_SECRET_XYZ_123"
    fake_password = "SYNTH_PASSWORD_SECRET_ABC_456"
    raw_content = (
        f"Authorization: Bearer {fake_token}\n"
        f"password={fake_password}\n"
        f"Ordinary diagnostic log line.\n"
    )

    ev = store_evidence(
        target=engine,
        data_dir=data_dir,
        scan_id='scan-test-1',
        tool='nuclei',
        evidence_type='raw_output',
        content=raw_content,
        filename='nuclei_output.txt',
        redacted=True,
    )

    assert ev.redacted is True
    file_path, retrieved = get_evidence_file(engine, data_dir, ev.id)
    stored_bytes = file_path.read_bytes()

    # The stored bytes MUST NOT contain the fake secrets
    assert fake_token.encode('utf-8') not in stored_bytes
    assert fake_password.encode('utf-8') not in stored_bytes
    assert b"[REDACTED]" in stored_bytes
    assert b"Ordinary diagnostic log line." in stored_bytes

    # Hash must match the exact bytes that were stored
    computed_hash = hashlib.sha256(stored_bytes).hexdigest()
    assert ev.sha256_hash == computed_hash
    assert ev.file_size == len(stored_bytes)
    assert retrieved.sha256_hash == computed_hash


def test_missing_evidence_file_raises_filenotfound(test_setup):
    """Finding 2: Missing evidence file on disk raises FileNotFoundError safely."""
    engine, data_dir = test_setup
    ev = store_evidence(
        target=engine,
        data_dir=data_dir,
        scan_id='scan-test-1',
        tool='nmap',
        evidence_type='raw_output',
        content=b"test data",
    )
    file_path, _ = get_evidence_file(engine, data_dir, ev.id)
    file_path.unlink()  # simulate file disappearance

    with pytest.raises(FileNotFoundError, match="missing on disk"):
        get_evidence_file(engine, data_dir, ev.id)


def test_evidence_custom_security_exceptions(test_setup):
    """Finding 3: Integrity and traversal violations raise specific security exceptions."""
    from backend.services.evidence_service import EvidenceIntegrityError, EvidencePathTraversalError
    engine, data_dir = test_setup

    ev = store_evidence(
        target=engine,
        data_dir=data_dir,
        scan_id='scan-test-1',
        tool='nmap',
        evidence_type='raw_output',
        content=b"authentic content",
    )
    file_path, _ = get_evidence_file(engine, data_dir, ev.id)
    file_path.write_bytes(b"tampered content")

    with pytest.raises(EvidenceIntegrityError):
        get_evidence_file(engine, data_dir, ev.id)


def test_forensic_retention_preserves_evidence_after_scan_deletion(test_setup):
    """Finding 5: Evidence records and files are retained forensically after scan deletion."""
    engine, data_dir = test_setup
    ev = store_evidence(
        target=engine,
        data_dir=data_dir,
        scan_id='scan-test-1',
        tool='nmap',
        evidence_type='raw_output',
        content=b"forensic evidence artifact",
    )

    with Session(engine) as session:
        scan = session.get(Scan, 'scan-test-1')
        for item in scan.evidence:
            item.archived_scan_id = scan.id
            item.scan_id = None
        session.delete(scan)
        session.commit()

    # Evidence record is preserved
    with Session(engine) as session:
        retrieved = session.get(Evidence, ev.id)
        assert retrieved is not None
        assert retrieved.scan_id is None
        assert retrieved.archived_scan_id == 'scan-test-1'

    # File artifact on disk remains intact and verifiable
    file_path, retrieved_ev = get_evidence_file(engine, data_dir, ev.id)
    assert file_path.is_file()
    assert file_path.read_bytes() == b"forensic evidence artifact"

    # Querying by scan_id still finds the forensically retained evidence
    results = query_evidence(engine, scan_id='scan-test-1')
    assert results['total'] == 1
    assert results['items'][0]['id'] == ev.id
    assert results['items'][0]['scan_id'] == 'scan-test-1'
