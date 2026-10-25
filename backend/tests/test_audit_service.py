"""Unit tests for Audit Service."""
import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.models import Base, AuditEvent
from backend.services.audit_service import log_event, query_events, serialize_audit_event


@pytest.fixture
def test_engine():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine


def test_log_event_commits_with_engine(test_engine):
    event = log_event(
        test_engine,
        event_type='auth_login',
        actor='admin_user',
        resource_type='user',
        resource_id='admin_user',
        details={'status': 'ok'},
        ip_address='127.0.0.1',
    )
    assert event.id is not None
    assert event.event_type == 'auth_login'
    assert event.actor == 'admin_user'
    assert event.ip_address == '127.0.0.1'

    with Session(test_engine) as session:
        stored = session.get(AuditEvent, event.id)
        assert stored is not None
        assert stored.actor == 'admin_user'
        assert stored.details == {'status': 'ok'}


def test_log_event_redacts_secrets(test_engine):
    sensitive_details = {
        'password': 'SuperSecretPassword123!',
        'api_key': 'ak_live_abcdef1234567890',
        'bearer_token': 'Bearer eyJhbGciOi...',
        'safe_info': 'public_metric',
        'nested': {
            'cookie': 'session=abc12345',
            'normal_key': 42,
        },
    }
    event = log_event(
        test_engine,
        event_type='sensitive_action',
        actor='operator',
        details=sensitive_details,
    )
    assert event.details['password'] == '[REDACTED]'
    assert event.details['api_key'] == '[REDACTED]'
    assert event.details['bearer_token'] == '[REDACTED]'
    assert event.details['safe_info'] == 'public_metric'
    assert event.details['nested']['cookie'] == '[REDACTED]'
    assert event.details['nested']['normal_key'] == 42


def test_log_event_validation(test_engine):
    with pytest.raises(ValueError, match='non-empty string'):
        log_event(test_engine, event_type='')

    with pytest.raises(ValueError, match='exceeds maximum length'):
        log_event(test_engine, event_type='x' * 65)

    with pytest.raises(TypeError, match='Session or Engine'):
        log_event(None, event_type='test')


def test_query_events_filtering_and_pagination(test_engine):
    now = datetime.now(timezone.utc)
    log_event(test_engine, event_type='type_a', actor='alice', details={'k': 1})
    log_event(test_engine, event_type='type_b', actor='bob', details={'k': 2})
    log_event(test_engine, event_type='type_a', actor='charlie', details={'k': 3})

    # All events
    res = query_events(test_engine, page=1, page_size=10)
    assert res['total'] == 3
    assert len(res['items']) == 3

    # Filter by event_type
    res_type = query_events(test_engine, event_type='type_a')
    assert res_type['total'] == 2
    assert {e['actor'] for e in res_type['items']} == {'alice', 'charlie'}

    # Filter by actor
    res_actor = query_events(test_engine, actor='bob')
    assert res_actor['total'] == 1
    assert res_actor['items'][0]['event_type'] == 'type_b'

    # Pagination bounds
    with pytest.raises(ValueError):
        query_events(test_engine, page=0)
    with pytest.raises(ValueError):
        query_events(test_engine, page_size=0)
    with pytest.raises(ValueError):
        query_events(test_engine, page_size=101)


def test_serialize_audit_event():
    event = AuditEvent(
        id='test-uuid',
        event_type='scan_dispatched',
        actor='admin',
        resource_type='scan',
        resource_id='scan-123',
        details={'target': '127.0.0.1'},
        ip_address='127.0.0.1',
        created_at=datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc),
    )
    data = serialize_audit_event(event)
    assert data['id'] == 'test-uuid'
    assert data['event_type'] == 'scan_dispatched'
    assert data['created_at'].startswith('2026-10-18')


def test_audit_event_survives_session_rollback(test_engine):
    """Finding 6: Logging with an active session commits independently so rollbacks do not erase audit events."""
    with Session(test_engine) as business_session:
        event = log_event(
            business_session,
            event_type='scan_dispatched',
            actor='operator',
            resource_type='scan',
            resource_id='scan-rollback-test',
            details={'target': '127.0.0.1'},
        )
        # Business transaction encounters an error and rolls back
        business_session.rollback()

    # The audit event is preserved in the database
    with Session(test_engine) as verify_session:
        stored = verify_session.get(AuditEvent, event.id)
        assert stored is not None
        assert stored.event_type == 'scan_dispatched'
        assert stored.resource_id == 'scan-rollback-test'

