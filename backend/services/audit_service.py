"""Append-only audit service for security-critical actions and system operations."""
from datetime import datetime, timezone
from typing import Any, Optional, Union
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ..models import AuditEvent, now
from .results import redact

MAX_EVENT_TYPE_LENGTH = 64
MAX_ACTOR_LENGTH = 64
MAX_RESOURCE_TYPE_LENGTH = 64
MAX_RESOURCE_ID_LENGTH = 64


def log_event(
    target: Union[Engine, Session],
    event_type: str,
    actor: str = 'system',
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
    commit_with_transaction: bool = False,
) -> AuditEvent:
    """Log an append-only audit event with strict secret redaction.

    Accepts either an active SQLAlchemy Session or an Engine.
    When passed a Session, adds the AuditEvent to the session.
    When passed an Engine, opens a session and commits immediately.
    """
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError('event_type must be a non-empty string.')
    if len(event_type) > MAX_EVENT_TYPE_LENGTH:
        raise ValueError(f'event_type exceeds maximum length of {MAX_EVENT_TYPE_LENGTH}.')

    actor_str = str(actor or 'system').strip()
    if not actor_str:
        actor_str = 'system'
    if len(actor_str) > MAX_ACTOR_LENGTH:
        actor_str = actor_str[:MAX_ACTOR_LENGTH]

    safe_resource_type = str(resource_type).strip() if resource_type else None
    if safe_resource_type and len(safe_resource_type) > MAX_RESOURCE_TYPE_LENGTH:
        safe_resource_type = safe_resource_type[:MAX_RESOURCE_TYPE_LENGTH]

    safe_resource_id = str(resource_id).strip() if resource_id else None
    if safe_resource_id and len(safe_resource_id) > MAX_RESOURCE_ID_LENGTH:
        safe_resource_id = safe_resource_id[:MAX_RESOURCE_ID_LENGTH]

    safe_ip = str(ip_address).strip() if ip_address else None
    if safe_ip and len(safe_ip) > 45:
        safe_ip = safe_ip[:45]

    # Redact any passwords, tokens, cookies, or secrets from details
    safe_details = redact(details if isinstance(details, dict) else {})

    event = AuditEvent(
        id=str(uuid4()),
        event_type=event_type.strip(),
        actor=actor_str,
        resource_type=safe_resource_type,
        resource_id=safe_resource_id,
        details=safe_details,
        ip_address=safe_ip,
        created_at=now(),
    )

    if isinstance(target, Session):
        if commit_with_transaction:
            target.add(event)
        else:
            # Preserve isolated audit durability for existing non-transactional callers.
            bind = target.get_bind()
            with Session(bind, expire_on_commit=False) as audit_session:
                audit_session.add(event)
                audit_session.commit()
    elif isinstance(target, Engine):
        with Session(target, expire_on_commit=False) as session:
            session.add(event)
            session.commit()
    else:
        raise TypeError('target must be an SQLAlchemy Session or Engine.')

    return event


def serialize_audit_event(event: AuditEvent) -> dict[str, Any]:
    """Serialize an AuditEvent for API responses."""
    return {
        'id': event.id,
        'event_type': event.event_type,
        'actor': event.actor,
        'resource_type': event.resource_type,
        'resource_id': event.resource_id,
        'details': event.details or {},
        'ip_address': event.ip_address,
        'created_at': event.created_at.isoformat() if event.created_at else None,
    }


def query_events(
    engine: Engine,
    page: int = 1,
    page_size: int = 20,
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    start_date: Optional[Union[datetime, str]] = None,
    end_date: Optional[Union[datetime, str]] = None,
) -> dict[str, Any]:
    """Query audit events with filtering and pagination."""
    if page < 1:
        raise ValueError('page must be at least 1.')
    if not 1 <= page_size <= 100:
        raise ValueError('page_size must be between 1 and 100.')

    with Session(engine) as session:
        query = select(AuditEvent)

        if event_type:
            query = query.where(AuditEvent.event_type == event_type)
        if actor:
            query = query.where(AuditEvent.actor == actor)
        if resource_type:
            query = query.where(AuditEvent.resource_type == resource_type)
        if resource_id:
            query = query.where(AuditEvent.resource_id == resource_id)

        if start_date:
            if isinstance(start_date, str):
                start_date = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            if start_date.tzinfo is None:
                start_date = start_date.replace(tzinfo=timezone.utc)
            query = query.where(AuditEvent.created_at >= start_date)

        if end_date:
            if isinstance(end_date, str):
                end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if end_date.tzinfo is None:
                end_date = end_date.replace(tzinfo=timezone.utc)
            query = query.where(AuditEvent.created_at <= end_date)

        total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = session.scalars(
            query.order_by(AuditEvent.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()

        return {
            'items': [serialize_audit_event(item) for item in items],
            'total': total,
            'page': page,
            'page_size': page_size,
        }
