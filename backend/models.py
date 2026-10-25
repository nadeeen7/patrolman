"""Initial schema. A migration is required before future schema changes."""
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Boolean, JSON, DateTime, ForeignKey, Index, Integer, String, Text, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session


def now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = 'scans'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target: Mapped[str] = mapped_column(String(253), index=True)
    profile: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(32), default='queued', index=True)
    configuration: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    assets: Mapped[list['Asset']] = relationship(cascade='all, delete-orphan')
    executions: Mapped[list['ToolExecution']] = relationship(cascade='all, delete-orphan')
    findings: Mapped[list['Finding']] = relationship(cascade='all, delete-orphan')
    evidence: Mapped[list['Evidence']] = relationship(passive_deletes=True)


class Asset(Base):
    __tablename__ = 'assets'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id', ondelete='CASCADE'), index=True)
    address: Mapped[str] = mapped_column(String(2048))
    kind: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class ToolExecution(Base):
    __tablename__ = 'tool_executions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id', ondelete='CASCADE'), index=True)
    tool: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(32), default='queued')
    exit_code: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = 'findings'
    __table_args__ = (Index('ix_finding_scan_fingerprint', 'scan_id', 'fingerprint', unique=True),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id', ondelete='CASCADE'), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default='unknown', index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanRequest(Base):
    """Idempotency keys persist across restarts; request hash prevents key reuse."""
    __tablename__ = 'scan_requests'
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id', ondelete='CASCADE'), unique=True)


class AdminAccount(Base):
    """A local administrator account created by first-run setup or registration."""
    __tablename__ = 'admin_accounts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AdminSession(Base):
    """Opaque server-side session; only a hash of the browser bearer is persisted."""
    __tablename__ = 'admin_sessions'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64))
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    # Idle-expiration marker for the server-side session. Added additively by
    # backend.auth.create_auth_tables; existing sessions without a value fall
    # back to created_at.
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LoginThrottle(Base):
    """Persistent per-client and per-account throttling for login and registration."""
    __tablename__ = 'login_throttles'
    client_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuthorizedTarget(Base):
    """Authorized target entity with documented permissions, scope restrictions, and audit trail."""
    __tablename__ = 'authorized_targets'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str] = mapped_column(String(32), index=True)  # organization, client, bug_bounty, lab
    owner_organization: Mapped[str] = mapped_column(String(255))
    scope_domains: Mapped[list] = mapped_column(JSON, default=list)  # in-scope hostnames and canonical IPs
    explicit_subdomains: Mapped[list] = mapped_column(JSON, default=list)  # explicitly authorized subdomains
    excluded_scope: Mapped[list] = mapped_column(JSON, default=list)  # excluded hosts, paths, IPs, or services
    permitted_methods: Mapped[list] = mapped_column(JSON, default=list)
    prohibited_methods: Mapped[list] = mapped_column(JSON, default=list)
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=10)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    evidence_reference: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default='active', index=True)  # active, inactive, revoked, pending_approval
    created_by: Mapped[str] = mapped_column(String(64))
    updated_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    audit_events: Mapped[list['TargetAuditEvent']] = relationship(cascade='all, delete-orphan', back_populates='target', order_by='TargetAuditEvent.created_at.desc()')
    scope_imports: Mapped[list['ScopeImportSnapshot']] = relationship(
        cascade='all, delete-orphan', back_populates='target',
        order_by='ScopeImportSnapshot.imported_at.desc()',
    )


class ScopeImportSnapshot(Base):
    """Provider-neutral, reviewable offline import of program scope."""
    __tablename__ = 'scope_import_snapshots'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_id: Mapped[str] = mapped_column(ForeignKey('authorized_targets.id', ondelete='CASCADE'), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    program_id: Mapped[str] = mapped_column(String(255))
    source_url: Mapped[str] = mapped_column(Text)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    last_successful_validation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    snapshot_version: Mapped[str] = mapped_column(String(128))
    digest: Mapped[str] = mapped_column(String(64), index=True)
    included_assets: Mapped[list] = mapped_column(JSON, default=list)
    excluded_assets: Mapped[list] = mapped_column(JSON, default=list)
    permitted_methods: Mapped[list] = mapped_column(JSON, default=list)
    prohibited_methods: Mapped[list] = mapped_column(JSON, default=list)
    restrictions: Mapped[list] = mapped_column(JSON, default=list)
    invalid_entries: Mapped[list] = mapped_column(JSON, default=list)
    scope_diff: Mapped[dict] = mapped_column(JSON, default=dict)
    approved_target_state: Mapped[dict] = mapped_column(JSON, default=dict)
    import_status: Mapped[str] = mapped_column(String(32), default='valid', index=True)
    approval_status: Mapped[str] = mapped_column(String(32), default='pending_review', index=True)
    approved_by: Mapped[str | None] = mapped_column(String(64))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    target: Mapped['AuthorizedTarget'] = relationship(back_populates='scope_imports')


class TargetAuditEvent(Base):
    """Immutable audit trail for authorization changes, scope edits, and status revocations."""
    __tablename__ = 'target_audit_events'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey('authorized_targets.id', ondelete='CASCADE'), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)  # created, updated, deactivated, revoked
    actor: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    target: Mapped['AuthorizedTarget'] = relationship(back_populates='audit_events')


class AuditEvent(Base):
    """Append-only audit trail for security-critical actions, scans, authentication, and system operations."""
    __tablename__ = 'audit_events'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class Evidence(Base):
    """Cryptographically verifiable evidence items linked to scans, executions, or findings."""
    __tablename__ = 'evidence'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str | None] = mapped_column(ForeignKey('scans.id', ondelete='SET NULL'), nullable=True, index=True)
    archived_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey('findings.id', ondelete='SET NULL'), nullable=True, index=True)
    execution_id: Mapped[int | None] = mapped_column(ForeignKey('tool_executions.id', ondelete='SET NULL'), nullable=True, index=True)
    tool: Mapped[str] = mapped_column(String(32), index=True)
    evidence_type: Mapped[str] = mapped_column(String(64), index=True)
    file_path: Mapped[str] = mapped_column(String(512))
    file_size: Mapped[int] = mapped_column(Integer)
    sha256_hash: Mapped[str] = mapped_column(String(64))
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class ToolVerification(Base):
    """Durable tool verification state persisting across backend restarts."""
    __tablename__ = 'tool_verifications'
    tool: Mapped[str] = mapped_column(String(32), primary_key=True)
    verified_version: Mapped[str] = mapped_column(String(255))
    verification_status: Mapped[str] = mapped_column(String(32), default='verified', index=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    executable_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_execution_id: Mapped[int | None] = mapped_column(ForeignKey('tool_executions.id', ondelete='SET NULL'), nullable=True)
    evidence_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    record_version: Mapped[int] = mapped_column(Integer, default=1)


def migrate_schema(engine):
    """Safely apply additive migrations without rewriting or losing data."""
    with engine.begin() as conn:
        scan_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(scans)"))}
        if 'created_by' not in scan_cols:
            conn.execute(text("ALTER TABLE scans ADD COLUMN created_by VARCHAR(64)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_created_by ON scans (created_by)"))

        ev_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(evidence)"))}
        if 'created_by' not in ev_cols:
            conn.execute(text("ALTER TABLE evidence ADD COLUMN created_by VARCHAR(64)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_created_by ON evidence (created_by)"))

    # Backfill legacy scans and evidence with reliable ownership attribution
    with Session(engine) as session:
        legacy_scans = session.scalars(select(Scan).where(Scan.created_by.is_(None))).all()
        if legacy_scans:
            scan_actor_map = {}
            try:
                target_events = session.execute(
                    select(TargetAuditEvent.actor, TargetAuditEvent.details)
                    .where(TargetAuditEvent.event_type == 'scan_dispatched')
                ).all()
                for actor, details in target_events:
                    if isinstance(details, dict) and details.get('scan_id'):
                        scan_actor_map[details['scan_id']] = actor
            except Exception:
                pass

            try:
                audit_records = session.execute(
                    select(AuditEvent.actor, AuditEvent.resource_id)
                    .where(AuditEvent.resource_type == 'scan', AuditEvent.actor.notin_(['worker', 'unknown', 'system']))
                ).all()
                for actor, res_id in audit_records:
                    if res_id and res_id not in scan_actor_map:
                        scan_actor_map[res_id] = actor
            except Exception:
                pass

            try:
                default_admin = session.scalar(select(AdminAccount.username).order_by(AdminAccount.id.asc()).limit(1)) or 'tester'
            except Exception:
                default_admin = 'tester'

            for scan in legacy_scans:
                scan.created_by = scan_actor_map.get(scan.id, default_admin)

            session.commit()

        # Attribute unassigned evidence items to the owning scan's creator
        legacy_ev = session.scalars(select(Evidence).where(Evidence.created_by.is_(None))).all()
        if legacy_ev:
            for ev in legacy_ev:
                scan_id = ev.scan_id or ev.archived_scan_id
                if scan_id:
                    scan = session.get(Scan, scan_id)
                    ev.created_by = scan.created_by if scan and scan.created_by else 'tester'
                else:
                    ev.created_by = 'tester'
            session.commit()


