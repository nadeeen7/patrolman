"""Phase 2 tests: Automatic Scope Validator.

Covers all 16 cases from the implementation plan. Tests are fully
self-contained via SQLAlchemy in-memory SQLite sessions so no real
database or network is touched.
"""
import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.models import AuthorizedTarget, TargetAuditEvent, Base
from backend.services.scope_validator import (
    ScopeAuthorizationError,
    TOOL_METHOD_MAP,
    check_host_in_scope,
    check_destination_excluded,
    check_methods_permitted,
    find_authorizing_target,
    recheck_authorized_target,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc(**kwargs):
    return datetime.now(timezone.utc) + timedelta(**kwargs)


def _engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine


def _target(session, *, name="Test Target", domains=("example.com",), subdomains=(),
            excluded=None, status="active", valid_from=None, valid_to=None,
            permitted=None, prohibited=None, rate_limit_rps=10):
    """Create and persist a minimal AuthorizedTarget."""
    t = AuthorizedTarget(
        name=name,
        target_type="organization",
        owner_organization="Test Org",
        scope_domains=list(domains),
        explicit_subdomains=list(subdomains),
        excluded_scope=list(excluded) if excluded is not None else [],
        permitted_methods=permitted if permitted is not None else [
            "port_scan", "web_service_discovery", "tls_audit", "vulnerability_check"
        ],
        prohibited_methods=prohibited if prohibited is not None else [
            "dos", "exploit", "credential_attack", "active_crawl"
        ],
        rate_limit_rps=rate_limit_rps,
        valid_from=valid_from or _utc(days=-30),
        valid_to=valid_to or _utc(days=30),
        evidence_reference="REF-001",
        status=status,
        created_by="test",
        updated_by="test",
    )
    session.add(t)
    session.flush()
    return t


# ---------------------------------------------------------------------------
# check_host_in_scope tests
# ---------------------------------------------------------------------------

class TestCheckHostInScope:
    def setup_method(self):
        self.engine = _engine()

    def teardown_method(self):
        self.engine.dispose()

    def test_host_exact_match_in_scope_domains(self):
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com",))
            assert check_host_in_scope("example.com", t) is True

    def test_host_exact_match_in_explicit_subdomains(self):
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com",), subdomains=("sub.example.com",))
            assert check_host_in_scope("sub.example.com", t) is True

    def test_host_parent_domain_does_not_cover_subdomain(self):
        """Parent-domain entries do NOT implicitly cover subdomains."""
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com",))
            assert check_host_in_scope("sub.example.com", t) is False

    def test_host_not_in_scope(self):
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com",))
            assert check_host_in_scope("other.com", t) is False

    def test_ip_exact_match(self):
        """Private IP in scope_domains matches exactly — scope_validator does not
        restrict IP ranges; that is the responsibility of target_validation."""
        with Session(self.engine) as session:
            t = _target(session, domains=("192.168.1.1",))
            assert check_host_in_scope("192.168.1.1", t) is True


    def test_ip_exact_match_public(self):
        with Session(self.engine) as session:
            t = _target(session, domains=("8.8.8.8",))
            assert check_host_in_scope("8.8.8.8", t) is True

    @pytest.mark.parametrize(("network", "inside", "outside"), [
        ("192.168.10.0/24", "192.168.10.255", "192.168.11.0"),
        ("2001:db8:1234::/48", "2001:db8:1234:ffff::1", "2001:db8:1235::1"),
    ])
    def test_cidr_matches_only_network_members(self, network, inside, outside):
        with Session(self.engine) as session:
            t = _target(session, domains=(network,))
            assert check_host_in_scope(inside, t) is True
            assert check_host_in_scope(outside, t) is False

    def test_cidr_exclusion_takes_precedence_over_inclusion(self):
        with Session(self.engine) as session:
            t = _target(
                session,
                domains=("192.168.0.0/16",),
                excluded=("192.168.10.0/24",),
            )
            assert check_host_in_scope("192.168.9.5", t) is True
            assert check_host_in_scope("192.168.10.5", t) is False

    def test_domain_entry_does_not_cover_resolved_ip(self):
        """A domain in scope_domains does not authorize its resolved IP."""
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com",))
            assert check_host_in_scope("93.184.216.34", t) is False

    def test_excluded_host_rejected(self):
        """Host matching excluded_scope is rejected even if in scope_domains."""
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com", "internal.example.com"),
                        excluded=("internal.example.com",))
            assert check_host_in_scope("example.com", t) is True
            assert check_host_in_scope("internal.example.com", t) is False

    def test_excluded_subdomain_rejected(self):
        """Subdomain matching excluded_scope is rejected even if in explicit_subdomains."""
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com",), subdomains=("api.example.com", "dev.example.com"),
                        excluded=("dev.example.com",))
            assert check_host_in_scope("api.example.com", t) is True
            assert check_host_in_scope("dev.example.com", t) is False

    def test_check_destination_excluded_path_boundary(self):
        """Safe path boundary: /admin matches /admin, /admin/, /admin/billing, but not /administrator."""
        with Session(self.engine) as session:
            t = _target(session, domains=("example.com",), excluded=("/admin", "192.168.1.99"))
            assert check_destination_excluded("http://example.com/admin", t) is not None
            assert check_destination_excluded("http://example.com/admin/", t) is not None
            assert check_destination_excluded("http://example.com/admin/billing", t) is not None
            assert check_destination_excluded("http://example.com/administrator", t) is None
            assert check_destination_excluded("http://example.com/api", t) is None
            assert check_destination_excluded("http://192.168.1.99/any", t) is not None


# ---------------------------------------------------------------------------
# check_methods_permitted tests
# ---------------------------------------------------------------------------

class TestCheckMethodsPermitted:
    def setup_method(self):
        self.engine = _engine()

    def teardown_method(self):
        self.engine.dispose()

    def test_all_tools_permitted(self):
        with Session(self.engine) as session:
            t = _target(session, permitted=["port_scan", "web_service_discovery",
                                            "tls_audit", "vulnerability_check"],
                        prohibited=["dos", "active_crawl"])
            result = check_methods_permitted(["nmap", "httpx", "sslyze", "nuclei"], t)
            assert result is None

    def test_prohibited_method_blocked(self):
        with Session(self.engine) as session:
            t = _target(session, prohibited=["active_crawl"])
            # nmap maps to port_scan only, so an active_crawl prohibition is irrelevant.
            result = check_methods_permitted(["nmap"], t)
            assert result is None

    def test_tool_in_prohibited_category_blocked(self):
        """gitleaks maps to local_scan; if local_scan is prohibited, gitleaks blocked."""
        with Session(self.engine) as session:
            t = _target(session, prohibited=["local_scan"])
            result = check_methods_permitted(["gitleaks"], t)
            assert result is not None
            assert "gitleaks" in result

    def test_tool_not_in_permitted_list_blocked(self):
        """When permitted_methods is non-empty, tools must map to it."""
        with Session(self.engine) as session:
            t = _target(session, permitted=["port_scan"], prohibited=[])
            result = check_methods_permitted(["nuclei"], t)
            assert result is not None
            assert "nuclei" in result

    def test_empty_permitted_methods_allows_all(self):
        """Empty permitted_methods means no restriction (only prohibited is enforced)."""
        with Session(self.engine) as session:
            t = _target(session, permitted=[], prohibited=[])
            result = check_methods_permitted(["nmap", "nuclei", "sslyze"], t)
            assert result is None

    def test_unknown_tool_passes_through(self):
        """Unknown tools cannot establish authorization."""
        with Session(self.engine) as session:
            t = _target(session, permitted=["port_scan"], prohibited=[])
            result = check_methods_permitted(["unknown_future_tool"], t)
            assert result is not None
            assert "no authorization method mapping" in result


# ---------------------------------------------------------------------------
# find_authorizing_target tests
# ---------------------------------------------------------------------------

class TestFindAuthorizingTarget:
    def setup_method(self):
        self.engine = _engine()

    def teardown_method(self):
        self.engine.dispose()

    def test_basic_authorized_match(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",))
            session.commit()
        with Session(self.engine) as session:
            result = find_authorizing_target("example.com", ["nmap"], session)
            assert result is not None
            assert result.name == "Test Target"

    def test_host_not_in_scope_raises(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",))
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="not listed"):
                find_authorizing_target("other.com", ["nmap"], session)

    def test_expired_target_rejected(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",),
                    valid_from=_utc(days=-60), valid_to=_utc(days=-1))
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="none are currently active"):
                find_authorizing_target("example.com", ["nmap"], session)

    def test_revoked_target_rejected(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",), status="revoked")
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="none are currently active"):
                find_authorizing_target("example.com", ["nmap"], session)

    def test_inactive_target_rejected(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",), status="inactive")
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="none are currently active"):
                find_authorizing_target("example.com", ["nmap"], session)

    def test_no_targets_in_db_permissive_returns_none(self):
        with Session(self.engine) as session:
            result = find_authorizing_target("example.com", ["nmap"], session, require=False)
            assert result is None

    def test_no_targets_in_db_strict_raises(self):
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="No authorized targets"):
                find_authorizing_target("example.com", ["nmap"], session, require=True)

    def test_multiple_targets_first_revoked_second_active_returns_active(self):
        with Session(self.engine) as session:
            _target(session, name="Revoked", domains=("example.com",), status="revoked")
            _target(session, name="Active", domains=("example.com",), status="active")
            session.commit()
        with Session(self.engine) as session:
            result = find_authorizing_target("example.com", ["nmap"], session)
            assert result.name == "Active"

    def test_conflicting_active_target_policy_denies_even_if_another_allows(self):
        with Session(self.engine) as session:
            _target(session, name="Permissive", domains=("example.com",))
            _target(
                session,
                name="Restrictive",
                domains=("example.com",),
                prohibited=["port_scan"],
            )
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="every active authorization"):
                find_authorizing_target("example.com", ["nmap"], session)

    def test_recheck_rejects_scope_or_method_change(self):
        with Session(self.engine) as session:
            target = _target(session, domains=("example.com",), permitted=["port_scan"])
            session.commit()
            target_id = target.id
        with Session(self.engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            target.scope_domains = ["other.example"]
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="no longer in scope"):
                recheck_authorized_target(target_id, session, "example.com", ["nmap"])
        with Session(self.engine) as session:
            target = session.get(AuthorizedTarget, target_id)
            target.scope_domains = ["example.com"]
            target.permitted_methods = ["tls_audit"]
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="permitted methods"):
                recheck_authorized_target(target_id, session, "example.com", ["nmap"])

    def test_prohibited_tool_rejected(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",), prohibited=["local_scan"])
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="not permitted"):
                find_authorizing_target("example.com", ["gitleaks"], session)

    def test_parent_domain_does_not_implicitly_cover_subdomain(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",))
            session.commit()
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="not listed"):
                find_authorizing_target("sub.example.com", ["nmap"], session)

    def test_explicit_subdomain_is_covered(self):
        with Session(self.engine) as session:
            _target(session, domains=("example.com",), subdomains=("api.example.com",))
            session.commit()
        with Session(self.engine) as session:
            result = find_authorizing_target("api.example.com", ["nmap"], session)
            assert result is not None


# ---------------------------------------------------------------------------
# recheck_authorized_target tests
# ---------------------------------------------------------------------------

class TestRecheckAuthorizedTarget:
    def setup_method(self):
        self.engine = _engine()

    def teardown_method(self):
        self.engine.dispose()

    def test_recheck_active_target_passes(self):
        with Session(self.engine) as session:
            t = _target(session)
            session.commit()
            target_id = t.id
        with Session(self.engine) as session:
            recheck_authorized_target(target_id, session)  # must not raise

    def test_recheck_revoked_target_raises(self):
        with Session(self.engine) as session:
            t = _target(session, status="revoked")
            session.commit()
            target_id = t.id
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="revoked"):
                recheck_authorized_target(target_id, session)

    def test_recheck_missing_target_raises(self):
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="no longer exists"):
                recheck_authorized_target("nonexistent-id-0000", session)

    def test_recheck_expired_target_raises(self):
        with Session(self.engine) as session:
            t = _target(session, valid_from=_utc(days=-60), valid_to=_utc(days=-1))
            session.commit()
            target_id = t.id
        with Session(self.engine) as session:
            with pytest.raises(ScopeAuthorizationError, match="expired"):
                recheck_authorized_target(target_id, session)


# ---------------------------------------------------------------------------
# TOOL_METHOD_MAP completeness tests
# ---------------------------------------------------------------------------

class TestToolMethodMap:
    def test_all_expected_tools_mapped(self):
        expected_tools = {
            'nmap', 'httpx', 'whatweb', 'subfinder',
            'sslyze', 'nuclei', 'wapiti', 'gitleaks', 'trivy',
        }
        assert expected_tools == set(TOOL_METHOD_MAP.keys())

    def test_wapiti_requires_vulnerability_check_and_respects_active_crawl(self):
        """Wapiti attacks the target, so an active_crawl prohibition blocks it."""
        assert 'vulnerability_check' in TOOL_METHOD_MAP['wapiti']
        assert 'active_crawl' in TOOL_METHOD_MAP['wapiti']
        blocked = AuthorizedTarget(
            name='Wapiti Target', scope_domains=['127.0.0.1'], explicit_subdomains=[],
            excluded_scope=[], permitted_methods=['vulnerability_check'],
            prohibited_methods=['active_crawl'],
        )
        assert check_methods_permitted(['wapiti'], blocked) is not None
        allowed = AuthorizedTarget(
            name='Wapiti Target', scope_domains=['127.0.0.1'], explicit_subdomains=[],
            excluded_scope=[], permitted_methods=['vulnerability_check'], prohibited_methods=[],
        )
        assert check_methods_permitted(['wapiti'], allowed) is None
