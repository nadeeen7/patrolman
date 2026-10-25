"""Exact-host scope checks. Does not authorize a scanner to resolve hosts again."""
import ipaddress
import re
import socket
import json
import sys
from .process_runner import run
from dataclasses import dataclass


class TargetError(ValueError):
    pass


class ScopeError(TargetError):
    pass


def normalize_target(value):
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 253:
        raise TargetError('Supply a domain or IP address without whitespace.')
    if '%' in value:
        raise TargetError('IPv6 zone identifiers are unsupported.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if any(c in value for c in '/:@\\?#'):
        raise TargetError('Use a hostname or IP only; URLs and ports are unsupported.')
    try:
        host = value.removesuffix('.').encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise TargetError('Invalid internationalized hostname.') from exc
    if not host or len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
        raise TargetError('Invalid hostname.')
    # Reject alternate numerical address spellings accepted by some resolvers.
    if re.fullmatch(r'[0-9.]+', host) or any(label.startswith('0x') for label in host.split('.')):
        raise TargetError('Use a canonical IP address.')
    return host


def normalize_scope_asset(value):
    """Normalize an exact host/IP or a canonical IPv4/IPv6 network.

    Rejects URLs, service endpoints with ports, and noncanonical CIDRs.
    """
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 253:
        raise TargetError('Supply a domain, IP address, or CIDR network without whitespace.')
    if '%' in value:
        raise TargetError('IPv6 zone identifiers are unsupported.')
    clean = value.strip()

    # Reject URLs, schemes, paths, and query/fragment components in scope fields
    if clean.startswith(('http://', 'https://')) or '://' in clean or any(c in clean for c in '?#@'):
        raise TargetError(
            'Scope entries must be a bare hostname, IP address, or canonical CIDR network; '
            'URLs and paths are unsupported in scope definitions.'
        )

    # If it contains a slash, it must be an IPv4/IPv6 CIDR network
    if '/' in clean:
        if clean.startswith('/') or clean.count('/') > 1 or '\\' in clean:
            raise TargetError(
                'Scope entries must be a bare hostname, IP address, or canonical CIDR network; '
                'paths are unsupported in scope definitions.'
            )
        try:
            network = ipaddress.ip_network(clean, strict=True)
        except ValueError as exc:
            raise TargetError('CIDR scope entries must be canonical IPv4 or IPv6 networks.') from exc
        return str(network)

    # If it contains a colon, it could be an IPv6 address or an unsupported port
    if ':' in clean:
        try:
            ip = ipaddress.ip_address(clean)
            return str(ip)
        except ValueError:
            raise TargetError(
                'Scope entries must be a bare hostname, IP address, or canonical CIDR network; '
                'ports are unsupported in scope definitions.'
            )

    return normalize_target(clean)


@dataclass(frozen=True)
class TargetEndpoint:
    host: str
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    canonical_endpoint: str = ''


def parse_target_endpoint(value: str) -> TargetEndpoint:
    """Parse and normalize an assessment target into its host, scheme, port, and canonical endpoint.

    Accepts:
    - Bare hostname or IP address (e.g. '127.0.0.1', 'example.com', '::1')
    - Single-host CIDR network (e.g. '127.0.0.1/32', '::1/128')
    - Host with explicit port (e.g. '127.0.0.1:3000', 'example.com:8080')
    - Full HTTP/HTTPS service URL (e.g. 'http://127.0.0.1:3000', 'https://example.com:8443/juice')
    """
    from urllib.parse import urlsplit

    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 2048:
        raise TargetError('Supply a valid target hostname, IP address, or service endpoint.')
    if any(ord(c) < 0x21 or ord(c) == 0x7f for c in value):
        raise TargetError('Target contains control or whitespace characters.')
    if any(c in value for c in ';$`&|<>\\"\'*'):
        raise TargetError('Target contains invalid or unsafe characters.')

    clean = value.strip()

    # Case 1: Single-host CIDR entry (e.g. 127.0.0.1/32 or ::1/128)
    if '/' in clean and '://' not in clean and not clean.startswith('/'):
        try:
            network = ipaddress.ip_network(clean, strict=True)
        except ValueError as exc:
            raise TargetError('CIDR scope entries must be canonical IPv4 or IPv6 networks.') from exc
        if network.num_addresses == 1:
            host = normalize_target(str(network.network_address))
            return TargetEndpoint(host=host, scheme=None, port=None, path=None, canonical_endpoint=host)
        raise TargetError('Scan target must be a specific host, IP address, or service endpoint, not a subnet range.')

    # Case 2: Full web service URL
    if '://' in clean:
        try:
            parts = urlsplit(clean)
        except Exception as exc:
            raise TargetError('Invalid service endpoint URL.') from exc
        scheme = (parts.scheme or '').lower()
        if scheme not in {'http', 'https'}:
            raise TargetError('Only HTTP and HTTPS service endpoints are supported.')
        if parts.username or parts.password:
            raise TargetError('Credential-bearing target URLs are prohibited.')
        if parts.fragment:
            raise TargetError('Target URLs must not contain fragment identifiers.')
        if parts.query:
            raise TargetError('Target URLs must not contain query parameters.')
        if not parts.hostname:
            raise TargetError('Target URL must include a valid hostname or IP address.')
        host = normalize_target(parts.hostname)
        port = parts.port
        if port is not None:
            if not 1 <= port <= 65535:
                raise TargetError('Invalid port number in target URL.')
        else:
            port = 443 if scheme == 'https' else 80

        raw_path = parts.path or ''
        if raw_path and raw_path != '/':
            segments = raw_path.split('/')
            if any(seg == '..' for seg in segments):
                raise TargetError('Path traversal sequences are prohibited in target URLs.')
            path = '/' + raw_path.strip('/')
        else:
            path = ''

        netloc_host = f'[{host}]' if ':' in host else host
        is_default_port = (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)
        if parts.port is not None and not is_default_port:
            canonical_endpoint = f'{scheme}://{netloc_host}:{port}{path}'
        elif parts.port is not None:
            canonical_endpoint = f'{scheme}://{netloc_host}:{port}{path}'
        else:
            canonical_endpoint = f'{scheme}://{netloc_host}{path}'

        return TargetEndpoint(
            host=host,
            scheme=scheme,
            port=port,
            path=path,
            canonical_endpoint=canonical_endpoint,
        )

    # Case 3: Host with explicit port, e.g. 127.0.0.1:3000 or example.com:8080 or [::1]:3000
    if ':' in clean:
        # Check if it's a bare IPv6 address without port
        try:
            ip = ipaddress.ip_address(clean)
            host = normalize_target(str(ip))
            return TargetEndpoint(host=host, scheme=None, port=None, path=None, canonical_endpoint=host)
        except ValueError:
            pass

        # Try host:port
        try:
            from urllib.parse import urlsplit
            parts = urlsplit('//' + clean)
            if parts.port is not None and parts.hostname:
                host = normalize_target(parts.hostname)
                port = parts.port
                if not 1 <= port <= 65535:
                    raise TargetError('Invalid port number in target.')
                scheme = 'https' if port in {443, 8443} else 'http'
                netloc_host = f'[{host}]' if ':' in host else host
                canonical_endpoint = f'{scheme}://{netloc_host}:{port}'
                return TargetEndpoint(
                    host=host,
                    scheme=scheme,
                    port=port,
                    path='',
                    canonical_endpoint=canonical_endpoint,
                )
        except TargetError:
            raise
        except Exception:
            pass

    # Case 4: Bare hostname or IP address
    host = normalize_target(clean)
    return TargetEndpoint(host=host, scheme=None, port=None, path=None, canonical_endpoint=host)


@dataclass(frozen=True)
class ValidatedTarget:
    host: str
    addresses: tuple[str, ...]
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    canonical_endpoint: str | None = None


def resolve_addresses(host):
    script = 'import socket,json,sys;print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))'
    result = run([sys.executable, '-c', script, host], timeout=5, max_output=16384)
    if result.state != 'completed':
        raise OSError('DNS resolution failed or timed out')
    return tuple(json.loads(result.stdout))


def validate_target(value, allowed_targets, allow_private=False, resolver=resolve_addresses):
    endpoint = parse_target_endpoint(value)
    host = endpoint.host

    # Match host against allowed_targets (supporting exact hosts and canonical CIDRs)
    allowed_hosts = set()
    allowed_cidrs = []
    for item in allowed_targets:
        try:
            norm_asset = normalize_scope_asset(str(item).strip())
            if '/' in norm_asset:
                allowed_cidrs.append(ipaddress.ip_network(norm_asset))
            else:
                allowed_hosts.add(norm_asset)
        except TargetError:
            continue

    is_allowed = host in allowed_hosts
    if not is_allowed and allowed_cidrs:
        try:
            addr = ipaddress.ip_address(host)
            is_allowed = any(addr in net for net in allowed_cidrs)
        except ValueError:
            pass

    if not is_allowed:
        raise ScopeError('Target is not in the administrator-configured exact-host allowlist.')

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    try:
        addresses = (str(literal),) if literal else tuple(resolver(host))
        parsed = tuple(ipaddress.ip_address(address) for address in addresses)
    except (OSError, ValueError) as exc:
        raise TargetError('Target resolution failed.') from exc
    if not parsed:
        raise TargetError('Target has no resolved addresses.')
    for address in parsed:
        effective = getattr(address, 'ipv4_mapped', None) or address
        if effective.is_multicast or effective.is_unspecified or effective.is_link_local:
            raise ScopeError('Multicast, unspecified, and link-local addresses are prohibited.')
        if not effective.is_global and not allow_private:
            raise ScopeError('Non-public addresses require explicit local lab configuration.')
    return ValidatedTarget(
        host=host,
        addresses=tuple(sorted({str(address) for address in parsed})),
        scheme=endpoint.scheme,
        port=endpoint.port,
        path=endpoint.path,
        canonical_endpoint=endpoint.canonical_endpoint,
    )

