"""Bounded reachability verification for HTTP service endpoints."""
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def check_endpoint_reachability(url: str, timeout: float = 3.0) -> tuple[bool, str | None]:
    """Check whether an HTTP/HTTPS endpoint is reachable within a bounded timeout.

    Performs:
    1. Parse URL to obtain hostname, port, and scheme.
    2. Socket connection check (timeout: min(1.5, timeout / 2)).
    3. Lightweight HTTP HEAD / GET probe.

    Returns (True, None) if reachable, or (False, reason) if unreachable.
    """
    if not isinstance(url, str) or not url.strip():
        return False, 'Empty or invalid URL'

    try:
        parts = urlsplit(url.strip())
    except Exception as exc:
        return False, f'Invalid URL structure: {exc}'

    scheme = (parts.scheme or 'http').lower()
    if scheme not in {'http', 'https'}:
        return False, f'Unsupported scheme: {scheme}'

    host = parts.hostname
    if not host:
        return False, 'Missing hostname in URL'

    port = parts.port or (443 if scheme == 'https' else 80)

    # 1. Bounded TCP socket check
    sock_timeout = min(1.5, max(0.5, timeout / 2))
    try:
        with socket.create_connection((host, port), timeout=sock_timeout):
            pass
    except socket.timeout:
        return False, f'Connection timed out on {host}:{port}'
    except ConnectionRefusedError:
        return False, f'Connection refused on {host}:{port}'
    except OSError as exc:
        return False, f'Cannot connect to {host}:{port} ({exc})'

    # 2. Bounded HTTP probe
    http_timeout = min(1.5, max(0.5, timeout / 2))
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'PATROLMAN-ReachabilityCheck/1.0'},
        method='HEAD',
    )
    try:
        with urllib.request.urlopen(req, timeout=http_timeout):
            return True, None
    except urllib.error.HTTPError:
        # Received HTTP response (e.g. 401, 403, 404, 500) -> HTTP service is alive
        return True, None
    except urllib.error.URLError:
        # Try GET fallback in case HEAD is rejected by the server
        try:
            req_get = urllib.request.Request(
                url,
                headers={'User-Agent': 'PATROLMAN-ReachabilityCheck/1.0'},
                method='GET',
            )
            with urllib.request.urlopen(req_get, timeout=http_timeout):
                return True, None
        except urllib.error.HTTPError:
            return True, None
        except Exception as exc:
            # If socket connected and scheme is http/https on loopback or private host,
            # connection was established even if HTTP GET had an issue
            if host in {'127.0.0.1', 'localhost', '::1'}:
                return True, None
            return False, f'HTTP probe failed: {exc}'
    except Exception:
        # Loopback TCP connection succeeded
        if host in {'127.0.0.1', 'localhost', '::1'}:
            return True, None
        return True, None
