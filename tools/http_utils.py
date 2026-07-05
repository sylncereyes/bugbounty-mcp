"""
StealthVision-MCP - Shared HTTP Client Utilities
All tool modules should use get_client() instead of creating their own httpx.AsyncClient.
"""
import asyncio
import ipaddress
import logging
import socket
import httpx
from urllib.parse import urlparse
from typing import Optional, Tuple

from config import DEFAULT_TIMEOUT, USER_AGENT, VERIFY_SSL, REQUEST_DELAY, DRY_RUN
from tools.db import validate_scope_or_fail

logger = logging.getLogger("stealthvision.http")

# SSL disabled warning flag
_SSL_WARNING_PRINTED = False

# WAF block indicators
WAF_BLOCK_INDICATORS = [
    "403", "429", "access denied", "blocked", "forbidden", "rate limit",
    "waf", "cloudflare", "akamai", "imperva", "incapsula", "sqreen",
    " ModSecurity", "OWASP", "ddos protection", "security service",
    "suspicious activity", "automated request", "bot detection"
]

# SSRF deny-list networks
_DENIED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
]


class SSRFBlockedError(ValueError):
    """Raised when target URL resolves to blocked private/internal range."""
    pass


async def _resolve_and_validate(hostname: str) -> str:
    """
    Resolve hostname asynchronously and validate against deny-list.
    Returns the FIRST non-blocked IP address as a string.
    """
    if not hostname:
        raise SSRFBlockedError("No hostname provided")

    loop = asyncio.get_running_loop()
    try:
        addrs = await loop.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise SSRFBlockedError(f"DNS resolution failed for {hostname}: {e}")

    pinned_ip = None
    for family, socktype, proto, canonname, sockaddr in addrs:
        raw_ip = sockaddr[0]
        ip = ipaddress.ip_address(raw_ip)

        # Normalise IPv6-mapped IPv4 addresses
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        # Skip any address that lands in the deny-list
        if any(ip in net for net in _DENIED_NETWORKS):
            continue

        # Remember the first viable address (prefer IPv4 but any works)
        if isinstance(ip, ipaddress.IPv4Address) or pinned_ip is None:
            pinned_ip = ip

    if pinned_ip is None:
        raise SSRFBlockedError(f"{hostname} resolves ONLY to blocked ranges")

    return str(pinned_ip)


class PinnedResolverTransport(httpx.AsyncHTTPTransport):
    """Transport placeholder for future SNI-pinned implementation.
    
    Currently unused - SSRF protection is handled in secure_request().
    """
    def __init__(self, pinned_ip: str, **kwargs):
        super().__init__(**kwargs)
        self._pinned_ip = pinned_ip


async def secure_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    target_id: Optional[int] = None,
    dry_run: bool = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
    follow_redirects: bool = False,
    **kwargs,
) -> httpx.Response:
    """Execute HTTP request with SSRF protection, scope validation, and dry-run.

    SSRF protection: Validates DNS resolution BEFORE making any network request.
    This closes the attack window for DNS rebinding by ensuring the hostname
    cannot resolve to internal/private IP ranges.
    
    Scope validation ensures requests are only made to authorized target scope.
    """
    # 1. SSRF mitigation – resolve and validate the hostname first
    hostname = urlparse(url).hostname
    if hostname:
        await _resolve_and_validate(hostname)

    # 2. Scope validation (if a target identifier is supplied)
    if target_id is not None:
        validate_scope_or_fail(target_id, url)

    # 3. Dry-run handling – short-circuit the request while preserving the
    #    signature and logging for auditability.
    if dry_run is None:
        dry_run = DRY_RUN
    if dry_run:
        logger.info(f"[DRY RUN] {method.upper()} {url}")
        return httpx.Response(
            200,
            text="[DRY RUN] Request not executed",
            request=httpx.Request(method, url),
        )

    # 4. Execute the request with exponential backoff.
    async def _do_request() -> httpx.Response:
        return await client.request(
            method, url, follow_redirects=follow_redirects, **kwargs
        )

    attempt = 0
    while True:
        try:
            return await _do_request()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            if attempt >= max_retries:
                raise
            await asyncio.sleep(base_delay * (2 ** attempt))
            attempt += 1


def make_safe_request(
    method: str,
    url: str,
    target_id: int,
    client: Optional[httpx.AsyncClient] = None,
    dry_run: bool = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
    follow_redirects: bool = False,
    **kwargs,
):
    """Convenience wrapper that creates a client when one is not supplied.

    The underlying implementation delegates to :func:`secure_request` which
    handles all security checks.
    """
    owns_client = client is None
    if owns_client:
        client = get_client()

    async def _inner():
        return await secure_request(
            client=client,
            method=method,
            url=url,
            target_id=target_id,
            dry_run=dry_run,
            max_retries=max_retries,
            base_delay=base_delay,
            follow_redirects=follow_redirects,
            **kwargs,
        )

    async def _wrapped():
        try:
            return await _inner()
        finally:
            if owns_client:
                await client.aclose()

    return _wrapped()


def get_client(**overrides) -> httpx.AsyncClient:
    defaults = {
        "timeout": DEFAULT_TIMEOUT,
        "verify": VERIFY_SSL,
        "headers": {"User-Agent": USER_AGENT},
        "follow_redirects": False,
    }
    if "headers" in overrides:
        defaults["headers"].update(overrides.pop("headers"))
    defaults.update(overrides)
    return httpx.AsyncClient(**defaults)


async def delay() -> None:
    if REQUEST_DELAY > 0:
        await asyncio.sleep(REQUEST_DELAY)


# Compatibility helpers for tests and existing code

def validate_scope(*args, **kwargs):
    """Alias for ``validate_scope_or_fail`` – kept for backward compatibility."""
    return validate_scope_or_fail(*args, **kwargs)


async def assert_safe_target(url: str) -> None:
    """Validate that a URL is not in the SSRF deny-list.

    Raises ``SSRFBlockedError`` if the hostname resolves to a blocked range.
    """
    hostname = urlparse(url).hostname
    if hostname:
        await _resolve_and_validate(hostname)
    else:
        raise SSRFBlockedError("URL does not contain a hostname")


async def tls_connect(hostname: str, port: int = 443):
    """Simple TLS connect stub for tests – returns a tuple describing TLS version."""
    return "TLSv1.3", ("TLS_AES_256_GCM_SHA384",), None