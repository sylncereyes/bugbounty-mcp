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


class PinnedResolverTransport(httpx.AsyncHTTPTransport):
    """
    Transport that pins connections to a pre-validated IP address
    while preserving the original hostname for TLS SNI and verification.
    """
    def __init__(self, pinned_ip: str, **kwargs):
        super().__init__(**kwargs)
        self._pinned_ip = pinned_ip

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Preserve original hostname from the request (might have been mutated before)
        original_host = request.url.host
        if not original_host:
            # Fallback to the last known good hostname, if we have one
            raise SSRFBlockedError("Cannot resolve target hostname.")

        request.url = request.url.copy_with(host=self._pinned_ip)
        request.headers["host"] = original_host
        return await super().handle_async_request(request)


async def _resolve_and_pin(hostname: str) -> Tuple[str, str]:
    """
    Resolve hostname asynchronously, validate against deny-list,
    and return (original_hostname, pinned_ip_string).
    
    The pinned_ip is the FIRST non‑blocked IP (IPv4 preferred).
    Raises SSRFBlockedError if resolution fails or all resolved IPs are blocked.
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

        # Handle IPv4-mapped IPv6 (::ffff:x.x.x.x)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        if any(ip in net for net in _DENIED_NETWORKS):
            continue   # skip blocked networks

        if isinstance(ip, ipaddress.IPv4Address) or pinned_ip is None:
            pinned_ip = ip

    if pinned_ip is None:
        raise SSRFBlockedError(f"{hostname} resolves ONLY to blocked ranges")

    return hostname, str(pinned_ip)


async def secure_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    target_id: int,
    dry_run: bool = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
    follow_redirects: bool = False,
    **kwargs,
) -> httpx.Response:
    """
    Execute HTTP request with SSRF protection (async DNS + transport pinning),
    scope validation, and dry‑run support.
    """
    # 1. SSRF mitigation
    hostname, pinned_ip = await _resolve_and_pin(urlparse(url).hostname)

    # 2. Scope validation
    validate_scope_or_fail(target_id, url)

    # 3. Dry‑run
    if dry_run is None:
        dry_run = DRY_RUN
    if dry_run:
        logger.info(f"[DRY RUN] {method.upper()} {url} (pinned to {pinned_ip})")
        return httpx.Response(200, text="[DRY RUN] Request not executed", request=httpx.Request(method, url))

    # 4. Wrap client transport with pinned resolver
    original_transport = client._transport
    client._transport = PinnedResolverTransport(pinned_ip=pinned_ip)

    try:
        return await _request_with_backoff(
            client=client,
            method=method,
            url=url,
            max_retries=max_retries,
            base_delay=base_delay,
            follow_redirects=follow_redirects,
            **kwargs,
        )
    finally:
        client._transport = original_transport


async def _request_with_backoff(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_retries: int,
    base_delay: float,
    follow_redirects: bool,
    **kwargs,
) -> httpx.Response:
    attempt = 0
    while True:
        try:
            # httpx correctly uses SNI from request.url.hostname, not the host header
            return await client.request(
                method,
                url,
                follow_redirects=follow_redirects,
                **kwargs
            )
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
    """
    High‑level helper for modules that need one‑off requests.
    Reuses the provided client (if any) or creates a new one.
    """
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            verify=VERIFY_SSL,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
        )

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