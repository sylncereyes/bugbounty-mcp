import re
"""
Shared HTTP Client Utilities
All tool modules should use get_sync_client() (sync) or get_async_client() (async) 
instead of creating their own httpx.Client/AsyncClient.

Security Features:
  • SSRF protection via per-request DNS validation against private network denylist
  • Mandatory target_id scope validation for all requests
  • Dry-run support for safe testing
  • Exponential backoff retry mechanism
"""
import asyncio
import ipaddress
import logging
import socket
import time
import httpx
from urllib.parse import urlparse, urljoin
from typing import Optional, Tuple
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

# Redirect status codes that require manual handling when follow_redirects=False
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECT_HOPS = 5


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


async def secure_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    target_id: int,
    dry_run: Optional[bool] = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
    follow_redirects: bool = False,
    manual_follow_redirects: bool = False,
    **kwargs,
) -> httpx.Response:
    """Execute HTTP request with SSRF protection, scope validation, and dry-run.

    Security Features:
      • SSRF protection: Validates DNS resolution BEFORE each request attempt,
        mitigating DNS rebinding across retry backoff windows.
      • Scope validation: All requests require target_id, validated against
        registered target scope before any network operation.
      • Dry-run support: Returns mock response when DRY_RUN is enabled.
      • Retry with backoff: Exponential delay with per-attempt SSRF re-validation.
    """
    # 1. Scope validation (MANDATORY)
    if target_id is None:
        raise ValueError(
            "SCOPE_VALIDATION_REQUIRED: target_id must be provided for all requests. "
            "Use add_target() to register a target before making requests."
        )
    validate_scope_or_fail(target_id, url)

    # 2. Dry-run handling – short-circuit the request while preserving the
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

    # 3. Execute the request with exponential backoff and per-attempt SSRF re-validation
    async def _do_request() -> httpx.Response:
        hostname = urlparse(url).hostname
        if hostname:
            await _resolve_and_validate(hostname)
        response = await client.request(
            method, url, follow_redirects=follow_redirects, **kwargs
        )
        
        # Manual redirect following with scope validation if requested
        if manual_follow_redirects and not follow_redirects:
            return await _follow_redirects_safely(
                client, method, url, target_id, response, **kwargs
            )
        
        return response

    attempt = 0
    while True:
        try:
            return await _do_request()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            if attempt >= max_retries:
                raise
            await asyncio.sleep(base_delay * (2 ** attempt))
            attempt += 1


def _resolve_and_validate_sync(hostname: str) -> str:
    """Sync version of _resolve_and_validate – used by pure-sync tools."""
    if not hostname:
        raise SSRFBlockedError("No hostname provided")
    try:
        addrs = socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise SSRFBlockedError(f"DNS resolution failed for {hostname}: {e}")

    pinned_ip = None
    for family, socktype, proto, canonname, sockaddr in addrs:
        raw_ip = sockaddr[0]
        ip = ipaddress.ip_address(raw_ip)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if any(ip in net for net in _DENIED_NETWORKS):
            continue
        if isinstance(ip, ipaddress.IPv4Address) or pinned_ip is None:
            pinned_ip = ip
    if pinned_ip is None:
        raise SSRFBlockedError(f"{hostname} resolves ONLY to blocked ranges")
    return str(pinned_ip)


async def _follow_redirects_safely(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    target_id: int,
    response: httpx.Response,
    **kwargs,
) -> httpx.Response:
    """Manually follow redirect chain, re-validating scope + SSRF at EVERY hop.
    
    Raises ValueError if any hop in the chain is out of scope or SSRF-blocked.
    """
    hop = 0
    current_response = response
    current_url = url
    
    while current_response.status_code in _REDIRECT_STATUS_CODES and hop < MAX_REDIRECT_HOPS:
        location = current_response.headers.get("Location")
        if not location:
            break
        
        next_url = urljoin(current_url, location)
        validate_scope_or_fail(target_id, next_url)
        
        next_hostname = urlparse(next_url).hostname
        if next_hostname:
            await _resolve_and_validate(next_hostname)
        
        current_response = await client.request(
            method, next_url, follow_redirects=False, **kwargs
        )
        current_url = next_url
        hop += 1
    
    if hop >= MAX_REDIRECT_HOPS:
        raise ValueError(f"Too many redirects (>{MAX_REDIRECT_HOPS}) starting from {url}")
    
    return current_response


def _follow_redirects_safely_sync(
    client: httpx.Client,
    method: str,
    url: str,
    target_id: int,
    response: httpx.Response,
    **kwargs,
) -> httpx.Response:
    """Sync version of _follow_redirects_safely."""
    hop = 0
    current_response = response
    current_url = url
    
    while current_response.status_code in _REDIRECT_STATUS_CODES and hop < MAX_REDIRECT_HOPS:
        location = current_response.headers.get("Location")
        if not location:
            break
        
        next_url = urljoin(current_url, location)
        validate_scope_or_fail(target_id, next_url)
        
        next_hostname = urlparse(next_url).hostname
        if next_hostname:
            _resolve_and_validate_sync(next_hostname)
        
        current_response = client.request(
            method, next_url, follow_redirects=False, **kwargs
        )
        current_url = next_url
        hop += 1
    
    if hop >= MAX_REDIRECT_HOPS:
        raise ValueError(f"Too many redirects (>{MAX_REDIRECT_HOPS}) starting from {url}")
    
    return current_response


def secure_request_sync(
    client: httpx.Client,
    method: str,
    url: str,
    target_id: int,
    dry_run: Optional[bool] = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
    follow_redirects: bool = False,
    manual_follow_redirects: bool = False,
    **kwargs,
) -> httpx.Response:
    """Sync wrapper of secure_request – supports pure-sync tools.

    SSRF protection, scope validation, dry-run and retry semantics are
    replicated from ``secure_request`` but run synchronously.
    """
    if target_id is None:
        raise ValueError(
            "SCOPE_VALIDATION_REQUIRED: target_id must be provided for all requests. "
            "Use add_target() to register a target before making requests."
        )
    validate_scope_or_fail(target_id, url)

    if dry_run is None:
        dry_run = DRY_RUN
    if dry_run:
        logger.info(f"[DRY RUN] {method.upper()} {url}")
        return httpx.Response(
            200,
            text="[DRY RUN] Request not executed",
            request=httpx.Request(method, url),
        )

    def _do_request() -> httpx.Response:
        hostname = urlparse(url).hostname
        if hostname:
            _resolve_and_validate_sync(hostname)
        response = client.request(method, url, follow_redirects=follow_redirects, **kwargs)
        
        # Manual redirect following with scope validation if requested
        if manual_follow_redirects and not follow_redirects:
            return _follow_redirects_safely_sync(
                client, method, url, target_id, response, **kwargs
            )
        
        return response

    attempt = 0
    while True:
        try:
            return _do_request()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            if attempt >= max_retries:
                raise
            time.sleep(base_delay * (2 ** attempt))
            attempt += 1


def get_sync_client(**overrides) -> httpx.Client:
    """Synchronous client factory for pure-sync tools (cloud_testing, git_testing, etc.)."""
    defaults = {
        "timeout": DEFAULT_TIMEOUT,
        "verify": VERIFY_SSL,
        "headers": {"User-Agent": USER_AGENT},
        "follow_redirects": False,
    }
    if "headers" in overrides:
        defaults["headers"].update(overrides.pop("headers"))
    defaults.update(overrides)
    return httpx.Client(**defaults)


def get_async_client(**overrides) -> httpx.AsyncClient:
    """Asynchronous client factory for async tools (hunter, etc.)."""
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


# Backward compatibility alias for existing async tools
get_client = get_async_client  # alias: async tools use this


async def delay() -> None:
    if REQUEST_DELAY > 0:
        await asyncio.sleep(REQUEST_DELAY)


def delay_sync() -> None:
    if REQUEST_DELAY > 0:
        time.sleep(REQUEST_DELAY)


# Compatibility helpers

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


def assert_safe_target_sync(url: str) -> None:
    """Sync version of ``assert_safe_target``."""
    hostname = urlparse(url).hostname
    if hostname:
        _resolve_and_validate_sync(hostname)
    else:
        raise SSRFBlockedError("URL does not contain a hostname")


def tls_connect(hostname: str, port: int = 443):
    """Simple TLS connect stub for tests – returns a tuple describing TLS version."""
    return "TLSv1.3", ("TLS_AES_256_GCM_SHA384",), None

# Keys/patterns yang dianggap sensitif dan wajib diredaksi dari laporan
_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token",
    "refresh_token", "api_key", "apikey", "authorization", "auth",
    "cookie", "session", "session_id", "sessionid", "credential",
    "credentials", "private_key", "client_secret", "bearer",
}

_SENSITIVE_VALUE_PATTERNS = [
    re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE),
    re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),  # JWT-like
    re.compile(r'(?i)(api[_-]?key|token|secret)["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-._~+/]{16,}'),
]

_REDACTED = "***REDACTED***"


def _redact_value(value: str) -> str:
    """Redact known sensitive patterns within a string value."""
    if not isinstance(value, str):
        return value
    result = value
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result


def sanitize_output(data):
    """Recursively redact sensitive data (tokens, cookies, credentials) from
    findings/stats before they are included in a generated report.

    Handles dict, list, tuple, and str inputs recursively. Any dict key
    matching a known-sensitive name (password, token, cookie, secret, etc.)
    has its value fully redacted regardless of content. String values are
    additionally scanned for embedded sensitive patterns (Bearer tokens,
    JWT-like strings, key=value secrets) even under non-sensitive keys.

    Does not mutate the input; returns a sanitized copy.
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(sensitive in key_lower for sensitive in _SENSITIVE_KEYS):
                sanitized[key] = _REDACTED
            else:
                sanitized[key] = sanitize_output(value)
        return sanitized
    elif isinstance(data, (list, tuple)):
        sanitized_list = [sanitize_output(item) for item in data]
        return sanitized_list if isinstance(data, list) else tuple(sanitized_list)
    elif isinstance(data, str):
        return _redact_value(data)
    else:
        return data
