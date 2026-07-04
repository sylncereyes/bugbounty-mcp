"""
AGY Bug Bounty MCP - Shared HTTP Client Utilities
All tool modules should use get_client() instead of creating their own httpx.AsyncClient.
"""
import httpx
import asyncio
import logging
import functools
from urllib.parse import urlparse
from config import DEFAULT_TIMEOUT, USER_AGENT, VERIFY_SSL, REQUEST_DELAY, DRY_RUN
from tools.db import is_in_scope

logger = logging.getLogger("agy")

# SSL disabled warning flag to avoid spamming logs
_ssl_warning_printed = False

# WAF block indicators
WAF_BLOCK_INDICATORS = [
    "403", "429", "access denied", "blocked", "forbidden", "rate limit",
    "waf", "cloudflare", "akamai", "imperva", "incapsula", "sqreen",
    " ModSecurity", "OWASP", "ddos protection", "security service",
    "suspicious activity", "automated request", "bot detection"
]


def extract_domain(url: str) -> str:
    """Extract domain from URL for rate limiting key."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        # Remove port if present
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        return hostname.lower()
    except Exception:
        # Fallback: return lowercase url
        return url.lower()


def validate_scope(url: str, target_id: int = None) -> None:
    """Validate URL scope before making requests.
    
    Args:
        url: Target URL to validate
        target_id: Optional target ID for scope checking
    
    Raises:
        ValueError: If target_id provided but URL is not in scope
    """
    if target_id is not None and not is_in_scope(target_id, url):
        from tools.db import get_target
        target = get_target(target_id)
        if not target:
            raise ValueError(
                f"INVALID_TARGET: Target ID {target_id} does not exist in database. "
                f"Use add_target() to create a target first."
            )
        raise ValueError(
            f"OUT_OF_SCOPE: URL '{url}' is NOT authorized for target '{target.get('program_name', 'Unknown')}'. "
            f"Declared scope: {target.get('scope', '[]')}. "
            f"ALWAYS verify scope before running security tests. "
            f"Update target scope via add_target() or remove target_id parameter."
        )


def with_scope_validation(func):
    """Decorator to automatically validate scope before tool execution.
    
    Tools using this decorator will check if target_id is provided and 
    validate the URL against declared scope before proceeding.
    """
    @functools.wraps(func)
    async def wrapper(url: str = None, target_id: int = None, **kwargs):
        if url and target_id is not None:
            validate_scope(url, target_id)
        return await func(url=url, target_id=target_id, **kwargs)
    
    # Also wrap sync functions
    if not asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        def sync_wrapper(url: str = None, target_id: int = None, **kwargs):
            if url and target_id is not None:
                validate_scope(url, target_id)
            return func(url=url, target_id=target_id, **kwargs)
        return sync_wrapper
    
    return wrapper

def _log_ssl_warning():
    """Log a one-time warning when SSL verification is disabled."""
    global _ssl_warning_printed
    if not VERIFY_SSL and not _ssl_warning_printed:
        logger.warning("[SECURITY] SSL certificate verification is DISABLED - requests are vulnerable to MITM attacks!")
        logger.warning("[SECURITY] Set VERIFY_SSL=true in .env to enable SSL verification")
        _ssl_warning_printed = True


def get_client(**kwargs) -> httpx.AsyncClient:
    """Create a pre-configured httpx.AsyncClient with AGY defaults.

    Defaults applied:
    - timeout   -> from REQUEST_TIMEOUT env (default 30s)
    - verify    -> from VERIFY_SSL env (default True)
    - User-Agent-> from USER_AGENT env
    - follow_redirects -> False (important for security testing)

    Any kwarg can override the defaults.  Custom ``headers`` are *merged*
    with the default User-Agent header rather than replacing it.
    """
    _log_ssl_warning()
    defaults = {
        "timeout": DEFAULT_TIMEOUT,
        "verify": VERIFY_SSL,
        "headers": {"User-Agent": USER_AGENT},
        "follow_redirects": False,
    }
    # Merge headers so caller-supplied headers don't drop User-Agent
    if "headers" in kwargs:
        merged = defaults["headers"].copy()
        merged.update(kwargs.pop("headers"))
        defaults["headers"] = merged
    defaults.update(kwargs)
    return httpx.AsyncClient(**defaults)


async def delay() -> None:
    """Apply the configured inter-request delay (REQUEST_DELAY seconds)."""
    if REQUEST_DELAY > 0:
        await asyncio.sleep(REQUEST_DELAY)


async def secure_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    target_id: int = None,
    dry_run: bool = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
    **kwargs
) -> httpx.Response:
    """Execute HTTP request with scope validation, backoff, and dry-run support.
    
    This is the preferred function for all security testing tools.
    
    Args:
        client: httpx.AsyncClient instance
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        target_id: Target ID for scope validation (raises ValueError if out of scope)
        dry_run: If True, return mock response without hitting target
        max_retries: Maximum retry attempts (default 3)
        base_delay: Base delay in seconds for exponential backoff (default 1.0)
        **kwargs: Additional request arguments (params, json, headers, etc.)
    
    Returns:
        httpx.Response object
    
    Raises:
        ValueError: If target_id provided but URL is out of scope
        Exception: On final failure after all retries
    """
    # 1. Scope validation - FAIL if out of scope
    validate_scope(url, target_id)
    
    # 2. Dry-run mode - return mock without hitting target
    if dry_run is None:
        dry_run = DRY_RUN
    if dry_run:
        logger.info(f"[DRY RUN] Would send {method} request to {url} - skipping actual request")
        return httpx.Response(200, text="[DRY RUN] Request not executed", request=httpx.Request(method, url))
    
    # 3. Actual request with backoff
    return await request_with_backoff(
        client=client,
        method=method,
        url=url,
        max_retries=max_retries,
        base_delay=base_delay,
        dry_run=False,  # Already handled above
        **kwargs
    )


async def request_with_backoff(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_retries: int = 3,
    base_delay: float = 1.0,
    dry_run: bool = None,
    **kwargs
) -> httpx.Response:
    """Execute HTTP request with exponential backoff for rate limiting/WAF blocking.
    
    Args:
        client: httpx.AsyncClient instance
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        max_retries: Maximum retry attempts (default 3)
        base_delay: Base delay in seconds (default 1.0)
        dry_run: If True, return mock response without actual request (default: DRY_RUN config)
        **kwargs: Additional request arguments (params, json, headers, etc.)
    
    Returns:
        httpx.Response object
    
    Raises:
        Exception: On final failure after all retries
    """
    # Handle dry_run mode - return mock response without hitting target
    if dry_run is None:
        dry_run = DRY_RUN
    if dry_run:
        logger.info(f"[DRY RUN] Would send {method} request to {url} - skipping actual request")
        return httpx.Response(200, text="[DRY RUN] Request not executed", request=httpx.Request(method, url))
    
    method_lower = method.lower()
    request_func = getattr(client, method_lower)
    
    last_error: Exception = Exception("Max retries exceeded")
    for attempt in range(max_retries):
        try:
            response = await request_func(url, **kwargs)
            
            # Check for rate limiting or WAF blocking
            is_blocked = False
            if response.status_code == 429:
                is_blocked = True
            elif response.status_code == 403:
                body_lower = response.text.lower()
                for indicator in WAF_BLOCK_INDICATORS:
                    if indicator in body_lower:
                        is_blocked = True
                        break
            
            if is_blocked and attempt < max_retries - 1:
                # exponential backoff with jitter: base_delay * 2^attempt + random
                backoff_time = base_delay * (2 ** attempt)
                logger.warning(
                    f"[RATE LIMIT/WAF] Detected blocking on {url} - "
                    f"Status: {response.status_code} - "
                    f"Backing off for {backoff_time:.1f}s (attempt {attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(backoff_time)
                continue
            
            return response
            
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                backoff_time = base_delay * (2 ** attempt)
                logger.warning(f"[RETRY] Request failed, retrying in {backoff_time:.1f}s: {e}")
                await asyncio.sleep(backoff_time)
    
    raise last_error


def tls_connect(hostname: str, port: int = 443, timeout: float = None):
    """Create a TLS/SSL connection and return (version, cipher, cert) tuple.

    This is a shared helper to avoid duplicating raw TLS socket logic
    across tool modules (e.g. a02_misconfiguration and a04_cryptography).

    Returns:
        tuple: (protocol_version: str, cipher: tuple|None, cert: dict|None)

    Raises:
        Exception: Any connection or TLS negotiation error.
    """
    import ssl
    import socket
    _timeout = timeout or DEFAULT_TIMEOUT
    # FIX BUG-MEDIUM-4: honour VERIFY_SSL config (previously always verified)
    context = ssl.create_default_context()
    if not VERIFY_SSL:
        logger.warning(f"[SECURITY] TLS connection to {hostname}:{port} without cert verification!")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=_timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.version(), ssock.cipher(), ssock.getpeercert()