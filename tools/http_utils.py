"""
AGY Bug Bounty MCP - Shared HTTP Client Utilities
All tool modules should use get_client() instead of creating their own httpx.AsyncClient.
"""
import httpx
import asyncio
import logging
from config import DEFAULT_TIMEOUT, USER_AGENT, VERIFY_SSL, REQUEST_DELAY

logger = logging.getLogger("agy")


def get_client(**kwargs) -> httpx.AsyncClient:
    """Create a pre-configured httpx.AsyncClient with AGY defaults.

    Defaults applied:
    - timeout   → from REQUEST_TIMEOUT env (default 30s)
    - verify    → from VERIFY_SSL env (default True)
    - User-Agent→ from USER_AGENT env
    - follow_redirects → False (important for security testing)

    Any kwarg can override the defaults.  Custom ``headers`` are *merged*
    with the default User-Agent header rather than replacing it.
    """
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


async def delay():
    """Apply the configured inter-request delay (REQUEST_DELAY seconds)."""
    if REQUEST_DELAY > 0:
        await asyncio.sleep(REQUEST_DELAY)


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
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=_timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.version(), ssock.cipher(), ssock.getpeercert()
