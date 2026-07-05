"""
AGY Bug Bounty MCP - Scope Enforcement & Rate Limiting

This module provides:
1. Scope validation decorator for tools
2. Rate limiting per target domain
3. Safety guards for destructive operations
"""

import time
import threading
from functools import wraps
from urllib.parse import urlparse
from typing import Callable, Optional, Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_target, is_in_scope, validate_scope_or_fail
from config import REQUEST_DELAY, MAX_CONCURRENT_REQUESTS

# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter per domain."""
    
    def __init__(self, requests_per_second: float = 1.0, max_burst: int = 10):
        self._tokens = defaultdict(float)
        self._last_refill = defaultdict(float)
        self._lock = threading.Lock()
        self._rps = requests_per_second
        self._max_burst = max_burst
    
    def _refill(self, domain: str) -> None:
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - self._last_refill[domain]
        self._tokens[domain] = min(
            self._max_burst,
            self._tokens[domain] + elapsed * self._rps
        )
        self._last_refill[domain] = now
    
    def acquire(self, domain: str) -> bool:
        """Acquire a token for the domain. Returns True if allowed."""
        with self._lock:
            self._refill(domain)
            if self._tokens[domain] >= 1.0:
                self._tokens[domain] -= 1.0
                return True
            return False
    
    def wait_time(self, domain: str) -> float:
        """Get seconds to wait before next request is allowed."""
        with self._lock:
            self._refill(domain)
            if self._tokens[domain] >= 1.0:
                return 0.0
            return (1.0 - self._tokens[domain]) / self._rps


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None
_rate_limiter_lock = threading.Lock()


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        with _rate_limiter_lock:
            if _rate_limiter is None:
                _rate_limiter = RateLimiter(
                    requests_per_second=1.0 / REQUEST_DELAY,
                    max_burst=MAX_CONCURRENT_REQUESTS
                )
    return _rate_limiter


# ─────────────────────────────────────────────────────────────────────────────
# SCOPE ENFORCEMENT DECORATOR
# ─────────────────────────────────────────────────────────────────────────────

def require_scope(target_id_arg: int = 0, url_arg: int = 1, 
                  raise_on_fail: bool = True, dry_run_only: bool = False):
    """
    Decorator to enforce scope validation on tool functions.
    
    Args:
        target_id_arg: Position of target_id parameter in function signature
        url_arg: Position of URL parameter in function signature  
        raise_on_fail: If True, raises ValueError on scope violation
        dry_run_only: If True, only enforces when DRY_RUN is False
    
    Usage:
        @require_scope(target_id_arg=0, url_arg=1)
        def sqli_test(target_id: int, url: str, ...):
            ...
    """
    from config import DRY_RUN
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Skip enforcement in dry-run mode
            if DRY_RUN and dry_run_only:
                return func(*args, **kwargs)
            
            # Extract target_id and url from args/kwargs
            target_id = kwargs.get('target_id')
            if target_id is None and len(args) > target_id_arg:
                target_id = args[target_id_arg]
            
            url = kwargs.get('url')
            if url is None and len(args) > url_arg:
                url = args[url_arg]
            
            # Validate scope if we have both
            if url is not None:
                try:
                    validate_scope_or_fail(target_id, url)
                except ValueError as e:
                    if raise_on_fail:
                        raise
                    # Log warning and continue
                    import sys
                    print(f"[SCOPE WARNING] {e}", file=sys.stderr)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_url_in_scope(url: str, target_id: int) -> tuple[bool, str]:
    """
    Validate a URL against a target's scope.
    
    Returns:
        (is_in_scope: bool, message: str)
    """
    try:
        validate_scope_or_fail(target_id, url)
        return True, "URL is in scope"
    except ValueError as e:
        return False, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING DECORATOR
# ─────────────────────────────────────────────────────────────────────────────

def rate_limited(domain_arg: int = 0):
    """
    Decorator to rate limit function calls per domain.
    
    Args:
        domain_arg: Position of domain/URL parameter
    
    Usage:
        @rate_limited(domain_arg=1)
        def sqli_test(target_id: int, url: str, ...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            from config import DRY_RUN
            from http_utils import extract_domain
            
            # Skip in dry-run mode
            if DRY_RUN:
                return func(*args, **kwargs)
            
            # Extract domain from URL
            domain = kwargs.get('url') or (args[domain_arg] if len(args) > domain_arg else None)
            if domain:
                domain_name = extract_domain(domain)
                limiter = get_rate_limiter()
                
                if not limiter.acquire(domain_name):
                    wait = limiter.wait_time(domain_name)
                    import time
                    time.sleep(wait)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# DESTRUCTIVE TOOL GUARD
# ─────────────────────────────────────────────────────────────────────────────

class DestructiveToolGuard:
    """Guard for tools that can cause availability impact."""
    
    _confirmed_targets: Dict[int, set] = defaultdict(set)
    _lock = threading.Lock()
    
    @classmethod
    def require_confirmation(cls, target_id: int, tool_name: str) -> bool:
        """Check if tool has been confirmed for this target. Returns True if safe to proceed."""
        with cls._lock:
            return tool_name in cls._confirmed_targets[target_id]
    
    @classmethod
    def confirm_target(cls, target_id: int, tool_name: str) -> None:
        """Mark a tool as confirmed for a target."""
        with cls._lock:
            cls._confirmed_targets[target_id].add(tool_name)
    
    @classmethod
    def clear_confirmation(cls, target_id: int, tool_name: Optional[str] = None) -> None:
        """Clear confirmation for a target or specific tool."""
        with cls._lock:
            if tool_name:
                cls._confirmed_targets[target_id].discard(tool_name)
            else:
                cls._confirmed_targets[target_id].clear()


def require_confirmation(tool_name: str):
    """
    Decorator for tools that can cause DoS/availability impact.
    Requires explicit confirmation before execution.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            from config import DRY_RUN
            
            if DRY_RUN:
                return func(*args, **kwargs)
            
            target_id = kwargs.get('target_id')
            if target_id is None and len(args) > 0:
                # Try to find target_id in args
                for arg in args:
                    if isinstance(arg, int):
                        target_id = arg
                        break
            
            if True:
                if not DestructiveToolGuard.require_confirmation(target_id, tool_name):
                    import sys
                    print(
                        f"[CONFIRMATION REQUIRED] Tool '{tool_name}' can impact target availability. "
                        f"Call confirm_tool('{tool_name}', target_id={target_id}) first.",
                        file=sys.stderr
                    )
                    raise PermissionError(
                        f"Tool '{tool_name}' requires confirmation for target {target_id}. "
                        "Call confirm_tool() first."
                    )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def confirm_tool(tool_name: str, target_id: int) -> None:
    """Explicitly confirm a destructive tool for a target."""
    DestructiveToolGuard.confirm_target(target_id, tool_name)
    print(f"[CONFIRMED] Tool '{tool_name}' enabled for target {target_id}")


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_rate_limiter_stats() -> Dict[str, Any]:
    """Get current rate limiter statistics."""
    limiter = get_rate_limiter()
    with limiter._lock:
        return {
            "domains_tracked": len(limiter._tokens),
            "config": {
                "rps": limiter._rps,
                "max_burst": limiter._max_burst
            }
        }


def reset_rate_limiter() -> None:
    """Reset the rate limiter (useful for testing)."""
    global _rate_limiter
    with _rate_limiter_lock:
        _rate_limiter = None