"""
AGY Bug Bounty MCP - Centralised Input Validators
Reusable guards for tool parameters before they reach network calls,
subprocess invocations (vulnx / searchsploit / msfconsole), or the database.

Design goals:
  - Fail fast with a clear, Indonesian-style error message (matches project
    persona) instead of letting bad input reach downstream code.
  - Reject shell-metacharacters for any parameter that gets passed to
    `asyncio.create_subprocess_exec` — defence-in-depth even though we
    don't shell-interpolate, the input also lands in a JSON payload
    that downstream tools parse.
  - Return `None` on success, or a `str` error message on failure so the
    calling tool can do `err = validate_…(...); if err: return {"error": err}`.
"""

from __future__ import annotations

import re
from typing import Optional

# Characters that should never appear in a parameter that is later passed to
# a shell-style tool, embedded in a SQL string, or used as part of a URL.
# Includes: ; | & ` $ ( ) < > newline, plus quotes that may break parsing.
_SHELL_METACHARS = re.compile(r"[;|`$&()<>\n\r\\\"]")


def _is_blank(value: object) -> bool:
    """True if value is None, empty, or whitespace-only."""
    if value is None:
        return True
    if not isinstance(value, str):
        return True
    return value.strip() == ""


def validate_required_string(
    value: object,
    param_name: str,
    *,
    allow_shell_metachars: bool = False,
) -> Optional[str]:
    """Validate a required non-empty string parameter.

    Returns:
        None  — value is acceptable.
        str   — human-readable error message in Indonesian persona voice.

    Args:
        value:    The parameter value to check.
        param_name: Name of the parameter (used in the error message).
        allow_shell_metachars: Set to True to skip the metachar check.
            Only do this for parameters that are already known-safe (e.g. an
            enum like "exploit"/"auxiliary" for msf_module_type).
    """
    if _is_blank(value):
        return f"Parameter '{param_name}' tidak boleh kosong"

    if not allow_shell_metachars and isinstance(value, str):
        if _SHELL_METACHARS.search(value):
            found = "".join(sorted(set(_SHELL_METACHARS.findall(value))))
            return (
                f"Parameter '{param_name}' mengandung karakter terlarang: "
                f"{found!r}. Karakter ini bisa digunakan untuk command injection."
            )

    return None


def validate_url(
    value: object,
    param_name: str,
) -> Optional[str]:
    """Validate a URL parameter — must start with http:// or https://.

    Returns None on success, error string on failure.
    """
    err = validate_required_string(value, param_name)
    if err:
        return err

    if not isinstance(value, str):
        return f"Parameter '{param_name}' harus berupa string"

    stripped = value.strip()
    if not (stripped.startswith("http://") or stripped.startswith("https://")):
        return (
            f"Parameter '{param_name}' harus berupa URL yang valid "
            f"(dimulai dengan http:// atau https://), dapat: {stripped[:40]!r}"
        )

    return None


def validate_cve_id(value: object, param_name: str = "cve_id") -> Optional[str]:
    """Validate a CVE ID like CVE-2024-12345.

    Returns None on success, error string on failure.
    """
    err = validate_required_string(value, param_name, allow_shell_metachars=True)
    if err:
        return err

    if not isinstance(value, str):
        return f"Parameter '{param_name}' harus berupa string"

    # Strip whitespace + uppercase
    candidate = value.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", candidate):
        return (
            f"Parameter '{param_name}' harus berformat CVE-YYYY-NNNN "
            f"(misal CVE-2024-12345), dapat: {value!r}"
        )

    return None
