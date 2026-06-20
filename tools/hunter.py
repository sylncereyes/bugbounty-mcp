"""
AGY Bug Bounty MCP - Hunter Mindset Tools
Tools that fill the gap between automated OWASP scanning and real bug bounty
hunter intuition: business-logic modeling, deep OSINT, finding escalation,
and context-aware hidden-endpoint discovery.

Every tool follows project conventions:
  • Registered via @mcp.tool() on the shared FastMCP instance.
  • Returns a plain dict (JSON-serialisable).
  • HTTP via tools.http_utils.get_client() (honours VERIFY_SSL, timeout, UA).
  • Async + timeout 30 s where external calls are involved.
  • Errors surfaced as {"error": "..."} — never raises to the client.
"""

import asyncio
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from mcp_instance import mcp
from tools.db import db_connection, init_db
from tools.http_utils import get_client, delay
from tools.validators import validate_required_string, validate_url
from config import GITHUB_TOKEN, DEFAULT_TIMEOUT

logger = logging.getLogger("agy")

# ──────────────────────────────────────────────────────────────────────────────
# DATABASE SCHEMA — hunter-specific tables
# ──────────────────────────────────────────────────────────────────────────────

def _init_hunter_tables() -> None:
    """Create hunter-specific tables if they don't exist."""
    with db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hunt_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                target          TEXT    NOT NULL,
                industry        TEXT    NOT NULL,
                objective       TEXT    NOT NULL,
                plan            TEXT    NOT NULL,
                created_at      TEXT    DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS osint_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      INTEGER REFERENCES hunt_sessions(id) ON DELETE SET NULL,
                target          TEXT    NOT NULL,
                result_type     TEXT    NOT NULL,
                data            TEXT    NOT NULL,
                created_at      TEXT    DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_hunt_sessions_target ON hunt_sessions(target);
            CREATE INDEX IF NOT EXISTS idx_osint_results_session ON osint_results(session_id);
        """)

_init_hunter_tables()


# ══════════════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASES  (pure data — no network calls)
# ══════════════════════════════════════════════════════════════════════════════

_INDUSTRY_KB: Dict[str, Dict[str, Any]] = {
    "fintech": {
        "priority_assets": [
            "/api/transfer", "/api/payment", "/api/withdraw", "/api/balance",
            "/api/transactions", "/api/kyc", "/api/cards", "/api/wallet",
            "/api/exchange", "/api/invoice", "/billing", "/checkout",
        ],
        "likely_logic_flaws": [
            "Race condition on balance transfer (double-spend)",
            "IDOR on transaction / statement / invoice endpoints",
            "Currency rounding / conversion manipulation",
            "Negative amount or zero-amount transfer bypass",
            "KYC verification bypass via direct API call",
            "Withdrawal to unverified account",
            "Transaction replay attack",
            "Fee calculation manipulation",
        ],
        "developer_assumptions": [
            "Frontend validates transfer amount — backend may not",
            "Rate limiting on login but not on OTP/2FA endpoint",
            "Staging payment gateway left connected in production",
            "Hardcoded test card numbers or sandbox API keys in JS",
            "Internal transfer between own accounts skips AML check",
        ],
    },
    "ecommerce": {
        "priority_assets": [
            "/checkout", "/cart", "/api/orders", "/api/coupons", "/api/promo",
            "/api/refund", "/api/inventory", "/api/shipping", "/api/discount",
            "/api/giftcard", "/wishlist", "/api/reviews",
        ],
        "likely_logic_flaws": [
            "Price tampering via cart/checkout parameter manipulation",
            "Coupon code stacking or reuse beyond intended limit",
            "Negative quantity / negative price abuse",
            "Order status manipulation (cancel after ship)",
            "Refund to different payment method than original",
            "Inventory race condition (overselling)",
            "Gift card balance manipulation",
            "Shipping cost bypass via address manipulation",
        ],
        "developer_assumptions": [
            "Price validated on frontend only — API accepts raw POST",
            "Coupon validation on apply but not re-checked at payment",
            "Order ID is sequential — enumerable for IDOR",
            "Refund endpoint trusts amount from client",
            "Test promo codes left active in production",
        ],
    },
    "saas": {
        "priority_assets": [
            "/api/billing", "/api/subscription", "/api/team", "/api/roles",
            "/api/permissions", "/api/export", "/api/import", "/api/keys",
            "/api/webhooks", "/api/integrations", "/api/audit", "/api/tenants",
            "/settings", "/admin",
        ],
        "likely_logic_flaws": [
            "Privilege escalation: member → admin via role parameter tampering",
            "Cross-tenant data access via IDOR on tenant-scoped resources",
            "API key leakage in client-side JavaScript or logs",
            "Billing bypass — downgrade plan but keep premium features",
            "Data export of another tenant's data via job ID manipulation",
            "Invitation link reuse after intended recipient already joined",
            "Webhook URL SSRF — internal network scan via callback",
            "Mass assignment on user profile (role, tenant_id fields)",
        ],
        "developer_assumptions": [
            "Tenant isolation enforced at app layer, not database layer",
            "Free-tier feature flags checked on frontend only",
            "Export jobs stored in predictable /tmp or S3 path",
            "Admin endpoints protected by UI but not by API middleware",
            "API key rotation does not invalidate old keys immediately",
        ],
    },
    "healthtech": {
        "priority_assets": [
            "/api/patients", "/api/records", "/api/prescriptions",
            "/api/appointments", "/api/lab-results", "/api/doctors",
            "/api/medical-history", "/api/billing", "/api/insurance",
            "/api/export", "/portal",
        ],
        "likely_logic_flaws": [
            "IDOR on patient records — access other patients' PHI",
            "Prescription manipulation — change medication or dosage",
            "Appointment booking race condition — double-book",
            "Lab result access without proper patient-doctor relationship",
            "Medical record export without audit logging",
            "Insurance claim amount manipulation",
            "Doctor impersonation via role parameter",
        ],
        "developer_assumptions": [
            "PHI access controlled by session role, not record-level ACL",
            "PDF export of records does not re-check authorization",
            "Patient ID is sequential integer — enumerable",
            "Debug mode exposes patient data in error messages",
            "HIPAA audit logging is async and can be bypassed",
        ],
    },
    "general": {
        "priority_assets": [
            "/admin", "/api/internal", "/debug", "/staging",
            "/api/v1", "/api/v2", "/graphql", "/api/export",
            "/api/users", "/api/auth", "/api/upload", "/api/download",
            "/api/webhook", "/api/callback", "/health", "/metrics",
        ],
        "likely_logic_flaws": [
            "Authentication bypass via direct API access",
            "Authorization check missing on state-changing endpoints",
            "File upload type/size validation bypass",
            "IDOR on user profile or resource endpoints",
            "Rate limiting inconsistency across endpoints",
            "Session fixation or insufficient session invalidation",
            "Mass assignment on user-controlled objects",
        ],
        "developer_assumptions": [
            "Debug endpoints disabled by env var but still routed",
            "API v1 deprecated but still live without security patches",
            "Admin panel behind /admin with no additional auth layer",
            "Error messages expose stack trace / SQL in non-prod mode flag",
            "Default credentials not changed after deployment",
        ],
    },
}

_OBJECTIVE_TOOLS: Dict[str, Dict[str, List[str]]] = {
    "data_breach": {
        "recommended_first_tools": [
            "idor_test", "sqli_test", "path_traversal_test",
            "check_sensitive_data_exposure", "exposed_files_check",
            "error_disclosure_check",
        ],
        "skip_for_now": [
            "security_headers_check", "cookie_security_check",
            "check_https_redirect", "tls_ssl_check",
        ],
    },
    "account_takeover": {
        "recommended_first_tools": [
            "password_reset_test", "session_management_check",
            "jwt_analyze", "jwt_attack_test", "xss_test",
            "oauth_misconfiguration_check", "account_enumeration_test",
            "csrf_test",
        ],
        "skip_for_now": [
            "directory_listing_check", "check_cdn_integrity",
            "detect_vulnerable_js_libs",
        ],
    },
    "privilege_escalation": {
        "recommended_first_tools": [
            "privilege_escalation_test", "access_control_bypass_test",
            "idor_test", "mass_assignment_test", "parameter_tampering_test",
            "forced_browsing_scan",
        ],
        "skip_for_now": [
            "tls_ssl_check", "ssl_cipher_check",
            "check_https_redirect",
        ],
    },
    "rce": {
        "recommended_first_tools": [
            "command_injection_test", "ssti_test", "xxe_test",
            "check_insecure_deserialization", "ssrf_test",
            "sqli_test",
        ],
        "skip_for_now": [
            "cors_misconfiguration_check", "cookie_security_check",
            "rate_limit_check",
        ],
    },
    "business_logic": {
        "recommended_first_tools": [
            "business_logic_price_test", "race_condition_test",
            "parameter_tampering_test", "idor_test",
            "mass_assignment_test", "rate_limit_check",
        ],
        "skip_for_now": [
            "tls_ssl_check", "ssl_cipher_check",
            "detect_weak_hashing", "check_cdn_integrity",
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 1 — define_hunt_goal
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def define_hunt_goal(
    target: str,
    industry: str,
    objective: str,
) -> dict:
    """Define a hunting goal and generate a hypothesis-driven plan.

    Before any scanning, this tool establishes what to hunt for (objective),
    infers which assets are crown jewels based on the target's industry,
    and recommends which MCP tools to use first — and which to skip.

    Parameters:
        target:    Domain of the target (e.g. "example.com").
        industry:  One of: fintech, ecommerce, saas, healthtech, general.
        objective: One of: data_breach, account_takeover, privilege_escalation, rce, business_logic.

    Returns a dict with the session_id and full hunting plan.
    """
    # Validate inputs FIRST — refuse to persist anything to the DB if invalid.
    for err in (
        validate_required_string(target, "target"),
        validate_required_string(industry, "industry"),
        validate_required_string(objective, "objective"),
    ):
        if err:
            return {"error": err}

    try:
        industry_key = industry.lower().strip()
        objective_key = objective.lower().strip()

        if industry_key not in _INDUSTRY_KB:
            industry_key = "general"
        if objective_key not in _OBJECTIVE_TOOLS:
            objective_key = "business_logic"

        ind = _INDUSTRY_KB[industry_key]
        obj = _OBJECTIVE_TOOLS[objective_key]

        plan = {
            "priority_assets": ind["priority_assets"],
            "likely_logic_flaws": ind["likely_logic_flaws"],
            "recommended_first_tools": obj["recommended_first_tools"],
            "skip_for_now": obj["skip_for_now"],
            "developer_assumptions": ind["developer_assumptions"],
            "hunting_order": [
                "1. Recon & OSINT — run osint_recon to map attack surface",
                "2. Hypothesis — pick 2-3 likely_logic_flaws to validate",
                "3. Critical assets — test priority_assets with recommended_first_tools",
                "4. Developer empathy — check developer_assumptions manually",
                "5. Escalation — run escalation_advisor on every finding",
                "6. OWASP safety net — run remaining tools LAST",
            ],
        }

        # Persist to database
        with db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO hunt_sessions (target, industry, objective, plan) VALUES (?, ?, ?, ?)",
                (target, industry_key, objective_key, json.dumps(plan)),
            )
            session_id = cursor.lastrowid

        return {
            "session_id": session_id,
            "target": target,
            "industry": industry_key,
            "objective": objective_key,
            "plan": plan,
        }
    except Exception as e:
        logger.error("define_hunt_goal failed: %s", e)
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 2 — osint_recon
# ══════════════════════════════════════════════════════════════════════════════

_INTERESTING_KEYWORDS = re.compile(
    r"(admin|api|internal|debug|staging|backup|test|old|v1|v2|"
    r"export|download|webhook|callback|graphql|swagger|config|"
    r"secret|token|dashboard|console|portal|manage)",
    re.IGNORECASE,
)

_JS_SECRET_PATTERNS = [
    re.compile(r"""(['"])(/api/[^\s'"]+)\1"""),
    re.compile(r"""(['"])(/v[12]/[^\s'"]+)\1"""),
    re.compile(r"""(['"])(/internal/[^\s'"]+)\1"""),
    re.compile(r"""(['"])(/graphql[^\s'"]*)\1"""),
    re.compile(r"""(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*['"]([^'"]{8,})['"]""", re.IGNORECASE),
]


_WAYBACK_TIMEOUT = 10.0  # Wayback CDX API is often slow; cap the wait


async def _wayback_fetch(target: str) -> Dict[str, Any]:
    """Fetch interesting URLs from Wayback Machine CDX API.

    Wrapped in asyncio.wait_for with a short timeout (10s) — if the
    Wayback CDX API is slow, this coroutine returns an empty result
    with status="timeout" instead of blocking the whole osint_recon
    call for the full 30s default timeout.
    """
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{target}&output=json&fl=original&collapse=urlkey&limit=200"
    )
    try:
        async def _do_fetch():
            async with get_client(timeout=_WAYBACK_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return {"urls": [], "error": f"Wayback returned {resp.status_code}"}
                rows = resp.json()
                # First row is header ["original"]
                all_urls = [r[0] for r in rows[1:]] if len(rows) > 1 else []
                interesting = [u for u in all_urls if _INTERESTING_KEYWORDS.search(u)]
                return {"urls": interesting, "total_archived": len(all_urls)}

        return await asyncio.wait_for(_do_fetch(), timeout=_WAYBACK_TIMEOUT + 2)
    except asyncio.TimeoutError:
        return {"urls": [], "error": f"Wayback timed out after {_WAYBACK_TIMEOUT}s", "status": "timeout"}
    except Exception as e:
        # httpx.ConnectTimeout / ReadTimeout inherit from httpx.TimeoutException
        try:
            import httpx
            if isinstance(e, httpx.TimeoutException):
                return {"urls": [], "error": f"Wayback timed out: {type(e).__name__}", "status": "timeout"}
        except ImportError:
            pass
        return {"urls": [], "error": str(e), "status": "error"}


async def _js_discovery(target: str) -> Dict[str, Any]:
    """Discover JS files from homepage, grep for endpoints & secrets."""
    endpoints: List[str] = []
    secrets: List[Dict[str, str]] = []
    js_files_found: List[str] = []

    try:
        async with get_client(timeout=30, follow_redirects=True) as client:
            resp = await client.get(f"https://{target}")
            html = resp.text

            # Extract <script src="..."> URLs
            src_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
            srcs = src_pattern.findall(html)

            for src in srcs[:20]:  # cap to avoid abuse
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    src = f"https://{target}{src}"
                elif not src.startswith("http"):
                    src = f"https://{target}/{src}"

                js_files_found.append(src)
                await delay()

                try:
                    js_resp = await client.get(src)
                    js_text = js_resp.text[:500_000]  # cap at 500KB per file

                    for pat in _JS_SECRET_PATTERNS:
                        for match in pat.finditer(js_text):
                            groups = match.groups()
                            if len(groups) >= 2:
                                value = groups[-1]
                                # Endpoints
                                if value.startswith("/"):
                                    if value not in endpoints:
                                        endpoints.append(value)
                                else:
                                    secrets.append({
                                        "file": src,
                                        "match": match.group(0)[:200],
                                    })
                except Exception:
                    continue

    except Exception as e:
        return {"endpoints": endpoints, "secrets": secrets, "error": str(e)}

    return {
        "js_files_scanned": len(js_files_found),
        "endpoints": endpoints,
        "secrets": secrets,
    }


async def _github_dork(target: str) -> Dict[str, Any]:
    """Search GitHub for potential secret leaks related to the target."""
    if not GITHUB_TOKEN:
        return {"results": [], "note": "GITHUB_TOKEN not set — skipped GitHub dorking"}

    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    queries = [
        f"{target} password",
        f"{target} api_key",
        f"{target} secret",
    ]
    results: List[Dict[str, str]] = []

    try:
        async with get_client(timeout=30) as client:
            for q in queries:
                await delay()
                resp = await client.get(
                    "https://api.github.com/search/code",
                    params={"q": q, "per_page": 10},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", [])[:5]:
                        results.append({
                            "repo": item.get("repository", {}).get("full_name", ""),
                            "file": item.get("path", ""),
                            "url": item.get("html_url", ""),
                            "query": q,
                        })
                elif resp.status_code == 403:
                    return {"results": results, "error": "GitHub rate limit hit"}
    except Exception as e:
        return {"results": results, "error": str(e)}

    return {"results": results}


@mcp.tool()
async def osint_recon(target: str, session_id: int = 0) -> dict:
    """Deep OSINT reconnaissance — Wayback Machine, JS file analysis, GitHub dorking.

    Goes beyond basic recon to uncover hidden endpoints, hardcoded secrets in
    JavaScript, and leaked credentials on GitHub.  Runs all three data sources
    in parallel for speed.

    Parameters:
        target:     Domain to investigate (e.g. "example.com").
        session_id: Optional hunt session ID (from define_hunt_goal) to link results.

    Returns a combined dict of all OSINT findings.
    """
    err = validate_required_string(target, "target")
    if err:
        return {"error": err}

    try:
        wayback_task = _wayback_fetch(target)
        js_task = _js_discovery(target)
        github_task = _github_dork(target)

        wayback, js, github = await asyncio.gather(
            wayback_task, js_task, github_task,
            return_exceptions=True,
        )

        # Normalise exceptions into dicts
        if isinstance(wayback, Exception):
            wayback = {"urls": [], "error": str(wayback)}
        if isinstance(js, Exception):
            js = {"endpoints": [], "secrets": [], "error": str(js)}
        if isinstance(github, Exception):
            github = {"results": [], "error": str(github)}

        total_surface = (
            len(wayback.get("urls", []))
            + len(js.get("endpoints", []))
            + len(js.get("secrets", []))
            + len(github.get("results", []))
        )

        result = {
            "target": target,
            "wayback_interesting_urls": wayback.get("urls", []),
            "wayback_total_archived": wayback.get("total_archived", 0),
            "wayback_status": (
                wayback.get("status")
                or ("error" if wayback.get("error") else "success")
            ),
            "js_endpoints": js.get("endpoints", []),
            "js_secrets": js.get("secrets", []),
            "js_files_scanned": js.get("js_files_scanned", 0),
            "github_leaks": github.get("results", []),
            "total_attack_surface": total_surface,
            "errors": {
                k: v
                for k, v in {
                    "wayback": wayback.get("error"),
                    "js": js.get("error"),
                    "github": github.get("error"),
                }.items()
                if v
            },
        }

        # Persist if linked to a hunt session
        if session_id > 0:
            try:
                with db_connection() as conn:
                    conn.execute(
                        "INSERT INTO osint_results (session_id, target, result_type, data) VALUES (?, ?, ?, ?)",
                        (session_id, target, "full_osint", json.dumps(result)),
                    )
            except Exception as db_err:
                logger.warning("Failed to persist OSINT results: %s", db_err)

        return result
    except Exception as e:
        logger.error("osint_recon failed: %s", e)
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 3 — logic_flow_mapper
# ══════════════════════════════════════════════════════════════════════════════

_FLOW_TEST_CASES: Dict[str, List[Dict[str, Any]]] = {
    "payment": [
        {
            "description": "Negative amount manipulation",
            "attack_vector": "Send negative value in amount parameter to reverse payment direction",
            "tools_to_use": ["parameter_tampering_test", "business_logic_price_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Currency confusion (rounding exploitation)",
            "attack_vector": "Manipulate currency code or exploit float rounding in multi-currency conversion",
            "tools_to_use": ["parameter_tampering_test", "business_logic_price_test"],
            "severity_if_found": "High",
        },
        {
            "description": "Race condition on double-spend",
            "attack_vector": "Send multiple identical transfer requests simultaneously to exploit TOCTOU",
            "tools_to_use": ["race_condition_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Skip payment step via direct URL access",
            "attack_vector": "Navigate directly to post-payment confirmation URL bypassing payment gateway",
            "tools_to_use": ["forced_browsing_scan", "access_control_bypass_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Coupon stacking beyond intended limit",
            "attack_vector": "Apply multiple coupon codes or reuse single-use coupon via race condition",
            "tools_to_use": ["race_condition_test", "parameter_tampering_test"],
            "severity_if_found": "High",
        },
        {
            "description": "Refund abuse — refund more than paid amount",
            "attack_vector": "Tamper refund amount parameter or initiate refund on modified order total",
            "tools_to_use": ["parameter_tampering_test", "business_logic_price_test"],
            "severity_if_found": "Critical",
        },
    ],
    "auth": [
        {
            "description": "Password reset token reuse",
            "attack_vector": "Use a consumed password reset token again after password has been changed",
            "tools_to_use": ["password_reset_test", "session_management_check"],
            "severity_if_found": "High",
        },
        {
            "description": "Reset token does not expire",
            "attack_vector": "Use a password reset token after extended time period (hours/days)",
            "tools_to_use": ["password_reset_test"],
            "severity_if_found": "Medium",
        },
        {
            "description": "Username enumeration via timing/response difference",
            "attack_vector": "Compare response time or body between valid and invalid usernames on login/reset",
            "tools_to_use": ["account_enumeration_test", "timing_attack_check"],
            "severity_if_found": "Low",
        },
        {
            "description": "Remember-me token persistence after password change",
            "attack_vector": "Change password and verify that remember-me / persistent sessions are invalidated",
            "tools_to_use": ["session_management_check"],
            "severity_if_found": "Medium",
        },
        {
            "description": "Session not invalidated after logout",
            "attack_vector": "Capture session token, logout, then reuse the token",
            "tools_to_use": ["session_management_check"],
            "severity_if_found": "Medium",
        },
    ],
    "registration": [
        {
            "description": "Email verification bypass",
            "attack_vector": "Access authenticated endpoints before completing email verification step",
            "tools_to_use": ["access_control_bypass_test", "forced_browsing_scan"],
            "severity_if_found": "Medium",
        },
        {
            "description": "Duplicate registration via case variation",
            "attack_vector": "Register User@email.com and user@email.com as separate accounts for same mailbox",
            "tools_to_use": ["account_enumeration_test"],
            "severity_if_found": "Medium",
        },
        {
            "description": "Referral / invite code abuse",
            "attack_vector": "Reuse referral codes or self-refer via multiple registrations",
            "tools_to_use": ["rate_limit_check", "parameter_tampering_test"],
            "severity_if_found": "Medium",
        },
        {
            "description": "Role assignment at registration",
            "attack_vector": "Add role=admin or is_admin=true parameter during registration request",
            "tools_to_use": ["mass_assignment_test", "privilege_escalation_test"],
            "severity_if_found": "Critical",
        },
    ],
    "password_reset": [
        {
            "description": "Token predictability",
            "attack_vector": "Request multiple reset tokens and analyze for sequential or time-based patterns",
            "tools_to_use": ["password_reset_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Host header injection on reset email",
            "attack_vector": "Inject malicious Host header to redirect reset link to attacker-controlled domain",
            "tools_to_use": ["host_header_injection_test", "password_reset_test"],
            "severity_if_found": "High",
        },
        {
            "description": "Token valid for unintended user",
            "attack_vector": "Request reset for user A, use token to reset user B's password",
            "tools_to_use": ["password_reset_test", "idor_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Unlimited reset attempts (no rate limiting)",
            "attack_vector": "Brute-force short reset tokens or OTP codes without lockout",
            "tools_to_use": ["rate_limit_check", "brute_force_protection_check"],
            "severity_if_found": "High",
        },
    ],
    "data_export": [
        {
            "description": "IDOR on export job ID",
            "attack_vector": "Increment or enumerate export job IDs to download other users' exports",
            "tools_to_use": ["idor_test"],
            "severity_if_found": "High",
        },
        {
            "description": "Export data of other users via parameter manipulation",
            "attack_vector": "Modify user_id or tenant_id parameter in export request",
            "tools_to_use": ["idor_test", "parameter_tampering_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Async export result accessible without auth",
            "attack_vector": "Access export download URL directly without authentication cookie",
            "tools_to_use": ["access_control_bypass_test", "forced_browsing_scan"],
            "severity_if_found": "High",
        },
    ],
    "invitation": [
        {
            "description": "Invite link reuse after consumed",
            "attack_vector": "Use an invitation link that was already accepted by the intended recipient",
            "tools_to_use": ["access_control_bypass_test"],
            "severity_if_found": "Medium",
        },
        {
            "description": "Privilege escalation via invite role parameter",
            "attack_vector": "Modify role parameter in invitation request to invite as admin instead of member",
            "tools_to_use": ["privilege_escalation_test", "mass_assignment_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Email takeover via invite to existing user's email",
            "attack_vector": "Send invite to an already-registered email to link attacker's team to victim account",
            "tools_to_use": ["account_enumeration_test", "parameter_tampering_test"],
            "severity_if_found": "High",
        },
    ],
    "coupon": [
        {
            "description": "Negative discount exploitation",
            "attack_vector": "Submit coupon with negative discount value to increase account credit",
            "tools_to_use": ["parameter_tampering_test", "business_logic_price_test"],
            "severity_if_found": "Critical",
        },
        {
            "description": "Coupon applied to ineligible product",
            "attack_vector": "Apply category-specific coupon to excluded product via API parameter manipulation",
            "tools_to_use": ["parameter_tampering_test", "business_logic_price_test"],
            "severity_if_found": "Medium",
        },
        {
            "description": "Race condition on coupon redemption",
            "attack_vector": "Send parallel requests to redeem single-use coupon multiple times",
            "tools_to_use": ["race_condition_test"],
            "severity_if_found": "High",
        },
    ],
}


@mcp.tool()
async def logic_flow_mapper(base_url: str, flow_type: str) -> dict:
    """Map business logic test cases for a specific application flow.

    Instead of blindly scanning, this tool models the business flow and
    generates targeted test cases that a human hunter would think of —
    covering payment, auth, registration, password reset, data export,
    invitation, and coupon flows.

    Parameters:
        base_url:  URL of the feature to analyze (e.g. "https://target.com/checkout").
        flow_type: One of: payment, auth, registration, password_reset, data_export, invitation, coupon.

    Returns a dict with all test cases, each with description, attack vector,
    recommended MCP tools, and expected severity if confirmed.
    """
    for err in (
        validate_url(base_url, "base_url"),
        validate_required_string(flow_type, "flow_type", allow_shell_metachars=True),
    ):
        if err:
            return {"error": err}

    try:
        ft = flow_type.lower().strip()
        if ft not in _FLOW_TEST_CASES:
            available = ", ".join(sorted(_FLOW_TEST_CASES.keys()))
            return {
                "error": f"Unknown flow_type '{flow_type}'. Available: {available}",
            }

        cases = _FLOW_TEST_CASES[ft]
        return {
            "flow_type": ft,
            "base_url": base_url,
            "total_test_cases": len(cases),
            "test_cases": cases,
        }
    except Exception as e:
        logger.error("logic_flow_mapper failed: %s", e)
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 4 — escalation_advisor
# ══════════════════════════════════════════════════════════════════════════════

_ESCALATION_KB: Dict[str, List[Dict[str, Any]]] = {
    "xss": [
        {
            "path": "Self-XSS → Stored XSS via CSRF",
            "steps": [
                "Confirm self-XSS payload executes in own session",
                "Check if the injection point accepts cross-origin POST (no CSRF token)",
                "Craft CSRF page that injects stored XSS payload into victim's account",
            ],
            "potential_impact": "Stored XSS affecting all users who view the injected content",
            "tools_to_use": ["xss_test", "cors_misconfiguration_check"],
            "difficulty": "Medium",
        },
        {
            "path": "Stored XSS → Admin Cookie Theft → Account Takeover",
            "steps": [
                "Confirm stored XSS executes in admin context",
                "Verify cookie is not HttpOnly (can be exfiltrated via document.cookie)",
                "Craft payload to exfiltrate admin session cookie to attacker server",
                "Use stolen cookie to access admin panel",
            ],
            "potential_impact": "Full admin account takeover",
            "tools_to_use": ["xss_test", "cookie_security_check", "session_management_check"],
            "difficulty": "Low",
        },
        {
            "path": "XSS → CSP Bypass via JSONP / trusted CDN",
            "steps": [
                "Check CSP policy for whitelisted domains with JSONP endpoints",
                "Use JSONP callback to execute arbitrary JS within CSP context",
            ],
            "potential_impact": "CSP bypass enabling full XSS exploitation on hardened target",
            "tools_to_use": ["xss_test", "security_headers_check"],
            "difficulty": "High",
        },
        {
            "path": "XSS + postMessage → Cross-Origin Data Steal",
            "steps": [
                "Identify postMessage listeners without origin validation",
                "Use XSS to send crafted postMessage to steal cross-origin data",
            ],
            "potential_impact": "Cross-origin sensitive data exfiltration",
            "tools_to_use": ["xss_test"],
            "difficulty": "High",
        },
    ],
    "idor": [
        {
            "path": "Read IDOR → Write IDOR on same endpoint",
            "steps": [
                "Confirm read access via GET with tampered ID",
                "Change HTTP method to PUT/PATCH/DELETE with same tampered ID",
                "Verify write/delete operation succeeds",
            ],
            "potential_impact": "Data modification or deletion of arbitrary resources",
            "tools_to_use": ["idor_test", "http_methods_check"],
            "difficulty": "Low",
        },
        {
            "path": "IDOR on one resource → Mass enumeration → Data breach",
            "steps": [
                "Confirm IDOR on single resource ID",
                "Script sequential ID enumeration (1, 2, 3, ...)",
                "Calculate total exposed records and data sensitivity",
            ],
            "potential_impact": "Mass PII / financial data exfiltration — potential GDPR violation",
            "tools_to_use": ["idor_test"],
            "difficulty": "Low",
        },
        {
            "path": "IDOR in file download endpoint",
            "steps": [
                "Test IDOR on file/document download by manipulating file ID or path",
                "Check if other users' uploaded files (ID cards, invoices) are accessible",
            ],
            "potential_impact": "Sensitive document exfiltration (PII, financial, medical)",
            "tools_to_use": ["idor_test", "path_traversal_test"],
            "difficulty": "Low",
        },
        {
            "path": "IDOR + PII data → GDPR/compliance angle",
            "steps": [
                "Document what PII fields are exposed (name, email, phone, SSN, etc.)",
                "Map affected user count",
                "Frame as regulatory compliance violation for maximum impact",
            ],
            "potential_impact": "Regulatory fines (GDPR, CCPA, UU PDP) — escalates business impact",
            "tools_to_use": ["idor_test", "check_sensitive_data_exposure"],
            "difficulty": "Low",
        },
    ],
    "ssrf": [
        {
            "path": "External SSRF → Blind SSRF confirmation",
            "steps": [
                "Confirm external SSRF via out-of-band callback (Burp Collaborator / interactsh)",
                "Test if response body is returned (full read SSRF) vs blind",
            ],
            "potential_impact": "Internal network reconnaissance",
            "tools_to_use": ["ssrf_test"],
            "difficulty": "Low",
        },
        {
            "path": "Blind SSRF → Internal port scan",
            "steps": [
                "Use SSRF to probe common internal ports (80, 443, 8080, 8443, 3306, 6379, 27017)",
                "Differentiate open vs closed via response time or error differences",
            ],
            "potential_impact": "Internal service discovery",
            "tools_to_use": ["ssrf_test"],
            "difficulty": "Medium",
        },
        {
            "path": "Internal SSRF → Cloud metadata → IAM takeover",
            "steps": [
                "Probe cloud metadata endpoint: http://169.254.169.254/latest/meta-data/",
                "Attempt IAM credential extraction via /latest/meta-data/iam/security-credentials/",
                "Use extracted credentials for cloud service access",
            ],
            "potential_impact": "Full cloud infrastructure takeover",
            "tools_to_use": ["ssrf_test"],
            "difficulty": "Medium",
        },
        {
            "path": "SSRF → Internal admin panel access",
            "steps": [
                "Use SSRF to access internal admin panel (localhost:8080/admin)",
                "Chain with any admin functionality (user creation, data export)",
            ],
            "potential_impact": "Internal admin access leading to full compromise",
            "tools_to_use": ["ssrf_test", "admin_panel_discovery"],
            "difficulty": "Medium",
        },
    ],
    "open_redirect": [
        {
            "path": "Open redirect → Phishing campaign",
            "steps": [
                "Confirm open redirect on trusted domain",
                "Craft phishing URL using trusted domain as redirect base",
            ],
            "potential_impact": "Credential theft via trusted-domain phishing",
            "tools_to_use": ["xss_test"],
            "difficulty": "Low",
        },
        {
            "path": "Open redirect + OAuth → Token hijacking",
            "steps": [
                "Find open redirect on OAuth redirect_uri whitelisted domain",
                "Modify redirect_uri to chain: legitimate domain → open redirect → attacker",
                "Intercept OAuth authorization code or token",
            ],
            "potential_impact": "OAuth account takeover via token theft",
            "tools_to_use": ["oauth_misconfiguration_check"],
            "difficulty": "Medium",
        },
        {
            "path": "Open redirect on logout → Session fixation",
            "steps": [
                "Chain open redirect in logout flow with session fixation payload",
                "Victim clicks link, gets logged out, redirected to attacker login page",
            ],
            "potential_impact": "Session fixation leading to account compromise",
            "tools_to_use": ["session_management_check"],
            "difficulty": "High",
        },
    ],
    "sqli": [
        {
            "path": "Read SQLi → Credential dump",
            "steps": [
                "Confirm SQL injection with UNION SELECT or boolean-based blind",
                "Extract user table (usernames, password hashes, emails)",
                "Attempt to crack hashes or use for credential stuffing",
            ],
            "potential_impact": "Mass credential theft — all user accounts compromised",
            "tools_to_use": ["sqli_test", "detect_weak_hashing"],
            "difficulty": "Low",
        },
        {
            "path": "Write SQLi → Insert admin user",
            "steps": [
                "Confirm INSERT/UPDATE capability via stacked queries or INSERT injection",
                "Insert new admin-level user into users table",
                "Login with created admin credentials",
            ],
            "potential_impact": "Persistent admin access via injected user",
            "tools_to_use": ["sqli_test", "privilege_escalation_test"],
            "difficulty": "Medium",
        },
        {
            "path": "SQLi → File read (LOAD_FILE) → Source code disclosure",
            "steps": [
                "Test LOAD_FILE() or similar file-read function via SQLi",
                "Read application source code, configuration files, /etc/passwd",
            ],
            "potential_impact": "Source code disclosure, credential file access, LFI upgrade",
            "tools_to_use": ["sqli_test", "path_traversal_test"],
            "difficulty": "Medium",
        },
        {
            "path": "SQLi → File write → Webshell",
            "steps": [
                "Test INTO OUTFILE or INTO DUMPFILE for file write capability",
                "Write webshell to web-accessible directory",
                "Access webshell for RCE",
            ],
            "potential_impact": "Remote code execution via webshell",
            "tools_to_use": ["sqli_test", "command_injection_test"],
            "difficulty": "High",
        },
    ],
    "info_disclosure": [
        {
            "path": "Stack trace → Tech stack identification → Targeted CVE search",
            "steps": [
                "Extract framework, language version, library versions from stack trace",
                "Search for known CVEs matching the exact versions",
                "Attempt exploitation of discovered CVEs",
            ],
            "potential_impact": "Exploitation of known vulnerability in identified component",
            "tools_to_use": ["error_disclosure_check", "detect_vulnerable_js_libs", "searchsploit_query"],
            "difficulty": "Medium",
        },
        {
            "path": "Debug endpoint → Internal IP disclosure → SSRF target",
            "steps": [
                "Extract internal IPs/hostnames from debug output",
                "Use discovered internal addresses as SSRF targets",
            ],
            "potential_impact": "Internal network mapping enabling further SSRF exploitation",
            "tools_to_use": ["check_debug_endpoints", "ssrf_test"],
            "difficulty": "Medium",
        },
        {
            "path": "Backup file → Source code → Logic flaw discovery",
            "steps": [
                "Access backup/config files (.bak, .sql, .env, .git)",
                "Analyze source code for hardcoded credentials, logic flaws, hidden endpoints",
            ],
            "potential_impact": "Source code disclosure leading to targeted attacks",
            "tools_to_use": ["exposed_files_check", "check_sensitive_data_exposure"],
            "difficulty": "Low",
        },
    ],
    "csrf": [
        {
            "path": "CSRF on state change → Account modification",
            "steps": [
                "Confirm CSRF on email/password change or profile update endpoint",
                "Craft auto-submitting HTML form hosted on attacker domain",
                "Victim visits page → account email changed → attacker resets password",
            ],
            "potential_impact": "Account takeover via email change + password reset",
            "tools_to_use": ["cors_misconfiguration_check", "session_management_check"],
            "difficulty": "Low",
        },
        {
            "path": "CSRF + Self-XSS → Stored XSS",
            "steps": [
                "Combine CSRF (no token on profile update) with self-XSS injection point",
                "CSRF auto-injects XSS payload into victim's profile, making it stored",
            ],
            "potential_impact": "Self-XSS upgraded to stored XSS via CSRF chain",
            "tools_to_use": ["xss_test", "cors_misconfiguration_check"],
            "difficulty": "Medium",
        },
    ],
    "xxe": [
        {
            "path": "XXE → Local file read (LFI)",
            "steps": [
                "Inject external entity referencing file:///etc/passwd",
                "Verify file contents returned in response or error",
            ],
            "potential_impact": "Arbitrary file read on server",
            "tools_to_use": ["xxe_test", "path_traversal_test"],
            "difficulty": "Low",
        },
        {
            "path": "XXE → SSRF → Internal network access",
            "steps": [
                "Use XXE entity to make HTTP requests to internal services",
                "Probe metadata endpoints or internal APIs",
            ],
            "potential_impact": "Internal service access, potential cloud credential theft",
            "tools_to_use": ["xxe_test", "ssrf_test"],
            "difficulty": "Medium",
        },
        {
            "path": "Blind XXE → Out-of-band data exfiltration",
            "steps": [
                "Use parameter entity with external DTD for OOB exfiltration",
                "Exfiltrate file contents via DNS or HTTP callback",
            ],
            "potential_impact": "Data exfiltration even without direct response reflection",
            "tools_to_use": ["xxe_test"],
            "difficulty": "High",
        },
    ],
    "rce": [
        {
            "path": "RCE → Persistent backdoor",
            "steps": [
                "Confirm command execution via id/whoami/hostname",
                "Establish reverse shell or create SSH key for persistence",
                "Document full impact: file system access, data access, lateral movement",
            ],
            "potential_impact": "Full server compromise with persistent access",
            "tools_to_use": ["command_injection_test"],
            "difficulty": "Low",
        },
        {
            "path": "RCE → Lateral movement → Infrastructure compromise",
            "steps": [
                "Enumerate internal network from compromised host",
                "Access cloud metadata for additional credentials",
                "Pivot to database servers or internal services",
            ],
            "potential_impact": "Full infrastructure compromise from single entry point",
            "tools_to_use": ["command_injection_test", "ssrf_test"],
            "difficulty": "High",
        },
    ],
    "lfi": [
        {
            "path": "LFI → Source code read → Credential discovery",
            "steps": [
                "Read application config files (config.php, .env, settings.py)",
                "Extract database credentials, API keys, secret keys",
            ],
            "potential_impact": "Credential disclosure enabling database or API access",
            "tools_to_use": ["path_traversal_test", "exposed_files_check"],
            "difficulty": "Low",
        },
        {
            "path": "LFI → Log poisoning → RCE",
            "steps": [
                "Inject PHP/code payload into access log via User-Agent or URL",
                "Include poisoned log file via LFI to execute injected code",
            ],
            "potential_impact": "Remote code execution via log poisoning",
            "tools_to_use": ["path_traversal_test", "command_injection_test"],
            "difficulty": "High",
        },
        {
            "path": "LFI → /proc/self/environ → RCE",
            "steps": [
                "Include /proc/self/environ via LFI",
                "Inject payload via HTTP headers (User-Agent) stored in environ",
            ],
            "potential_impact": "Remote code execution via environment variable injection",
            "tools_to_use": ["path_traversal_test", "command_injection_test"],
            "difficulty": "High",
        },
    ],
}


@mcp.tool()
async def escalation_advisor(
    finding_type: str,
    current_impact: str,
    target_context: str = "",
) -> dict:
    """Advise on how to escalate a confirmed finding for maximum impact.

    For every confirmed vulnerability, this tool provides concrete escalation
    paths — chains, impact upgrades, and sibling endpoint checks — so you
    never stop at the first finding when a Critical is hiding one step away.

    Parameters:
        finding_type:   One of: xss, sqli, idor, ssrf, open_redirect, info_disclosure, csrf, xxe, rce, lfi.
        current_impact: Brief description of current finding impact.
        target_context: Optional context (e.g. "fintech", "ecommerce") for prioritisation hints.

    Returns escalation paths with steps, tools, difficulty, and potential impact.
    """
    for err in (
        validate_required_string(finding_type, "finding_type", allow_shell_metachars=True),
        validate_required_string(current_impact, "current_impact"),
    ):
        if err:
            return {"error": err}
    # target_context is optional — only validate if provided
    if target_context:
        err = validate_required_string(target_context, "target_context")
        if err:
            return {"error": err}

    try:
        ft = finding_type.lower().strip()
        if ft not in _ESCALATION_KB:
            available = ", ".join(sorted(_ESCALATION_KB.keys()))
            return {
                "error": f"Unknown finding_type '{finding_type}'. Available: {available}",
            }

        paths = _ESCALATION_KB[ft]

        # Add context-specific hints if provided
        context_hints = []
        ctx = target_context.lower()
        if ctx:
            if "fintech" in ctx:
                context_hints = [
                    "In fintech: any data access bug may expose financial PII — frame as regulatory violation (PCI-DSS, OJK)",
                    "In fintech: any write bug on transaction endpoints = financial fraud potential → always Critical",
                ]
            elif "ecommerce" in ctx:
                context_hints = [
                    "In ecommerce: any price/discount manipulation = direct financial loss → Critical",
                    "In ecommerce: order/refund IDOR = fraud enablement → High minimum",
                ]
            elif "saas" in ctx:
                context_hints = [
                    "In SaaS: any cross-tenant access = data breach across organizations → Critical",
                    "In SaaS: privilege escalation member→admin = full org compromise → Critical",
                ]
            elif "health" in ctx:
                context_hints = [
                    "In healthtech: any patient data exposure = HIPAA violation → Critical",
                    "In healthtech: prescription/medical record tampering = patient safety issue → Critical",
                ]

        return {
            "finding_type": ft,
            "current_impact": current_impact,
            "target_context": target_context or "not specified",
            "escalation_paths": paths,
            "total_escalation_paths": len(paths),
            "context_hints": context_hints,
            "reminder": (
                "Do NOT save the finding yet — try at least one escalation path first. "
                "Save via save_finding_tool only after escalation is maxed out or confirmed dead end."
            ),
        }
    except Exception as e:
        logger.error("escalation_advisor failed: %s", e)
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# TOOL 5 — hidden_endpoint_discovery
# ══════════════════════════════════════════════════════════════════════════════

_UNIVERSAL_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/config", "/.env", "/backup.sql",
    "/api/v1/", "/api/v2/", "/api/internal/", "/admin/", "/superadmin/",
    "/debug/", "/test/", "/staging/", "/health", "/status", "/metrics",
    "/swagger.json", "/openapi.json", "/graphql", "/changelog",
    "/.well-known/security.txt", "/wp-login.php", "/elmah.axd",
    "/server-status", "/server-info", "/.htaccess", "/web.config",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/phpinfo.php",
    "/info.php", "/.DS_Store", "/config.json", "/package.json",
    "/composer.json", "/Gemfile", "/requirements.txt",
]

_FRAMEWORK_PATHS: Dict[str, List[str]] = {
    "laravel": [
        "/.env", "/storage/logs/laravel.log", "/telescope", "/horizon",
        "/_debugbar/open", "/api/docs", "/nova", "/vapor",
    ],
    "django": [
        "/admin/", "/django-admin/", "/__debug__/", "/api/schema/",
        "/api/docs/", "/silk/", "/media/", "/static/admin/",
    ],
    "rails": [
        "/rails/info/properties", "/rails/info/routes", "/rails/mailers",
        "/__better_errors", "/sidekiq", "/letter_opener",
    ],
    "spring": [
        "/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/health",
        "/actuator/info", "/actuator/beans", "/actuator/mappings",
        "/actuator/configprops", "/h2-console", "/swagger-ui.html",
        "/v2/api-docs", "/v3/api-docs",
    ],
    "express": [
        "/graphql", "/graphiql", "/__apollo", "/swagger", "/api-docs",
        "/swagger-ui/", "/.env", "/npm-debug.log",
    ],
    "node": [
        "/graphql", "/graphiql", "/__apollo", "/swagger", "/api-docs",
        "/swagger-ui/", "/.env", "/npm-debug.log",
    ],
    "flask": [
        "/console", "/debugger", "/api/spec", "/apidocs",
        "/swagger.json", "/flasgger/",
    ],
    "nextjs": [
        "/_next/data/", "/api/", "/_next/static/", "/404",
        "/_error", "/api/auth/",
    ],
    "wordpress": [
        "/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts", "/xmlrpc.php", "/wp-content/debug.log",
        "/wp-includes/", "/wp-config.php.bak",
    ],
    "php": [
        "/phpinfo.php", "/info.php", "/adminer.php", "/phpmyadmin/",
        "/.env", "/config.php.bak", "/debug.php",
    ],
}

_SENSITIVE_KEYWORDS = re.compile(
    r"(password|secret|token|api.?key|database|internal|admin|debug|"
    r"stack.?trace|exception|error|config|credential|private)",
    re.IGNORECASE,
)


@mcp.tool()
async def hidden_endpoint_discovery(base_url: str, context: str = "") -> dict:
    """Context-aware hidden endpoint discovery — NOT a dumb wordlist brute-force.

    Uses knowledge of specific frameworks (Laravel, Django, Rails, Spring,
    Express, Flask, Next.js, WordPress) to probe endpoints that are commonly
    left exposed by developers.  Always checks a universal baseline set too.

    Parameters:
        base_url: Target base URL (e.g. "https://target.com").
        context:  Known tech stack, comma-separated (e.g. "laravel,php" or "spring,java").
                  If empty, only universal paths are checked.

    Returns interesting endpoints (status 200/301/302/403, non-empty body,
    or sensitive keywords in response) — 403 is flagged because something IS
    there even if access is denied.
    """
    err = validate_url(base_url, "base_url")
    if err:
        return {"error": err}
    if context:
        err = validate_required_string(context, "context")
        if err:
            return {"error": err}

    try:
        # Normalise base URL
        base = base_url.rstrip("/")
        if not base.startswith("http"):
            base = f"https://{base}"

        # Build path list
        paths_to_check = list(_UNIVERSAL_PATHS)
        ctx_lower = context.lower()
        for framework, framework_paths in _FRAMEWORK_PATHS.items():
            if framework in ctx_lower:
                for p in framework_paths:
                    if p not in paths_to_check:
                        paths_to_check.append(p)

        # De-duplicate while preserving order
        seen = set()
        unique_paths = []
        for p in paths_to_check:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)

        interesting: List[Dict[str, Any]] = []
        checked = 0
        errors = 0

        async with get_client(timeout=15, follow_redirects=False) as client:
            # Process in batches to respect rate limiting
            batch_size = 5
            for i in range(0, len(unique_paths), batch_size):
                batch = unique_paths[i : i + batch_size]
                tasks = []
                for path in batch:
                    url = f"{base}{path}"
                    tasks.append(_probe_endpoint(client, url, path))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    checked += 1
                    if isinstance(result, Exception):
                        errors += 1
                        continue
                    if result is not None:
                        interesting.append(result)

                await delay()

        return {
            "base_url": base,
            "context": context or "none (universal paths only)",
            "total_checked": checked,
            "total_interesting": len(interesting),
            "errors": errors,
            "interesting": interesting,
        }
    except Exception as e:
        logger.error("hidden_endpoint_discovery failed: %s", e)
        return {"error": str(e)}


async def _probe_endpoint(
    client,
    url: str,
    path: str,
) -> Optional[Dict[str, Any]]:
    """Probe a single endpoint and return info if interesting, else None."""
    try:
        resp = await client.get(url)
        status = resp.status_code
        content_length = len(resp.content)
        body_snippet = resp.text[:500]

        reasons = []

        # 403 is interesting — something exists but is blocked
        if status == 403:
            reasons.append("403 Forbidden — endpoint exists but access denied")
        elif status in (200, 301, 302):
            if content_length > 0:
                reasons.append(f"HTTP {status} with {content_length} bytes")
            if _SENSITIVE_KEYWORDS.search(body_snippet):
                matches = _SENSITIVE_KEYWORDS.findall(body_snippet)
                reasons.append(f"Sensitive keywords in response: {', '.join(set(matches)[:5])}")

        if reasons:
            return {
                "url": url,
                "path": path,
                "status": status,
                "content_length": content_length,
                "reason": " | ".join(reasons),
            }
        return None
    except Exception:
        return None
