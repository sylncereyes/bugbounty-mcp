"""
AGY Bug Bounty MCP - Hunter Mindset Tools
Tools that fill the gap between automated OWASP scanning and real bug bounty
hunter intuition: business-logic modeling, deep OSINT, finding escalation,
and context-aware hidden-endpoint discovery.

Every tool follows project conventions:
  • Registered via @mcp.tool() on the shared FastMCP instance.
  • Returns a plain dict (JSON-serialisable).
  • HTTP via tools.http_utils.get_async_client() (honours VERIFY_SSL, timeout, UA).
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
from tools.http_utils import get_async_client as get_client, delay
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

# ──────────────────────────────────────────────────────────────────────────────
# KNOWLEDGE BASES  (pure data — no network calls)
# ──────────────────────────────────────────────────────────────────────────────

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

# ═══════════════════════════════════════════════════════════════════════════════════
# TOOL 1 — define_hunt_goal
# ══════════════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════════════
# TOOL 2 — osint_recon
# ══════════════════════════════════════════════════════════════════════════════════

_INTERESTING_KEYWORDS = re.compile(
    r"(admin|api|internal|debug|staging|backup|test|old|v1|v2|"
    r"export|download|webhook|callback|graphql|swagger|config|"
    r"secret|token|dashboard|console|portal|manage)",
    re.IGNORECASE,
)

_JS_SECRET_PATTERNS = [
    re.compile(r'''(['"])(/api/[^\s'"]+)\1'''),
    re.compile(r'''(['"])(/v[12]/[^\s'"]+)\1'''),
    re.compile(r'''(['"])(/internal/[^\s'"]+)\1'''),
    re.compile(r'''(['"])(/graphql[^\s'"]*)\1'''),
    re.compile(r'''(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*['"]([^'"]{8,})['"]''', re.IGNORECASE),
]

_WAYBACK_TIMEOUT = 10.0  # Wayback CDX API is often slow; cap the wait

async def _wayback_fetch(target: str, target_id: int) -> Dict[str, Any]:
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
                resp = await secure_request(
                    client, "GET", url, target_id
                )
                if resp.status_code != 200:
                    status_msg = f"Wayback returned {resp.status_code}"
                    return {"urls": [], "error": status_msg}
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

async def _js_discovery(target: str, target_id: int) -> Dict[str, Any]:
    """Discover JS files from homepage, grep for endpoints & secrets."""
    endpoints: List[str] = []
    secrets: List[Dict[str, str]] = []
    js_files_found: List[str] = []

    try:
        async with get_client(timeout=30, follow_redirects=True) as client:
            resp = await secure_request(
                client, "GET", f"https://{target}", target_id
            )
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
                    js_resp = await secure_request(
                        client, "GET", src, target_id
                    )
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

async def _github_dork(target: str, target_id: int) -> Dict[str, Any]:
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
                resp = await secure_request(
                    client, "GET",
                    "https://api.github.com/search/code",
                    target_id,
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
async def osint_recon(target: str, target_id: int, session_id: int = 0) -> dict:
    """Deep OSINT reconnaissance — Wayback Machine, JS file analysis, GitHub dorking.

    Goes beyond basic recon to uncover hidden endpoints, hardcoded secrets in
    JavaScript, and leaked credentials on GitHub.  Runs all three data sources
    in parallel for speed.

    Parameters:
        target:     Domain to investigate (e.g. "example.com").
        target_id:  The ID of the target in the database (for scope validation).
        session_id: Optional hunt session ID (from define_hunt_goal) to link results.
    """
    if not is_in_scope(target_id, target):
        return {"error": f"Target {target} is out of scope for target {target_id}. Scan aborted."}

    # Validate target
    for err in (validate_required_string(target, "target"),):
        if err:
            return {"error": err}

    # Run the three OSINT sources in parallel
    wayback_task = asyncio.create_task(_wayback_fetch(target, target_id))
    js_task = asyncio.create_task(_js_discovery(target, target_id))
    github_task = asyncio.create_task(_github_dork(target, target_id))

    wayback_result, js_result, github_result = await asyncio.gather(
        wayback_task, js_task, github_task, return_exceptions=True
    )

    # Handle exceptions from tasks
    if isinstance(wayback_result, Exception):
        wayback_result = {"urls": [], "error": str(wayback_result)}
    if isinstance(js_result, Exception):
        js_result = {"endpoints": [], "secrets": [], "error": str(js_result)}
    if isinstance(github_result, Exception):
        github_result = {"results": [], "error": str(github_result)}

    # Save results to database if session_id provided
    if session_id:
        with db_connection() as conn:
            cursor = conn.cursor()
            if wayback_result.get("urls"):
                cursor.execute(
                    "INSERT INTO osint_results (session_id, target, result_type, data) VALUES (?, ?, ?, ?)",
                    (session_id, target, "wayback", json.dumps(wayback_result)),
                )
            if js_result.get("endpoints") or js_result.get("secrets"):
                cursor.execute(
                    "INSERT INTO osint_results (session_id, target, result_type, data) VALUES (?, ?, ?, ?)",
                    (session_id, target, "js_discovery", json.dumps(js_result)),
                )
            if github_result.get("results"):
                cursor.execute(
                    "INSERT INTO osint_results (session_id, target, result_type, data) VALUES (?, ?, ?, ?)",
                    (session_id, target, "github_dork", json.dumps(github_result)),
                )
            conn.commit()

    return {
        "target": target,
        "wayback": wayback_result,
        "js_discovery": js_result,
        "github_dork": github_result,
    }

# ═══════════════════════════════════════════════════════════════════════════════════
# TOOL 3 — hunt_suggestion (example of a helper that uses OSINT results)
# ══════════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def hunt_suggestion(session_id: int) -> dict:
    """Suggest next steps based on OSINT results from a hunt session."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT target, result_type, data FROM osint_results WHERE session_id = ?",
            (session_id,),
        )
        rows = cursor.fetchall()

    if not rows:
        return {"error": f"No OSINT results found for session {session_id}"}

    # Parse and analyse results to suggest promising vectors
    suggestions = []
    for _target, result_type, data_json in rows:
        data = json.loads(data_json)
        if result_type == "wayback" and data.get("urls"):
            urls = data["urls"][:5]
            suggestions.append(f"Investigate Wayback URLs: {', '.join(urls)}")
        elif result_type == "js_discovery":
            endpoints = data.get("endpoints", [])
            secrets = data.get("secrets", [])
            if endpoints:
                suggestions.append(f"Test JS-discovered endpoints: {', '.join(endpoints[:3])}")
            if secrets:
                # Extract unique secret types
                secret_types = list(set(s["type"] for s in secrets))
                suggestions.append(f"Investigate leaked secrets: {', '.join(sorted(set(s['type'] for s in [s for s in secrets])))}")
        elif result_type == "github_dork" and data.get("results"):
            leaks = data["results"][:3]
            for leak in leaks:
                suggestions.append(f"Review GitHub leak: {leak['file']} in {leak['repo']}")

    if not suggestions:
        return {"message": "No specific suggestions from OSINT data"}

    return {
        "session_id": session_id,
        "suggestions": suggestions,
    }