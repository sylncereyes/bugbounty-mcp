import re
import asyncio
from mcp_instance import mcp
from tools.db import save_finding
from tools.db import is_in_scope
from tools.http_utils import secure_request, get_client, delay
import logging
logger = logging.getLogger("agy")

@mcp.tool()
async def idor_test(url: str, id_param: str, test_ids: list, target_id: int, method: str = "GET", headers: dict = None, cookies: str = None) -> dict:
    """
    Tests IDOR by cycling through test_ids, replacing {id} in URL or appending as param.
    """
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    if headers is None:
        headers = {}
    if cookies:
        headers["Cookie"] = cookies

    findings = []
    vulnerable = False
    
    async with get_client(follow_redirects=True) as client:
        # Establish baseline using an invalid ID to avoid false positives on public resources
        baseline_status = None
        try:
            baseline_url = url
            baseline_params = {}
            if "{id}" in url:
                baseline_url = url.replace("{id}", "99999999")
            else:
                baseline_params[id_param] = "99999999"

            if method.upper() == "GET":
                res_base = await secure_request(client, "GET", baseline_url, target_id=target_id, headers=headers, params=baseline_params)
            elif method.upper() == "POST":
                res_base = await secure_request(client, "POST", baseline_url, target_id=target_id, headers=headers, data={id_param: "99999999"})
            else:
                res_base = await secure_request(client, method, baseline_url, target_id=target_id, headers=headers, params=baseline_params)
            baseline_status = res_base.status_code
        except Exception:
            pass

        for tid in test_ids:
            await delay()
            # Replace {id} in url if present, else append as query param
            current_url = url
            params = {}
            if "{id}" in url:
                current_url = url.replace("{id}", str(tid))
            else:
                params[id_param] = str(tid)

            try:
                if method.upper() == "GET":
                    res = await secure_request(client, "GET", current_url, target_id=target_id, headers=headers, params=params)
                elif method.upper() == "POST":
                    res = await secure_request(client, "POST", current_url, target_id=target_id, headers=headers, data={id_param: str(tid)})
                else:
                    res = await secure_request(client, method, current_url, target_id=target_id, headers=headers, params=params)

                if baseline_status is not None:
                    suspicious = res.status_code == 200 and baseline_status != 200 and len(res.text) > 100
                else:
                    suspicious = res.status_code == 200 and len(res.text) > 100
                findings.append({
                    "id": tid,
                    "status_code": res.status_code,
                    "response_size": len(res.text),
                    "suspicious": suspicious
                })
                if suspicious:
                    vulnerable = True
            except Exception as e:
                logger.debug("IDOR test request failed for id %s: %s", tid, e)
                findings.append({
                    "id": tid,
                    "error": str(e),
                    "suspicious": False
                })

    if vulnerable:
        save_finding(
            target_id=target_id,
            title=f"Potential IDOR on parameter {id_param}",
            vulnerability_type="IDOR",
            owasp_category="A01:2025 - Broken Access Control",
            severity="High",
            url=url,
            parameter=id_param,
            description="Cycling through ID values led to successful responses indicating missing access controls.",
            evidence=str(findings)
        )

    return {
        "vulnerable": vulnerable,
        "findings": findings,
        "summary": f"Tested {len(test_ids)} IDs. Vulnerable: {vulnerable}"
    }

@mcp.tool()
async def cors_misconfiguration_check(url: str, target_id: int) -> dict:
    """
    Tests CORS configuration by sending requests with custom Origin headers.
    """
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    test_origins = ["http://evil.com", "null", "http://localhost"]
    findings = []
    vulnerable = False
    severity = "Low"

    async with get_client() as client:
        for origin in test_origins:
            await delay()
            headers = {"Origin": origin}
            try:
                res = await secure_request(client, "OPTIONS", url, target_id=target_id, headers=headers)
                # Fallback to GET if OPTIONS not allowed
                if res.status_code == 405 or res.status_code == 404:
                    res = await secure_request(client, "GET", url, target_id=target_id, headers=headers)
                
                acao = res.headers.get("Access-Control-Allow-Origin", "")
                acac = res.headers.get("Access-Control-Allow-Credentials", "")
                
                if acao == origin and acac.lower() == "true":
                    vulnerable = True
                    severity = "High"
                    findings.append({"origin": origin, "issue": "Arbitrary Origin Reflected with Credentials Allowed"})
                elif acao == "*" and acac.lower() == "true":
                    vulnerable = True
                    severity = "Medium"
                    findings.append({"origin": origin, "issue": "Wildcard Allowed with Credentials Allowed"})
                elif acao == origin:
                    findings.append({"origin": origin, "issue": "Arbitrary Origin Reflected (No Credentials)"})
            except Exception as e:
                logger.debug("CORS check failed for origin %s: %s", origin, e)

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="CORS Misconfiguration",
            vulnerability_type="CORS Misconfiguration",
            owasp_category="A01:2025 - Broken Access Control",
            severity=severity,
            url=url,
            description="The server allows insecure CORS configurations which could lead to cross-origin data exposure.",
            evidence=str(findings)
        )

    return {
        "vulnerable": vulnerable,
        "severity": severity,
        "findings": findings
    }

@mcp.tool()
async def path_traversal_test(url: str, param: str, target_id: int) -> dict:
    """
    Tests for path traversal vulnerabilities by injecting common payloads.
    """
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    successful_payloads = []
    vulnerable = False

    async with get_client() as client:
        for payload in payloads:
            await delay()
            params = {param: payload}
            try:
                res = await secure_request(client, "GET", url, target_id=target_id, params=params)
                if "root:x:" in res.text or "[extensions]" in res.text or "[fonts]" in res.text:
                    vulnerable = True
                    successful_payloads.append(payload)
            except Exception as e:
                logger.debug("Path traversal request failed: %s", e)

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Path Traversal Vulnerability",
            vulnerability_type="Path Traversal",
            owasp_category="A01:2025 - Broken Access Control",
            severity="High",
            url=url,
            parameter=param,
            payload=str(successful_payloads),
            description="The application is vulnerable to Path Traversal, allowing files to be read from the filesystem.",
            evidence=f"Payloads successful: {successful_payloads}"
        )

    return {
        "vulnerable": vulnerable,
        "payloads_tested": len(payloads),
        "successful_payloads": successful_payloads,
        "severity": "High" if vulnerable else "None"
    }

@mcp.tool()
async def http_methods_check(url: str, target_id: int) -> dict:
    """
    Checks what HTTP methods are supported by the target endpoint.
    """
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "HEAD"]
    allowed = []
    dangerous = []
    vulnerable = False

    async with get_client() as client:
        for m in methods:
            await delay()
            try:
                res = await secure_request(client, m, url, target_id=target_id)
                if res.status_code < 400:
                    allowed.append(m)
                    if m in ["TRACE", "PUT", "DELETE"]:
                        dangerous.append(m)
                        vulnerable = True
            except Exception as e:
                logger.debug("HTTP method %s check failed: %s", m, e)

    if vulnerable:
        save_finding(
            target_id=target_id,
            title=f"Insecure HTTP Method Allowed: {','.join(dangerous)}",
            vulnerability_type="Insecure HTTP Methods",
            owasp_category="A01:2025 - Broken Access Control",
            severity="Medium",
            url=url,
            description=f"The endpoint supports potentially insecure HTTP methods: {dangerous}",
            evidence=f"Allowed dangerous methods: {dangerous}"
        )

    return {
        "allowed_methods": allowed,
        "dangerous_methods": dangerous,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def forced_browsing_scan(base_url: str, target_id: int, wordlist_type: str = "common") -> dict:
    """
    Scans for predictable resource locations. Wordlist types: common, admin, backup, api.
    """
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    wordlists = {
        "common": ["/admin", "/dashboard", "/api/v1", "/swagger", "/metrics", "/health", "/console"],
        "admin": ["/admin/login", "/administrator", "/admin.php", "/manage", "/panel", "/control"],
        "backup": ["/backup.zip", "/backup.sql", "/.env", "/config.bak", "/db.sql"],
        "api": ["/api/v1/users", "/api/v2/admin", "/graphql", "/v1", "/v2"]
    }

    paths = wordlists.get(wordlist_type, wordlists["common"])
    accessible = []
    interesting = []

    async with get_client(follow_redirects=False) as client:
        for p in paths:
            await delay()
            target = base_url.rstrip("/") + p
            try:
                res = await secure_request(client, "GET", target, target_id=target_id)
                if res.status_code in [200, 301, 302, 401, 403]:
                    item = {
                        "path": p,
                        "status_code": res.status_code,
                        "content_length": len(res.text)
                    }
                    accessible.append(item)
                    if res.status_code == 200:
                        interesting.append(item)
            except Exception as e:
                logger.debug("Forced browsing request failed for %s: %s", p, e)

    if interesting:
        save_finding(
            target_id=target_id,
            title="Exposed files or sensitive endpoints",
            vulnerability_type="Forced Browsing",
            owasp_category="A01:2025 - Broken Access Control",
            severity="Medium",
            url=base_url,
            description="Exposed panels or files found via forced browsing.",
            evidence=str(interesting)
        )

    return {
        "accessible_paths": accessible,
        "total_checked": len(paths),
        "interesting": interesting
    }

@mcp.tool()
async def access_control_bypass_test(url: str, target_id: int, bypass_header: str = None) -> dict:
    """
    Tests if access control can be bypassed using headers like X-Original-URL.
    """
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    headers_to_test = {
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Forwarded-For": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1"
    }
    if bypass_header:
        headers_to_test = {bypass_header: "127.0.0.1"}

    bypassed = False
    successful_bypasses = []

    async with get_client() as client:
        # Get baseline response without bypass headers
        try:
            baseline = await secure_request(client, "GET", url, target_id=target_id)
            baseline_status = baseline.status_code
            baseline_body = baseline.text[:500]
        except Exception as e:
            return {"error": f"Baseline request failed: {str(e)}", "bypassed": False}

        for h_name, h_val in headers_to_test.items():
            await delay()
            try:
                res = await secure_request(client, "GET", url, target_id=target_id, headers={h_name: h_val})
                # Only flag bypass if baseline was blocked but bypass succeeded
                if baseline_status in [401, 403] and res.status_code == 200 and "unauthorized" not in res.text.lower():
                    bypassed = True
                    successful_bypasses.append(h_name)
                elif res.status_code == 200 and baseline_status == 200 and res.text[:500] != baseline_body:
                    # Different content with bypass header might indicate bypass
                    bypassed = True
                    successful_bypasses.append(h_name)
            except Exception as e:
                logger.debug("Access control bypass request failed: %s", e)

    if bypassed:
        save_finding(
            target_id=target_id,
            title="Access Control Bypass via Headers",
            vulnerability_type="Access Control Bypass",
            owasp_category="A01:2025 - Broken Access Control",
            severity="High",
            url=url,
            description=f"Access control can be bypassed by providing headers: {successful_bypasses}",
            evidence=str(successful_bypasses)
        )

    return {
        "bypassed": bypassed,
        "successful_bypasses": successful_bypasses,
        "details": f"Headers successful: {successful_bypasses}"
    }

@mcp.tool()
async def privilege_escalation_test(url: str, low_priv_cookie: str, high_priv_endpoint: str, target_id: int) -> dict:
    """
    Checks if high-privilege endpoints can be accessed with low-privilege cookies.
    """
    if not is_in_scope(target_id, high_priv_endpoint):
        return {"error": f"URL {high_priv_endpoint} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    headers = {
        "Cookie": low_priv_cookie
    }
    escalated = False
    async with get_client() as client:
        # Baseline: check if endpoint is publicly accessible without any authentication
        try:
            public_res = await secure_request(client, "GET", high_priv_endpoint, target_id=target_id)
            if public_res.status_code == 200 and "access denied" not in public_res.text.lower():
                # Endpoint is publicly accessible, not a privilege escalation issue
                return {
                    "escalated": False,
                    "severity": "None",
                    "note": "Endpoint is publicly accessible without authentication. Not a privilege escalation finding."
                }
        except Exception as e:
            logger.debug("Public baseline request failed: %s", e)

        try:
            res = await secure_request(client, "GET", high_priv_endpoint, target_id=target_id, headers=headers)
            if res.status_code == 200 and "access denied" not in res.text.lower():
                escalated = True
        except Exception as e:
            logger.debug("Privilege escalation request failed: %s", e)

    if escalated:
        save_finding(
            target_id=target_id,
            title="Privilege Escalation Vulnerability",
            vulnerability_type="Privilege Escalation",
            owasp_category="A01:2025 - Broken Access Control",
            severity="High",
            url=high_priv_endpoint,
            description="The low privilege user was able to access a high privilege endpoint successfully.",
            evidence=f"Low priv cookie: {low_priv_cookie}"
        )

    return {
        "escalated": escalated,
        "severity": "High" if escalated else "None"
    }
