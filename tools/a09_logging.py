import re
from mcp_instance import mcp
from tools.db import save_finding, is_in_scope
from tools.http_utils import secure_request, get_client, delay
import logging
logger = logging.getLogger("agy")



@mcp.tool()
async def log_injection_test(url: str, target_id: int, params: dict = None) -> dict:
    """Checks for log injection by feeding CRLF characters in inputs."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        "admin\r\nINFO: Successful login",
        "test%0d%0aINFO: Login bypassed"
    ]
    vulnerable = False
    injectable = []
    
    async with get_client() as client:
        for p_name, p_val in (params or {"q": "search"}).items():
            for p in payloads:
                test_params = (params or {"q": "search"}).copy()
                test_params[p_name] = p
                try:
                    res = await secure_request(client, "GET", url, target_id=target_id, params=test_params)
                    # Log injection is verified by checking server log files.
                    # Since we can't read internal logs directly, we flag reflection as a potential risk.
                    if p in res.text:
                        vulnerable = True
                        injectable.append(p_name)
                        break
                except Exception as e:
                    logger.debug("Error testing log injection param %s at %s: %s", p_name, url, e)
                await delay()

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Potential Log Injection",
            vulnerability_type="Log Injection",
            owasp_category="A09:2025 - Security Logging and Alerting Failures",
            severity="Low",
            url=url,
            description="The application does not filter CRLF characters, allowing potential injection in application logs.",
            evidence=str(injectable)
        )

    return {
        "vulnerable": vulnerable,
        "injectable_params": injectable,
        "payloads_tested": payloads,
        "evidence": f"Reflected parameters: {injectable}"
    }

@mcp.tool()
async def error_disclosure_check(url: str, target_id: int, trigger_methods: list = None) -> dict:
    """Attempts to trigger errors on endpoint and check for details/stack trace disclosures."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    vulnerable = False
    info_types = []
    
    # Try invalid parameters to trigger DB / server exceptions
    test_params = {"id": "'", "file": "../invalid_file.ext"}
    
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url, target_id=target_id, params=test_params)
            body = res.text
            
            # Framework traces
            if "stack trace" in body.lower() or "exception" in body.lower() or "traceback" in body.lower():
                vulnerable = True
                info_types.append({"type": "Stack Trace", "pattern_found": "traceback/exception", "severity": "Medium"})
            # SQL Errors
            if any(sql in body.lower() for sql in ["sql syntax", "mysql_fetch", "ora-00933"]):
                vulnerable = True
                info_types.append({"type": "Database Stack Trace", "pattern_found": "SQL error syntax", "severity": "High"})
        except Exception as e:
            logger.debug("Error checking error disclosure at %s: %s", url, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Verbose Error Information Disclosure",
            vulnerability_type="Information Disclosure",
            owasp_category="A09:2025 - Security Logging and Alerting Failures",
            severity="Medium",
            url=url,
            description="Verbose error outputs reveal database type, internal file paths, or stack traces.",
            evidence=str(info_types)
        )

    return {
        "discloses_info": vulnerable,
        "info_types": info_types,
        "recommendations": ["Implement custom error pages and disable stack trace display in production."]
    }

@mcp.tool()
async def sensitive_data_in_logs_check(url: str, target_id: int) -> dict:
    """Verifies if query parameters transmit sensitive details which could end up in server logs."""
    sensitive_params = []
    vulnerable = False
    
    # Check if URL query string contains sensitive words
    parsed = re.findall(r"[?&](password|pass|secret|token|key|session|ssn|auth|card_num)=", url.lower())
    if parsed:
        vulnerable = True
        sensitive_params = list(set(parsed))

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Sensitive Data Stored in URLs (Log Risk)",
            vulnerability_type="Information Disclosure",
            owasp_category="A09:2025 - Security Logging and Alerting Failures",
            severity="Medium",
            url=url,
            description="Sensitive user credentials or auth tokens are transmitted via URL query parameters, causing exposure in server access logs.",
            evidence=str(sensitive_params)
        )

    return {
        "sensitive_in_url": vulnerable,
        "sensitive_params": sensitive_params,
        "recommendations": ["Transmit passwords, tokens, and PII inside POST request bodies (application/json or multipart/form-data) rather than URL query variables."]
    }

_ENDPOINT_FINGERPRINTS = {
    "/actuator": ["_links", '"health"', '"beans"'],
    "/actuator/env": ["propertySources", "activeProfiles", '"env"'],
    "/actuator/heapdump": None,
    "/phpinfo.php": ["phpinfo()", "PHP Version", "PHP License", "PHP Credits"],
    "/debug": None,
    "/metrics": ["# HELP", "# TYPE"],
    "/health": ['"status"', '"UP"', '"DOWN"'],
    "/server-status": ["Apache Server Status", "Total Accesses"],
}


def _content_matches_endpoint(ep: str, res) -> bool:
    """Verifikasi body/Content-Type response benar-benar cocok dengan endpoint
    yang diharapkan -- mencegah false positive dari soft-404 (custom error
    page atau SPA fallback yang return status 200 untuk semua path)."""
    fingerprints = _ENDPOINT_FINGERPRINTS.get(ep)

    if ep == "/actuator/heapdump":
        content_type = res.headers.get("content-type", "")
        return "application/octet-stream" in content_type or len(res.content) > 100_000

    if fingerprints is None:
        return False

    body = res.text[:5000]
    return any(fp in body for fp in fingerprints)


@mcp.tool()
async def check_debug_endpoints(base_url: str, target_id: int) -> dict:
    """Checks for exposed logging, metric, and debug endpoints."""
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    endpoints = [
        "/actuator", "/actuator/env", "/actuator/heapdump", "/debug",
        "/metrics", "/health", "/server-status", "/phpinfo.php"
    ]
    found = []

    async with get_client() as client:
        for ep in endpoints:
            target = base_url.rstrip("/") + ep
            try:
                res = await secure_request(client, "GET", target, target_id=target_id)
                if res.status_code == 200:
                    content_verified = _content_matches_endpoint(ep, res)
                    found.append({
                        "path": ep,
                        "status_code": res.status_code,
                        "content_verified": content_verified,
                        "sensitive_data": "Exposed endpoint details" if ep != "/health" else "Public info",
                        "severity": (
                            "High" if content_verified and ("actuator" in ep or "phpinfo" in ep)
                            else "Low" if content_verified
                            else "Info (unverified - manual review required)"
                        ),
                    })
            except Exception as e:
                logger.debug("Error checking debug endpoint %s at %s: %s", ep, base_url, e)
            await delay()

    verified_found = [f for f in found if f.get("content_verified")]
    vulnerable = len(verified_found) > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Exposed Debug or Actuator Endpoint",
            vulnerability_type="Information Disclosure",
            owasp_category="A09:2025 - Security Logging and Alerting Failures",
            severity="High",
            url=base_url,
            description="Exposed debug or admin endpoints containing system environment data.",
            evidence=str(verified_found)
        )

    return {
        "found": found,
        "critical_count": sum(1 for f in found if f["severity"] == "High"),
        "verified_vulnerable": verified_found,
        "vulnerable": vulnerable,
    }
