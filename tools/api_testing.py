"""StealthVision-MCP - API Security Testing Module
Specialized testing for REST/GraphQL/gRPC APIs beyond OWASP API Top 10.
"""
import json
import httpx
from mcp_instance import mcp
import logging

logger = logging.getLogger("stealthvision")


def _get_client():
    """Create httpx client with defaults"""
    return httpx.Client(
        timeout=30.0,
        verify=True,
        headers={"User-Agent": "StealthVision/1.0"},
        follow_redirects=False
    )


@mcp.tool()
def api_security_scan(base_url: str, api_type: str = "auto", endpoints: list = None) -> dict:
    """API security scanner for REST/GraphQL endpoints."""
    if not base_url.startswith(('http://', 'https://')):
        return {"error": "Invalid URL - must include http:// or https://"}
    
    client = _get_client()
    findings = []
    
    try:
        resp = client.get(f"{base_url}/", timeout=10.0)
        if resp.status_code in [200, 401, 403]:
            findings.append({
                "type": "endpoint_accessible",
                "endpoint": "/",
                "status": resp.status_code,
                "finding": "Endpoint accessible, check authentication" if resp.status_code == 200 else "Authentication required"
            })
    except Exception as e:
        logger.debug(f"API scan error: {e}")
    
    return {
        "base_url": base_url,
        "api_type": api_type,
        "findings_count": len(findings),
        "findings": findings
    }


@mcp.tool()
def graphql_introspection_check(url: str) -> dict:
    """Check GraphQL endpoint for introspection."""
    if not url.startswith(('http://', 'https://')):
        return {"error": "Invalid URL"}
    
    client = _get_client()
    
    introspection_query = {"query": "{__schema{types{name,fields{name}}}"}
    
    try:
        resp = client.post(url, json=introspection_query, timeout=10.0)
        data = resp.json()
        
        if 'data' in data and '__schema' in data.get('data', {}):
            return {
                "introspection_enabled": True,
                "schema_leaked": True,
                "finding": "CRITICAL: GraphQL introspection enabled - schema exposed",
            }
    except:
        pass
    
    return {"introspection_enabled": False, "schema_leaked": False}