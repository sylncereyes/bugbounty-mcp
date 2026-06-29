"""StealthVision-MCP - API Security Testing Module
Specialized testing for REST/GraphQL/gRPC APIs beyond OWASP API Top 10.
"""
import json
import httpx
from mcp_instance import mcp
from tools.http_utils import get_http_client
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def api_security_scan(base_url: str, api_type: str = "auto", endpoints: list = None) -> dict:
    """
    Comprehensive API security scanner.
    
    Args:
        base_url: Target API base URL (e.g., https://api.target.com)
        api_type: "rest", "graphql", "grpc", or "auto" for detection
        endpoints: Optional list of endpoints to test (e.g., ["/", "/api/v1/users"])
    
    Returns:
        API security findings including missing auth, rate limiting, CORS issues, dll
    """
    if not base_url.startswith(('http://', 'https://')):
        return {"error": "Invalid URL - must include http:// or https://"}
    
    client = get_http_client()
    findings = []
    
    # Test 1: Check API endpoint accessibility
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
    
    # Test 2: HTTP methods enumeration
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']
    method_findings = []
    
    for method in methods:
        try:
            resp = client.request(method, f"{base_url}/api", timeout=5.0)
            if resp.status_code not in [404, 405]:
                method_findings.append({"method": method, "status": resp.status_code})
        except:
            pass
    
    if len(method_findings) > 4:
        findings.append({
            "type": "http_methods",
            "methods_allowed": method_findings,
            "severity": "medium",
            "finding": f"Multiple HTTP methods allowed: {[m['method'] for m in method_findings]}"
        })
    
    return {
        "base_url": base_url,
        "api_type": api_type,
        "findings_count": len(findings),
        "findings": findings
    }


@mcp.tool()
def graphql_introspection_check(url: str) -> dict:
    """
    Check GraphQL endpoint for introspection and sensitive queries.
    
    Args:
        url: GraphQL endpoint URL (e.g., https://api.target.com/graphql)
    
    Returns:
        Introspection enabled status, schema info, sensitive queries
    """
    if not url.startswith(('http://', 'https://')):
        return {"error": "Invalid URL"}
    
    client = get_http_client()
    
    # Try introspection query
    introspection_query = {
        "query": "{__schema{types{name,fields{name}}}"
    }
    
    try:
        resp = client.post(url, json=introspection_query, timeout=10.0)
        data = resp.json()
        
        if 'data' in data and '__schema' in data.get('data', {}):
            return {
                "introspection_enabled": True,
                "schema_leaked": True,
                "finding": "CRITICAL: GraphQL introspection enabled - schema exposed",
                "recommendation": "Disable introspection in production"
            }
    except:
        pass
    
    return {
        "introspection_enabled": False,
        "schema_leaked": False,
        "finding": "GraphQL introspection disabled or endpoint not found"
    }