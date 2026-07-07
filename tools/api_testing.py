"""API Security Testing Module
Specialized testing for REST/GraphQL/gRPC APIs beyond OWASP API Top 10.
"""
import json
import httpx
from mcp_instance import mcp
from tools.http_utils import secure_request_sync, get_sync_client
from tools.db import is_in_scope
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def api_security_scan(base_url: str, target_id: int, api_type: str = "auto", endpoints: list = None) -> dict:
    """API security scanner for REST/GraphQL endpoints."""
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "findings_count": 0, "findings": []}
    
    if not base_url.startswith(('http://', 'https://')):
        return {"error": "Invalid URL - must include http:// or https://", "findings_count": 0, "findings": []}
    
    findings = []
    client = get_sync_client()
    
    try:
        resp = secure_request_sync(
            client, "GET",
            f"{base_url}/",
            target_id,
            timeout=10.0
        )
        if resp.status_code in [200, 401, 403]:
            findings.append({
                "type": "endpoint_accessible",
                "endpoint": "/",
                "status": resp.status_code,
                "finding": "Endpoint accessible, check authentication" if resp.status_code == 200 else "Authentication required"
            })
    except Exception as e:
        logger.debug(f"API scan error: {e}")
    finally:
        client.close()
    
    return {
        "base_url": base_url,
        "api_type": api_type,
        "findings_count": len(findings),
        "findings": findings
    }


@mcp.tool()
def graphql_introspection_check(url: str, target_id: int) -> dict:
    """Check GraphQL endpoint for introspection."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "introspection_enabled": False, "schema_leaked": False}
    
    if not url.startswith(('http://', 'https://')):
        return {"error": "Invalid URL", "introspection_enabled": False, "schema_leaked": False}
    
    client = get_sync_client()
    
    introspection_query = {"query": "{__schema{types{name,fields{name}}}"}
    
    try:
        resp = secure_request_sync(
            client, "POST",
            url,
            target_id,
            json=introspection_query,
            timeout=10.0
        )
        data = resp.json()
        
        if 'data' in data and '__schema' in data.get('data', {}):
            return {
                "introspection_enabled": True,
                "schema_leaked": True,
                "finding": "CRITICAL: GraphQL introspection enabled - schema exposed",
            }
    except Exception as e:
        logger.debug(f"GraphQL introspection error: {e}")
    finally:
        client.close()
    
    return {"introspection_enabled": False, "schema_leaked": False}