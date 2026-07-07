"""Container Security Testing Module"""
import httpx
from mcp_instance import mcp
from tools.http_utils import secure_request_sync, get_sync_client
from tools.db import is_in_scope
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def container_endpoint_check(base_url: str, target_id: int) -> dict:
    """Check for exposed container endpoints (Docker socket, K8s API)."""
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "findings": [], "count": 0}
    
    findings = []
    client = get_sync_client()
    
    try:
        for path in ["/var/run/docker.sock", ":2375", ":2376"]:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = secure_request_sync(
                    client, "GET",
                    url,
                    target_id,
                    timeout=3.0
                )
                if resp.status_code in [200, 404, 401] and ("docker" in resp.text.lower() or "containers" in resp.text.lower()):
                    findings.append({"type": "docker_socket_exposed", "endpoint": path, "severity": "critical"})
            except Exception as e:
                logger.debug("Container check failed for %s: %s", path, e)
    finally:
        client.close()
    
    return {"base_url": base_url, "findings": findings, "count": len(findings)}


@mcp.tool()
def k8s_api_check(host: str, target_id: int, port: int = 8443) -> dict:
    """Check for exposed Kubernetes API server."""
    if not is_in_scope(target_id, host):
        return {"error": f"Host {host} is out of scope for target {target_id}. Scan aborted.", "findings": [], "count": 0}
    
    findings = []
    client = get_sync_client()
    
    try:
        for endpoint in ["/api/v1/nodes", "/api/v1/pods", "/version"]:
            url = f"http://{host}:{port}{endpoint}"
            try:
                resp = secure_request_sync(
                    client, "GET",
                    url,
                    target_id,
                    timeout=5.0
                )
                if resp.status_code == 200:
                    data = resp.json()
                    findings.append({"type": "k8s_api_exposed", "endpoint": endpoint})
            except Exception as e:
                logger.debug("K8s API check failed for %s: %s", endpoint, e)
    finally:
        client.close()
    
    return {"host": host, "port": port, "findings": findings, "count": len(findings)}


@mcp.tool()
def k8s_dashboard_check(host: str, target_id: int, port: int = 8443) -> dict:
    """Check for exposed Kubernetes dashboard."""
    if not is_in_scope(target_id, host):
        return {"error": f"Host {host} is out of scope for target {target_id}. Scan aborted.", "dashboard_exposed": False}
    
    client = get_sync_client()
    url = f"http://{host}:{port}/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:https/proxy/"
    
    try:
        resp = secure_request_sync(
            client, "GET",
            url,
            target_id,
            timeout=5.0
        )
        if resp.status_code in [200, 401, 403]:
            return {"dashboard_exposed": True, "url": url, "auth_required": resp.status_code != 200}
    except Exception as e:
        logger.debug("K8s dashboard check failed: %s", e)
    finally:
        client.close()
    
    return {"dashboard_exposed": False, "url": url}