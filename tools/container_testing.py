"""StealthVision-MCP - Container Security Testing Module"""
import httpx
from mcp_instance import mcp
import logging

logger = logging.getLogger("stealthvision")


def _get_client():
    return httpx.Client(timeout=30.0, verify=True, follow_redirects=False)


@mcp.tool()
def container_endpoint_check(base_url: str) -> dict:
    """Check for exposed container endpoints (Docker socket, K8s API)."""
    client = _get_client()
    findings = []
    
    for path in ["/var/run/docker.sock", ":2375", ":2376"]:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            resp = client.get(url, timeout=3.0)
            if resp.status_code in [200, 404, 401] and ("docker" in resp.text.lower() or "containers" in resp.text.lower()):
                findings.append({"type": "docker_socket_exposed", "endpoint": path, "severity": "critical"})
        except:
            pass
    
    return {"base_url": base_url, "findings": findings, "count": len(findings)}


@mcp.tool()
def k8s_api_check(host: str, port: int = 8443) -> dict:
    """Check for exposed Kubernetes API server."""
    client = _get_client()
    findings = []
    
    for endpoint in ["/api/v1/nodes", "/api/v1/pods", "/version"]:
        url = f"http://{host}:{port}{endpoint}"
        try:
            resp = client.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                findings.append({"type": "k8s_api_exposed", "endpoint": endpoint})
        except:
            pass
    
    return {"host": host, "port": port, "findings": findings, "count": len(findings)}


@mcp.tool()
def k8s_dashboard_check(host: str, port: int = 8443) -> dict:
    """Check for exposed Kubernetes dashboard."""
    client = _get_client()
    
    url = f"http://{host}:{port}/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:https/proxy/"
    
    try:
        resp = client.get(url, timeout=5.0)
        if resp.status_code in [200, 401, 403]:
            return {"dashboard_exposed": True, "url": url, "auth_required": resp.status_code != 200}
    except:
        pass
    
    return {"dashboard_exposed": False, "url": url}