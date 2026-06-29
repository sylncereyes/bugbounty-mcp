"""StealthVision-MCP - Container Security Testing Module
Docker, Kubernetes, container-related security checks.
"""
import httpx
from mcp_instance import mcp
from tools.http_utils import get_http_client
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def container_endpoint_check(base_url: str) -> dict:
    """
    Check for exposed container endpoints (Docker socket, K8s API).
    
    Args:
        base_url: Target URL or IP to check
    
    Returns:
        Container endpoint exposure findings
    """
    client = get_http_client()
    findings = []
    
    # Docker socket
    docker_paths = [
        "/var/run/docker.sock",
        "/docker.sock",
        ":2375",  # Docker API (unsecured)
        ":2376",  # Docker API (TLS)
    ]
    
    for path in docker_paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = client.get(url, timeout=3.0)
            if resp.status_code in [200, 404, 401]:
                if "docker" in resp.text.lower() or "containers" in resp.text.lower():
                    findings.append({
                        "type": "docker_socket_exposed",
                        "endpoint": path,
                        "severity": "critical"
                    })
        except:
            pass
    
    return {
        "base_url": base_url,
        "findings": findings,
        "count": len(findings)
    }


@mcp.tool()
def k8s_api_check(host: str, port: int = 8443) -> dict:
    """
    Check for exposed Kubernetes API server.
    
    Args:
        host: Target host or IP
        port: K8s API port (default 8443)
    
    Returns:
        K8s API exposure and version info
    """
    client = get_http_client()
    findings = []
    
    k8s_endpoints = [
        "/api/v1/nodes",
        "/api/v1/pods",
        "/version",
        "/healthz",
    ]
    
    for endpoint in k8s_endpoints:
        url = f"http://{host}:{port}{endpoint}"
        try:
            resp = client.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                findings.append({
                    "type": "k8s_api_exposed",
                    "endpoint": endpoint,
                    "version": data.get("major", "unknown"),
                    "severity": "critical"
                })
        except:
            pass
    
    return {
        "host": host,
        "port": port,
        "findings": findings,
        "count": len(findings)
    }


@mcp.tool()
def k8s_dashboard_check(host: str, port: int = 8443) -> dict:
    """
    Check for exposed Kubernetes dashboard.
    
    Args:
        host: Target host or IP
        port: K8s port (default 8443)
    
    Returns:
        Dashboard exposure findings
    """
    client = get_http_client()
    
    url = f"http://{host}:{port}/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:https/proxy/"
    
    try:
        resp = client.get(url, timeout=5.0)
        if resp.status_code in [200, 401, 403]:
            return {
                "dashboard_exposed": True,
                "url": url,
                "auth_required": resp.status_code != 200,
                "severity": "critical"
            }
    except:
        pass
    
    return {
        "dashboard_exposed": False,
        "url": url,
        "finding": "Kubernetes dashboard not accessible or protected"
    }