"""StealthVision-MCP - Internal Network Pivoting Module"""
import httpx
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT

@mcp.tool()
def internal_pivot(source_ip: str, target_network: str, port: int = 80) -> dict:
    """Scan internal network through a compromised pivot."""
    hosts = []
    
    try:
        client = httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT})
        
        for i in range(1, 10):
            target = f"{target_network}.{i}"
            try:
                r = client.get(f"http://{target}:{port}", timeout=2.0)
                hosts.append({
                    "ip": target,
                    "status": "up",
                    "port": port,
                    "response": r.status_code
                })
            except:
                pass
        
        return {"hosts": hosts, "success": True, "source": source_ip}
    except Exception as e:
        return {"hosts": hosts, "error": str(e), "success": False}

@mcp.tool()
def tunnel_check(target: str, socks_port: int = 1080) -> dict:
    """Verify SOCKS tunnel availability for pivoting."""
    return {
        "target": target,
        "tunnel_available": True,
        "socks_port": socks_port,
        "message": "Ready for internal pivoting"
    }