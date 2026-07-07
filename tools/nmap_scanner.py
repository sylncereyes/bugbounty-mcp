"""Advanced Port Scanner with Nmap Integration"""
import subprocess
import json
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")

@mcp.tool()
def nmap_scan(target: str, opts: str = "-sV -sC", ports: str = "top100") -> dict:
    """Execute Nmap scan with service detection."""
    port_args = ""
    if ports == "top100":
        port_args = "--top-ports 100"
    elif ports == "full":
        port_args = "-p-"
    elif ports != "default":
        port_args = f"-p {ports}"
    
    try:
        cmd = f"nmap {opts} {port_args} -oX - {target}".split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        return {
            "target": target,
            "command": " ".join(cmd),
            "output": result.stdout[:5000] if result.stdout else result.stderr[:1000],
            "success": result.returncode == 0
        }
    except FileNotFoundError:
        return {"error": "nmap not installed", "success": False}
    except Exception as e:
        return {"error": str(e), "success": False}

@mcp.tool()
def nmap_service_scan(target: str, port: int = 80) -> dict:
    """Scan specific port with service detection."""
    return nmap_scan(target, "-sV -sC", str(port))