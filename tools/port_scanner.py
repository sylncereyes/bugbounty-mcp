"""StealthVision-MCP - Advanced Port Scanner Module"""
import socket
import concurrent.futures
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 9200: "Elasticsearch"
}

@mcp.tool()
def port_scan(host: str, ports: list = None, timeout: float = 1.0) -> dict:
    """Scan common ports on target host."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    else:
        ports = list(ports)
    
    open_ports = []
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                return {"port": port, "service": service}
            sock.close()
        except Exception:
            pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(scan_port, ports))
    
    open_ports = [r for r in results if r]
    
    return {"host": host, "open_ports": open_ports, "count": len(open_ports), "success": True}