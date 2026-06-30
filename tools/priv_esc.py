"""StealthVision-MCP - Lateral Movement & Privilege Escalation Module"""
import httpx
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT

WINDOWS_PRIV_ESC = {
    "always_install_elevated": "msiexec /i malicious.msi",
    "wmi_event_subscription": "wmic /namespace:\\root\\subscription",
    "service_execution": "sc create evil binPath=",
    "scheduled_task": "schtasks /create /tn evil /tr",
    "dll_hijack": "regsvr32 /s /n /u /sc server /i",
}

LINUX_PRIV_ESC = {
    "sudo_misconfig": "sudo -l check",
    "suid_bin": "find / -perm -4000",
    "cron_job": "crontab -l",
    "path_hijack": "export PATH=evil:",
    "capability_abuse": "getcap -r /",
}

@mcp.tool()
def lateral_movement_check(host: str, creds: dict = {}) -> dict:
    """Check lateral movement opportunities from compromised host."""
    opportunities = []
    
    # Check SMB shares
    try:
        client = httpx.Client(timeout=DEFAULT_TIMEOUT)
        r = client.get(f"http://{host}/admin$", timeout=3.0)
        if r.status_code != 404:
            opportunities.append({"method": "admin_share", "url": f"http://{host}/admin$"})
    except:
        pass
    
    # Check WMI/DCOM
    user = creds.get('user', 'admin') if creds else 'admin'
    opportunities.append({"method": "wmi", "command": f"wmic -target {host} -user {user}"})
    
    return {"opportunities": opportunities, "count": len(opportunities), "success": True}

@mcp.tool()
def priv_esc_chains(os_type: str = "windows") -> dict:
    """Get privilege escalation command chains."""
    if os_type.lower() == "linux":
        return {
            "techniques": LINUX_PRIV_ESC,
            "os": "linux",
            "count": len(LINUX_PRIV_ESC),
            "success": True
        }
    else:
        return {
            "techniques": WINDOWS_PRIV_ESC,
            "os": "windows",
            "count": len(WINDOWS_PRIV_ESC),
            "success": True
        }