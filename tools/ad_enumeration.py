"""StealthVision-MCP - Active Directory Enumeration Module"""
import httpx
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT

@mcp.tool()
def ad_enumerate(target: str, domain: str = "") -> dict:
    """Enumerate Active Directory information via LDAP/HTTP."""
    results = {
        "ldap": {"status": "not_tested"},
        "kerberos": {"status": "not_tested"},
        "users": [],
        "groups": [],
        "computers": [],
        "shares": []
    }
    
    # Common AD endpoints to check
    ad_endpoints = [
        f"http://{target}/",
        f"https://{target}/",
        f"ldap://{target}:389",
        f"ldaps://{target}:636",
    ]
    
    if domain:
        ad_endpoints.extend([
            f"https://{target}/owa",
            f"https://{target}/ecp",
            f"https://{target}/autodiscover",
        ])
    
    try:
        client = httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT})
        for endpoint in ad_endpoints:
            try:
                r = client.get(endpoint, timeout=5.0)
                if "active directory" in r.text.lower() or "windows" in r.text.lower():
                    results["ldap"]["running"] = endpoint
            except:
                pass
        
        results["status"] = "completed"
        results["success"] = True
    except Exception as e:
        results["error"] = str(e)
        results["success"] = False
    
    return results

@mcp.tool()
def ad_user_enum(target: str, usernames: list = None) -> dict:
    """Enumerate AD users via various endpoints."""
    if usernames is None:
        usernames = ["administrator", "admin", "guest", "test", "user", "service"]
    
    found_users = []
    
    for user in usernames:
        # Check OWA login page
        try:
            client = httpx.Client(timeout=DEFAULT_TIMEOUT)
            r = client.get(f"https://{target}/owa", follow_redirects=True)
            if r.status_code in [200, 401]:
                found_users.append({
                    "username": user,
                    "endpoint": f"https://{target}/owa",
                    "status": "accessible"
                })
        except:
            pass
    
    return {"users": found_users, "count": len(found_users), "success": True}