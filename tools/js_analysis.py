"""AI Offensive Security Platform - JavaScript Analysis Module"""
import httpx
import re
import logging
from mcp_instance import mcp
from tools.http_utils import secure_request_sync, get_sync_client
from tools.db import is_in_scope

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT

@mcp.tool()
def js_secrets_find(url: str, target_id: int) -> dict:
    """Find secrets in JavaScript files via regex patterns."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "success": False}
    
    client = get_sync_client()
    try:
        r = secure_request_sync(
            client, "GET",
            url,
            target_id,
            headers={"User-Agent": USER_AGENT}
        )
        
        secrets = []
        patterns = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "github_token": r"ghp_[a-zA-Z0-9]{36}",
            "generic_secret": r"(?:secret|api_key|apikey|token|password)[^:=]*[:=]\s*[\'\"]([a-zA-Z0-9-_]{20,})[\'\"]",
            "base_url": r"(?:baseURL|apiUrl|endpoint)[^:=]*[:=]\s*[\'\"](https?://[^\'\"]+)[\'\"]",
        }
        
        for name, pat in patterns.items():
            matches = re.findall(pat, r.text, re.IGNORECASE)
            for m in matches:
                secrets.append({"type": name, "value": m[:50] + "..." if len(m) > 50 else m})
        
        return {"secrets": secrets, "count": len(secrets), "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}
    finally:
        client.close()