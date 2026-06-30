"""StealthVision-MCP - GraphQL Introspection & Query Generation Module"""
import httpx
import json
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT

@mcp.tool()
def graphql_introspect(endpoint: str) -> dict:
    """Introspect GraphQL schema and extract all queries/mutations."""
    try:
        query = {
            "query": "{ __schema { types { name fields { name } } } }"
        }
        
        client = httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT})
        r = client.post(endpoint, json=query)
        
        if r.status_code == 200:
            result = r.json()
            types = result.get("data", {}).get("__schema", {}).get("types", [])
            
            queries = []
            mutations = []
            
            for t in types:
                name = t.get("name", "")
                if "Query" in name:
                    queries = t.get("fields", [])
                elif "Mutation" in name:
                    mutations = t.get("fields", [])
            
            return {
                "queries": [f["name"] for f in queries],
                "mutations": [f["name"] for f in mutations],
                "types_found": len(types),
                "success": True
            }
        else:
            return {"error": f"Introspection failed: {r.status_code}", "success": False}
    except Exception as e:
        return {"error": str(e), "success": False}

@mcp.tool()
def graphql_generate_queries(queries: list, mutations: list) -> dict:
    """Generate sample GraphQL query/mutations for testing."""
    generated = {"queries": [], "mutations": []}
    
    for q in queries[:5]:
        generated["queries"].append({
            "name": q,
            "sample": f"query {{ {q} {{ id name }} }}"
        })
    
    for m in mutations[:5]:
        generated["mutations"].append({
            "name": m,
            "sample": f"mutation {{ {m}(input: {{}}) {{ success }} }}"
        })
    
    return generated