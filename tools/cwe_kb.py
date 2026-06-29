#!/usr/bin/env python3
"""
CWE Knowledge Base MCP Tools.
Provides search, detail lookup, examples, and Top 25 listing for CWE entries.
"""
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add tools to path for db functions
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from db import db_connection
from mcp_instance import mcp


@mcp.tool()
def search_cwe(query: str, limit: int = 5) -> dict:
    """FTS5 search across CWE name, description, and extended_description.
    
    Args:
        query: Search query string (supports FTS5 syntax like "injection OR xss")
        limit: Maximum results to return (default 5)
        
    Returns:
        Dict with query, count, and results list containing cwe_id, name, snippet
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}
    
    safe_query = query.strip()
    # FTS5 special characters: - + * ( ) " : < > @ 
    # We need to either quote the query or escape special chars
    # Best practice: quote the whole phrase if it has spaces or special chars
    needs_quoting = any(c in safe_query for c in ' -+*():<>@') or ' ' in safe_query
    if '"' not in safe_query and "'" not in safe_query:
        if needs_quoting:
            safe_query = f'"{safe_query}"'
        else:
            safe_query = ' OR '.join(safe_query.split())
    
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cwe_id, name,
                   snippet(cwe_entries_fts, -1, '[', ']', '...', 64) as snippet
            FROM cwe_entries_fts
            WHERE cwe_entries_fts MATCH ?
            LIMIT ?
        """, (safe_query, limit))
        rows = cursor.fetchall()
        results = [{"cwe_id": r[0], "name": r[1], "snippet": r[2]} for r in rows]
        return {"query": query, "count": len(results), "results": results}


@mcp.tool()
def get_cwe(cwe_id: int) -> dict:
    """Get full detail for a single CWE including mitigations.
    
    Args:
        cwe_id: CWE identifier (e.g., 79 for CWE-79)
        
    Returns:
        Dict with all CWE fields including mitigations, or error if not found
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cwe_id, name, abstraction, structure, status, 
                   description, extended_description, likelihood_of_exploit,
                   is_top25, raw_json
            FROM cwe_entries
            WHERE cwe_id = ?
        """, (cwe_id,))
        row = cursor.fetchone()
        if not row:
            return {"error": f"CWE-{cwe_id} not found", "found": False}
        
        # Parse raw_json for mitigations and other fields
        import json
        raw = json.loads(row[9]) if row[9] else {}
        
        # Extract mitigations from raw_json
        mitigations = []
        mits = raw.get("PotentialMitigations", [])
        if isinstance(mits, list):
            for m in mits:
                if isinstance(m, dict):
                    desc = m.get("Description", "")
                    if isinstance(desc, str):
                        mitigations.append(desc.strip())
                    elif isinstance(m, dict):
                        # Sometimes Description might be nested
                        pass
        
        # Extract common consequences
        consequences = []
        cc = raw.get("CommonConsequences", [])
        if isinstance(cc, list):
            for c in cc:
                if isinstance(c, dict):
                    scope = c.get("Scope", [])
                    impact = c.get("Impact", [])
                    note = c.get("Note", "")
                    if isinstance(scope, list):
                        scope_text = ", ".join(scope)
                    else:
                        scope_text = str(scope)
                    if isinstance(impact, list):
                        impact_text = ", ".join(impact)
                    else:
                        impact_text = str(impact)
                    consequences.append({
                        "scope": scope_text, 
                        "impact": impact_text,
                        "note": note
                    })
        
        return {
            "found": True,
            "cwe_id": row[0],
            "name": row[1],
            "abstraction": row[2],
            "structure": row[3],
            "status": row[4],
            "description": row[5],
            "extended_description": row[6],
            "likelihood_of_exploit": row[7],
            "is_top25": bool(row[8]),
            "mitigations": mitigations,
            "common_consequences": consequences
        }


@mcp.tool()
def get_cwe_examples(cwe_id: int) -> dict:
    """Get observed examples (CVE references) for a CWE.
    
    Args:
        cwe_id: CWE identifier (e.g., 79 for CWE-79)
        
    Returns:
        Dict with cwe_id, count, and examples list containing cve_id, example_description, link
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, example_description, link
            FROM cwe_observed_examples
            WHERE cwe_id = ?
            ORDER BY cve_id
        """, (cwe_id,))
        rows = cursor.fetchall()
        examples = [{"cve_id": r[0], "example_description": r[1], "link": r[2]} for r in rows]
        return {"cwe_id": cwe_id, "count": len(examples), "examples": examples}


@mcp.tool()
def list_top25_cwe() -> dict:
    """List all CWE Top 25 2025 entries with brief description.
    
    Returns:
        Dict with count and cwes list containing cwe_id, name, description (truncated)
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cwe_id, name, description
            FROM cwe_entries
            WHERE is_top25 = 1
            ORDER BY cwe_id
        """)
        rows = cursor.fetchall()
        cwes = [
            {
                "cwe_id": r[0],
                "name": r[1],
                "description": (r[2][:200] + "...") if r[2] and len(r[2]) > 200 else r[2]
            }
            for r in rows
        ]
        return {"count": len(cwes), "cwes": cwes}