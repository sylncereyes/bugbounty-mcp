#!/usr/bin/env python3
"""
CVE Knowledge Base MCP Tools (CISA KEV Catalog).
Provides search, detail lookup, ransomware listing, and CWE cross-referencing for known exploited vulnerabilities.
"""

import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import json

# Add tools to path for db functions
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from db import db_connection
from mcp_instance import mcp


@mcp.tool()
def search_cve(query: str, vendor: Optional[str] = None, limit: int = 10) -> dict:
    """FTS5 search across CVE vulnerability_name, short_description, vendor_project, product.
    
    Args:
        query: Search query string (supports FTS5 syntax like "rce OR injection")
        vendor: Optional vendor_project filter (e.g., "Microsoft", "Cisco", "Apache")
        limit: Maximum results to return (default 10)
        
    Returns:
        Dict with query, count, and results list containing cve_id, vulnerability_name,
        vendor_project, product, known_ransomware_use, snippet
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}
    
    safe_query = query.strip()
    # FTS5 special characters: - + * ( ) " : < > @
    # Quote the whole phrase if it has spaces or special chars
    needs_quoting = any(c in safe_query for c in ' -+*():<>@') or ' ' in safe_query
    if '"' not in safe_query and "'" not in safe_query:
        if needs_quoting:
            safe_query = f'"{safe_query}"'
        else:
            safe_query = ' OR '.join(safe_query.split())
    
    with db_connection() as conn:
        cursor = conn.cursor()
        
        if vendor:
            # Search with vendor filter
            sql = """
                SELECT c.cve_id, c.vulnerability_name, c.vendor_project, c.product,
                       c.known_ransomware_use,
                       snippet(cve_entries_fts, -1, '[', ']', '...', 64) as snippet
                FROM cve_entries c
                JOIN cve_entries_fts f ON c.cve_id = f.cve_id
                WHERE cve_entries_fts MATCH ?
                  AND c.vendor_project LIKE ?
                LIMIT ?
            """
            params = [safe_query, f"%{vendor}%", limit]
        else:
            sql = """
                SELECT c.cve_id, c.vulnerability_name, c.vendor_project, c.product,
                       c.known_ransomware_use,
                       snippet(cve_entries_fts, -1, '[', ']', '...', 64) as snippet
                FROM cve_entries c
                JOIN cve_entries_fts f ON c.cve_id = f.cve_id
                WHERE cve_entries_fts MATCH ?
                LIMIT ?
            """
            params = [safe_query, limit]
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        results = [
            {
                "cve_id": r[0],
                "vulnerability_name": r[1],
                "vendor_project": r[2],
                "product": r[3],
                "known_ransomware_use": r[4],
                "snippet": r[5]
            }
            for r in rows
        ]
        return {"query": query, "vendor_filter": vendor, "count": len(results), "results": results}


@mcp.tool()
def get_cve(cve_id: str) -> dict:
    """Get full detail for a single CVE from KEV catalog.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-3400")
        
    Returns:
        Dict with all CVE fields including cwe_ids (parsed JSON), or error if not found
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
                   short_description, required_action, due_date, known_ransomware_use,
                   cwe_ids, notes, raw_json, indexed_at
            FROM cve_entries
            WHERE cve_id = ?
        """, (cve_id.upper(),))
        row = cursor.fetchone()
        
        if not row:
            return {"error": f"CVE {cve_id} not found in KEV catalog", "found": False}
        
        # Parse cwe_ids JSON
        cwe_ids = []
        try:
            cwe_ids = json.loads(row[9]) if row[9] else []
        except (json.JSONDecodeError, TypeError):
            cwe_ids = []
        
        return {
            "found": True,
            "cve_id": row[0],
            "vendor_project": row[1],
            "product": row[2],
            "vulnerability_name": row[3],
            "date_added": row[4],
            "short_description": row[5],
            "required_action": row[6],
            "due_date": row[7],
            "known_ransomware_use": row[8],
            "cwe_ids": cwe_ids,
            "notes": row[9],
            "indexed_at": row[11]
        }


@mcp.tool()
def list_ransomware_cves(limit: int = 20) -> dict:
    """List CVEs with known ransomware campaign use, sorted by date_added newest first.
    
    Args:
        limit: Maximum results to return (default 20)
        
    Returns:
        Dict with count and results list containing cve_id, vulnerability_name,
        vendor_project, product, date_added, known_ransomware_use
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, vulnerability_name, vendor_project, product,
                   date_added, known_ransomware_use
            FROM cve_entries
            WHERE known_ransomware_use = 'Known'
            ORDER BY date_added DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        results = [
            {
                "cve_id": r[0],
                "vulnerability_name": r[1],
                "vendor_project": r[2],
                "product": r[3],
                "date_added": r[4],
                "known_ransomware_use": r[5]
            }
            for r in rows
        ]
        return {"count": len(results), "results": results}


@mcp.tool()
def get_cve_for_cwe(cwe_id: int) -> dict:
    """Find CVEs in KEV catalog that are associated with a given CWE.
    
    Cross-references cwe_observed_examples (MITRE historical examples) with
    cve_entries (CISA KEV active exploitation) to find CWEs that are BOTH
    historically associated AND currently exploited in the wild.
    
    Args:
        cwe_id: CWE identifier (e.g., 79 for CWE-79 XSS)
        
    Returns:
        Dict with cwe_id, count, and results list containing cve_id, vulnerability_name,
        vendor_project, product, date_added, known_ransomware_use
    """
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # First get CVE IDs from cwe_observed_examples for this CWE
        cursor.execute("""
            SELECT DISTINCT o.cve_id
            FROM cwe_observed_examples o
            JOIN cve_entries c ON o.cve_id = c.cve_id
            WHERE o.cwe_id = ?
        """, (cwe_id,))
        cve_ids = [row[0] for row in cursor.fetchall()]
        
        if not cve_ids:
            return {
                "cwe_id": cwe_id,
                "count": 0,
                "results": [],
                "note": "No CVEs found in KEV catalog for this CWE"
            }
        
        # Get full details for matching CVEs
        placeholders = ','.join('?' for _ in cve_ids)
        cursor.execute(f"""
            SELECT cve_id, vulnerability_name, vendor_project, product,
                   date_added, known_ransomware_use
            FROM cve_entries
            WHERE cve_id IN ({placeholders})
            ORDER BY date_added DESC
        """, cve_ids)
        
        rows = cursor.fetchall()
        results = [
            {
                "cve_id": r[0],
                "vulnerability_name": r[1],
                "vendor_project": r[2],
                "product": r[3],
                "date_added": r[4],
                "known_ransomware_use": r[5]
            }
            for r in rows
        ]
        
        return {
            "cwe_id": cwe_id,
            "count": len(results),
            "results": results,
            "note": f"Found {len(results)} CVE(s) in KEV catalog associated with CWE-{cwe_id}"
        }