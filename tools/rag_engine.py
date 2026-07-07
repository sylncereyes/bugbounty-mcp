"""AGY-MCP RAG (Retrieval-Augmented Generation) Engine
Automatically triggers knowledge base searches when AI conversations detect relevant intent.
"""
import sqlite3
import logging
from typing import Optional
from mcp_instance import mcp
from tools.db import DB_PATH

logger = logging.getLogger("stealthvision_rag")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@mcp.tool()
def rag_search(intent_type: str, query: str, limit: int = 5) -> dict:
    """
    Smart RAG search that automatically selects the appropriate knowledge base
    based on intent type.
    
    Args:
        intent_type: Type of query - one of:
            - 'vulnerability_knowledge': Search for vulnerability patterns, techniques
            - 'cve_exploit': Search for CVE exploits and PoCs  
            - 'pentest_methodology': Search for pentesting methodologies
            - 'attack_technique': Search for ATT&CK techniques
            - 'tool_usage': Search for tool usage guides
            - 'generic': Search across all knowledge bases
        query: Search string
        limit: Max results to return
    
    Returns:
        Combined results from relevant knowledge bases
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": {}}
    
    safe_query = query.strip()
    results = {}
    
    # Map intent to tables
    intent_tables = {
        'vulnerability_knowledge': ['hacktricks_kb', 'portswigger_kb', 'lolbins_kb'],
        'cve_exploit': ['exploitdb_kb', 'cve_kb', 'cwe_kb'],
        'pentest_methodology': ['hacktricks_kb', 'owasp_wstg', 'portswigger_kb'],
        'attack_technique': ['attck_capec_kb'],
        'tool_usage': ['seclists_kb', 'patt_kb', 'hacktricks_kb'],
        'generic': ['hacktricks_kb', 'exploitdb_kb', 'attck_capec_kb', 'portswigger_kb', 'cve_kb', 'wstg']
    }
    
    tables_to_search = intent_tables.get(intent_type, intent_tables['generic'])
    
    conn = _get_conn()
    try:
        for table in tables_to_search:
            try:
                # Check if table exists
                table_check = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table,)
                ).fetchone()
                
                if table_check:
                    # Get first column name for FTS5
                    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
                    if cols:
                        search_col = cols[0][1]  # First column usually searchable
                        
                        # Build dynamic query
                        fts_query = safe_query.replace('"', ' OR "').replace("'", " OR '")
                        fts_query = f'"{fts_query}"'
                        
                        rows = conn.execute(
                            f"""
                            SELECT *
                            FROM {table}
                            WHERE {search_col} MATCH ?
                            LIMIT ?
                            """,
                            (fts_query, limit)
                        ).fetchall()
                        
                        if rows:
                            results[table] = [dict(r) for r in rows[:limit]]
            except Exception as e:
                logger.debug(f"Table {table} search skipped: {e}")
                continue
        
        return {
            "intent": intent_type,
            "query": query,
            "sources": list(results.keys()),
            "total_results": sum(len(v) for v in results.values()),
            "results": results
        }
    finally:
        conn.close()


@mcp.tool()
def rag_context_inject(target_vulnerability: str, limit_per_source: int = 3) -> dict:
    """
    Inject relevant knowledge base context for a given vulnerability type.
    Called automatically by AI to enrich conversation with methodology.
    
    Args:
        target_vulnerability: Vulnerability type (e.g., 'sqli', 'xss', 'idor', 'jwt')
        limit_per_source: Max results per knowledge source
    
    Returns:
        Structured context ready for AI consumption
    """
    vuln_to_intent = {
        'sqli': 'pentest_methodology',
        'sql-injection': 'pentest_methodology',
        'xss': 'pentest_methodology',
        'idor': 'vulnerability_knowledge',
        'jwt': 'vulnerability_knowledge',
        'authentication': 'vulnerability_knowledge',
        'ssrf': 'vulnerability_knowledge',
        'ssti': 'pentest_methodology',
        'xxe': 'pentest_methodology'
    }
    
    intent = vuln_to_intent.get(target_vulnerability.lower(), 'generic')
    
    # Get attack techniques
    attack_results = rag_search('attack_technique', target_vulnerability, limit_per_source)
    
    # Get methodology
    method_results = rag_search(intent, target_vulnerability, limit_per_source)
    
    # Combine and format
    context = {
        "vulnerability": target_vulnerability,
        "attack_techniques": attack_results.get("results", {}).get("attck_capec_kb", []),
        "methodology": method_results.get("results", {}),
        "summary": f"Found {attack_results.get('total_results', 0) + method_results.get('total_results', 0)} relevant entries across {len(set(attack_results.get('sources', []) + method_results.get('sources', [])))} knowledge sources."
    }
    
    return context


@mcp.tool()
def rag_get_exploits(cve_id: str, vendor: Optional[str] = None, product: Optional[str] = None) -> dict:
    """
    Retrieve exploits for a given CVE or software from knowledge bases.
    Combines ExploitDB, CVE, and ATT&CK data for comprehensive exploitability analysis.
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2021-41773')
        vendor: Optional vendor name filter
        product: Optional product name filter
    
    Returns:
        Exploit information with references and PoC links
    """
    results = {}
    
    conn = _get_conn()
    try:
        # Search ExploitDB
        exploit_query = f'"{cve_id}"' if cve_id else ""
        if product:
            exploit_query += f' OR "{product}"'
        if vendor:
            exploit_query += f' OR "{vendor}"'
            
        if exploit_query:
            rows = conn.execute(
                """
                SELECT *
                FROM exploitdb_kb
                WHERE exploitdb_kb MATCH ?
                ORDER BY date DESC
                LIMIT 10
                """,
                (exploit_query,)
            ).fetchall()
            if rows:
                results["exploitdb"] = [dict(r) for r in rows]
        
        # Search CVE database
        if cve_id:
            row = conn.execute(
                "SELECT * FROM cve_kb WHERE cve_id = ?",
                (cve_id,)
            ).fetchone()
            if row:
                results["cve"] = dict(row)
        
        return {
            "cve_id": cve_id,
            "sources_found": list(results.keys()),
            "exploits": results
        }
    finally:
        conn.close()