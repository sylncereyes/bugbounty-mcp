"""
PortSwigger Notes Knowledge Base - MCP Tools
Provides tools to search and query personal PortSwigger Web Security Academy notes.
"""
import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_instance import mcp
from tools.db import get_connection, db_connection


# ─────────────────────────────────────────────
# MCP TOOLS
# ─────────────────────────────────────────────

@mcp.tool()
def search_portswigger_notes(
    query: str,
    section_type: Optional[str] = None,
    limit: int = 5
) -> str:
    """
    Full-text search PortSwigger personal notes using FTS5.
    
    Args:
        query: Search query (FTS5 syntax - supports quotes, AND/OR, wildcards)
        section_type: Optional filter - 'lab', 'lab_hint', 'lab_solution', 'community_solutions', 'concept'
        limit: Maximum results to return (default 5, max 20)
    
    Returns:
        Formatted search results with doc_title, section_title, section_type, and content snippets
    """
    if limit > 20:
        limit = 20
    
    with db_connection() as conn:
        # Build FTS5 query - escape special characters
        # FTS5 treats - as NOT operator, so we need to quote phrases with hyphens
        # Simple approach: wrap the whole query in quotes if it contains spaces/special chars
        fts_query = query
        # If query contains special FTS5 chars without quotes, wrap in quotes
        special_chars = ['-', '+', '*', '(', ')', '"', 'AND', 'OR', 'NOT']
        has_special = any(c in query for c in ['-', '+', '*', '(', ')'])
        has_quotes = '"' in query
        if has_special and not has_quotes:
            fts_query = f'"{query}"'
        
        if section_type:
            sql = """
                SELECT pk.doc_title, pk.section_title, pk.section_type, pk.content,
                       pk.parent_lab_title, pk.order_index
                FROM portswigger_kb pk
                JOIN portswigger_kb_fts ON pk.rowid = portswigger_kb_fts.rowid
                WHERE portswigger_kb_fts MATCH ?
                AND pk.section_type = ?
                ORDER BY bm25(portswigger_kb_fts)
                LIMIT ?
            """
            params = (fts_query, section_type, limit)
        else:
            sql = """
                SELECT pk.doc_title, pk.section_title, pk.section_type, pk.content,
                       pk.parent_lab_title, pk.order_index
                FROM portswigger_kb pk
                JOIN portswigger_kb_fts ON pk.rowid = portswigger_kb_fts.rowid
                WHERE portswigger_kb_fts MATCH ?
                ORDER BY bm25(portswigger_kb_fts)
                LIMIT ?
            """
            params = (fts_query, limit)
        
        rows = conn.execute(sql, params).fetchall()
        
        if not rows:
            return f"No results found for query: '{query}'"
        
        results = []
        for row in rows:
            content_preview = row["content"][:300] + ("..." if len(row["content"]) > 300 else "")
            lab_info = f" [Lab: {row['parent_lab_title']}]" if row["parent_lab_title"] else ""
            results.append(
                f"📄 **{row['doc_title']}** → **{row['section_title']}** ({row['section_type']}){lab_info}\n"
                f"   {content_preview}"
            )
        
        return f"Found {len(results)} result(s) for '{query}':\n\n" + "\n\n".join(results)


@mcp.tool()
def get_portswigger_section(
    doc_title: str,
    section_title: str
) -> str:
    """
    Get full content of a specific section from PortSwigger notes.
    
    Args:
        doc_title: Document title (e.g., "SQL injection", "File upload vulnerabilities")
        section_title: Exact section title (e.g., "Lab: SQL injection UNION attack, determining the number of columns")
    
    Returns:
        Full section content with metadata
    """
    with db_connection() as conn:
        row = conn.execute("""
            SELECT doc_title, section_title, section_type, parent_lab_title, content, order_index
            FROM portswigger_kb
            WHERE doc_title = ? AND section_title = ?
        """, (doc_title, section_title)).fetchone()
        
        if not row:
            # Try fuzzy match on section_title
            rows = conn.execute("""
                SELECT doc_title, section_title, section_type, parent_lab_title, content, order_index
                FROM portswigger_kb
                WHERE doc_title = ? AND section_title LIKE ?
                ORDER BY order_index
            """, (doc_title, f"%{section_title}%")).fetchall()
            
            if not rows:
                return f"Section not found: '{section_title}' in document '{doc_title}'"
            
            if len(rows) > 1:
                titles = [r["section_title"] for r in rows]
                return f"Multiple matches found. Be more specific:\n" + "\n".join(f"  - {t}" for t in titles)
            
            row = rows[0]
        
        lab_info = f"\n**Parent Lab:** {row['parent_lab_title']}" if row['parent_lab_title'] else ""
        
        return (
            f"# {row['doc_title']} → {row['section_title']}\n"
            f"**Type:** {row['section_type']}{lab_info}\n"
            f"**Order:** {row['order_index']}\n"
            f"---\n\n"
            f"{row['content']}"
        )


@mcp.tool()
def get_lab_solution(lab_query: str) -> str:
    """
    Get complete lab solution: description + hint + solution + community solutions.
    Combines all lab-related sections into one structured response.
    
    Args:
        lab_query: Lab name or partial name (e.g., "UNION attack determining number of columns")
    
    Returns:
        Structured response with all lab sections combined
    """
    with db_connection() as conn:
        # Find the lab section
        lab_rows = conn.execute("""
            SELECT doc_title, section_title, parent_lab_title, order_index
            FROM portswigger_kb
            WHERE section_type = 'lab' AND (parent_lab_title LIKE ? OR section_title LIKE ?)
            ORDER BY order_index
        """, (f"%{lab_query}%", f"%{lab_query}%")).fetchall()
        
        if not lab_rows:
            return f"No lab found matching: '{lab_query}'"
        
        if len(lab_rows) > 1:
            # Show options
            options = []
            for r in lab_rows:
                options.append(f"  - {r['doc_title']} → {r['section_title']}")
            return f"Multiple labs match '{lab_query}'. Be more specific:\n" + "\n".join(options)
        
        lab = lab_rows[0]
        lab_title = lab['parent_lab_title']
        
        # Get all related sections
        sections = conn.execute("""
            SELECT section_type, section_title, content
            FROM portswigger_kb
            WHERE parent_lab_title = ?
            ORDER BY 
                CASE section_type 
                    WHEN 'lab' THEN 1
                    WHEN 'lab_hint' THEN 2
                    WHEN 'lab_solution' THEN 3
                    WHEN 'community_solutions' THEN 4
                    ELSE 5
                END,
                order_index
        """, (lab_title,)).fetchall()
        
        if not sections:
            return f"Lab '{lab_title}' found but no sections available."
        
        output = [f"# Lab Solution: {lab_title}", f"**Source Document:** {lab['doc_title']}", "---"]
        
        for sec in sections:
            if sec["section_type"] == "lab":
                output.append(f"## 📋 Lab Description\n{sec['content']}")
            elif sec["section_type"] == "lab_hint":
                output.append(f"## 💡 Hint\n{sec['content']}")
            elif sec["section_type"] == "lab_solution":
                output.append(f"## ✅ Solution (Step-by-Step)\n{sec['content']}")
            elif sec["section_type"] == "community_solutions":
                output.append(f"## 👥 Community Solutions\n{sec['content']}")
        
        return "\n\n".join(output)


@mcp.tool()
def list_portswigger_topics() -> str:
    """
    List all 17 PortSwigger topics with lab counts.
    
    Returns:
        Table of topics with document title and number of labs
    """
    with db_connection() as conn:
        # Get doc titles with lab counts
        rows = conn.execute("""
            SELECT 
                doc_title,
                COUNT(CASE WHEN section_type = 'lab' THEN 1 END) as lab_count,
                COUNT(*) as total_sections
            FROM portswigger_kb
            GROUP BY doc_title
            ORDER BY lab_count DESC, doc_title
        """).fetchall()
        
        if not rows:
            return "No PortSwigger notes indexed. Run build_portswigger_notes_index.py first."
        
        output = ["# PortSwigger Web Security Academy - Personal Notes Index", ""]
        output.append(f"{'#':<3} {'Topic':<45} {'Labs':<6} {'Sections':<8}")
        output.append("-" * 65)
        
        total_labs = 0
        for i, row in enumerate(rows, 1):
            output.append(f"{i:<3} {row['doc_title']:<45} {row['lab_count']:<6} {row['total_sections']:<8}")
            total_labs += row['lab_count']
        
        output.append("-" * 65)
        output.append(f"Total: {len(rows)} topics, {total_labs} labs, {sum(r['total_sections'] for r in rows)} sections")
        
        return "\n".join(output)


# ─────────────────────────────────────────────
# HELPER FUNCTIONS (for internal use / scripts)
# ─────────────────────────────────────────────

def get_stats() -> Dict[str, Any]:
    """Get database statistics for PortSwigger KB."""
    with db_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM portswigger_kb").fetchone()[0]
        by_type = conn.execute("""
            SELECT section_type, COUNT(*) as cnt
            FROM portswigger_kb
            GROUP BY section_type
            ORDER BY cnt DESC
        """).fetchall()
        docs = conn.execute("SELECT COUNT(DISTINCT doc_title) FROM portswigger_kb").fetchone()[0]
        labs = conn.execute("SELECT COUNT(*) FROM portswigger_kb WHERE section_type = 'lab'").fetchone()[0]
        
        return {
            "total_sections": total,
            "documents": docs,
            "labs": labs,
            "by_type": {r["section_type"]: r["cnt"] for r in by_type}
        }


if __name__ == "__main__":
    # Quick test when run directly
    stats = get_stats()
    print("PortSwigger KB Stats:")
    for k, v in stats.items():
        print(f"  {k}: {v}")