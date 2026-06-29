"""
AGY Bug Bounty MCP - HackTricks Knowledge Base Tools
Provides full-text search over indexed HackTricks content using SQLite FTS5.
"""
import sqlite3
from mcp_instance import mcp
from tools.db import DB_PATH
import logging

logger = logging.getLogger("agy")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@mcp.tool()
def search_hacktricks(query: str, limit: int = 5) -> list:
    """
    Full-text search across all indexed HackTricks pages.
    Uses SQLite FTS5 with snippet highlighting.
    Returns up to `limit` results with path, title, breadcrumb, and relevant snippet.
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}

    safe_query = query.strip()
    if '"' not in safe_query and "'" not in safe_query:
        safe_query = ' OR '.join(safe_query.split())

    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                path,
                title,
                breadcrumb,
                snippet(hacktricks_kb, 3, '<b>', '</b>', '…', 64) AS snippet
            FROM hacktricks_kb
            WHERE hacktricks_kb MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (safe_query, limit),
        ).fetchall()
        results = [
            {
                "path": r["path"],
                "title": r["title"],
                "breadcrumb": r["breadcrumb"],
                "snippet": r["snippet"],
            }
            for r in rows
        ]
        return {"query": query, "count": len(results), "results": results}
    except Exception as e:
        logger.error("FTS5 search error: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def get_hacktricks_page(path: str) -> dict:
    """
    Return the full content of a single HackTricks page by its exact path
    (e.g. 'pentesting-web/sql-injection.md').
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT path, title, breadcrumb, content FROM hacktricks_kb WHERE path = ?",
            (path,),
        ).fetchone()
        if not row:
            return {"error": f"Page not found: {path}", "found": False}
        return {
            "found": True,
            "path": row["path"],
            "title": row["title"],
            "breadcrumb": row["breadcrumb"],
            "content": row["content"],
        }
    except Exception as e:
        logger.error("Error fetching page: %s", e)
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@mcp.tool()
def list_hacktricks_categories() -> list:
    """
    Return all unique breadcrumb categories available in the knowledge base.
    Each entry includes the breadcrumb path and the page count.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT breadcrumb, COUNT(*) as page_count
            FROM hacktricks_kb
            GROUP BY breadcrumb
            ORDER BY breadcrumb
            """
        ).fetchall()
        categories = [
            {"category": r["breadcrumb"], "page_count": r["page_count"]}
            for r in rows
        ]
        return {"count": len(categories), "categories": categories}
    except Exception as e:
        logger.error("Error listing categories: %s", e)
        return {"error": str(e), "categories": []}
    finally:
        conn.close()
