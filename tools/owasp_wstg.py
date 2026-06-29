"""
AGY Bug Bounty MCP - OWASP WSTG Knowledge Base Tools
Provides full-text search over indexed OWASP Web Security Testing Guide
content using SQLite FTS5.
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
def search_wstg(query: str, limit: int = 5) -> list:
    """
    Full-text search across all indexed OWASP WSTG test cases.
    Uses SQLite FTS5 with snippet highlighting.
    Returns up to `limit` results with wstg_id, title, breadcrumb, and relevant snippet.
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
                wstg_id,
                title,
                breadcrumb,
                snippet(owasp_wstg_kb, 2, '<b>', '</b>', '…', 64) AS snippet
            FROM owasp_wstg_kb
            WHERE owasp_wstg_kb MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (safe_query, limit),
        ).fetchall()
        results = [
            {
                "wstg_id": r["wstg_id"],
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
def get_wstg_test(wstg_id: str) -> dict:
    """
    Return the full content of a single WSTG test case by its WSTG-ID
    (e.g. 'WSTG-ATHN-04').
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT wstg_id, title, breadcrumb, content, path FROM owasp_wstg_kb WHERE wstg_id = ?",
            (wstg_id,),
        ).fetchone()
        if not row:
            return {"error": f"Test case not found: {wstg_id}", "found": False}
        return {
            "found": True,
            "wstg_id": row["wstg_id"],
            "title": row["title"],
            "breadcrumb": row["breadcrumb"],
            "content": row["content"],
            "path": row["path"],
        }
    except Exception as e:
        logger.error("Error fetching test: %s", e)
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@mcp.tool()
def list_wstg_categories() -> list:
    """
    Return all unique breadcrumb categories available in the WSTG knowledge base.
    Each entry includes the category name and the test case count.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT breadcrumb, COUNT(*) as test_count
            FROM owasp_wstg_kb
            GROUP BY breadcrumb
            ORDER BY breadcrumb
            """
        ).fetchall()
        categories = [
            {"category": r["breadcrumb"], "test_count": r["test_count"]}
            for r in rows
        ]
        return {"count": len(categories), "categories": categories}
    except Exception as e:
        logger.error("Error listing categories: %s", e)
        return {"error": str(e), "categories": []}
    finally:
        conn.close()
