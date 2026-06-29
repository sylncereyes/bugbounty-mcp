import sqlite3
from datetime import datetime, timezone
import logging
from typing import Optional
from mcp_instance import mcp
from tools.db import DB_PATH, fetch_rfc_text, extract_rfc_title, extract_rfc_status, clean_rfc_pagination, parse_rfc_sections, db_connection

logger = logging.getLogger("agy")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _normalize_section(section_number: str) -> str:
    """Normalize section number: ensure trailing dot for matching database format."""
    if section_number and not section_number.endswith("."):
        return section_number + "."
    return section_number


@ mcp.tool()
def search_rfc(query: str, rfc_number: int = None, limit: int = 5) -> list:
    """Full-text search across indexed HTTP RFC sections.
    Uses SQLite FTS5 with snippet highlighting.
    Optionally filter by RFC number.
    Returns rfc_number, title (from rfc_documents), section_number, section_title, and snippet.
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}

    safe_query = query.strip()
    if '"' not in safe_query and "'" not in safe_query:
        safe_query = ' OR '.join(safe_query.split())

    conn = _get_conn()
    try:
        sql = """
            SELECT
                rfc_sections.rfc_number,
                rfc_documents.title as rfc_title,
                rfc_sections.section_number,
                rfc_sections.section_title,
                snippet(rfc_sections, 3, '<b>', '</b>', '...', 64) AS snippet
            FROM rfc_sections
            LEFT JOIN rfc_documents ON rfc_sections.rfc_number = rfc_documents.rfc_number
            WHERE rfc_sections MATCH ?
        """
        params = [safe_query]
        if rfc_number is not None:
            sql += " AND rfc_sections.rfc_number = ?"
            params.append(rfc_number)
        sql += " ORDER BY rank LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        results = [
            {
                "rfc_number": r["rfc_number"],
                "rfc_title": r["rfc_title"],
                "section_number": r["section_number"],
                "section_title": r["section_title"],
                "snippet": r["snippet"],
            }
            for r in rows
        ]
        return {"query": query, "rfc_filter": rfc_number, "count": len(results), "results": results}
    except Exception as e:
        logger.error("FTS5 RFC search error: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@ mcp.tool()
def get_rfc_section(rfc_number: int, section_number: str) -> dict:
    """Return the full content of a single RFC section by RFC number and section number.
    Accepts section number with or without trailing dot (e.g., "11.2" or "11.2.").
    """
    # Normalize: try both with and without trailing dot
    normalized = _normalize_section(section_number)
    alt_section = section_number if not section_number.endswith(".") else section_number[:-1] + "."

    conn = _get_conn()
    try:
        # Try both formats
        row = conn.execute(
            "SELECT rfc_number, section_number, section_title, content FROM rfc_sections WHERE rfc_number = ? AND section_number = ?",
            (rfc_number, section_number),
        ).fetchone()
        
        if not row:
            row = conn.execute(
                "SELECT rfc_number, section_number, section_title, content FROM rfc_sections WHERE rfc_number = ? AND section_number = ?",
                (rfc_number, normalized),
            ).fetchone()
            
        if not row:
            row = conn.execute(
                "SELECT rfc_number, section_number, section_title, content FROM rfc_sections WHERE rfc_number = ? AND section_number = ?",
                (rfc_number, alt_section),
            ).fetchone()
            
        if not row:
            return {"error": f"Section {section_number} not found in RFC {rfc_number}", "found": False}
        return {
            "found": True,
            "rfc_number": row["rfc_number"],
            "section_number": row["section_number"],
            "section_title": row["section_title"],
            "content": row["content"],
        }
    except Exception as e:
        logger.error("Error fetching RFC section: %s", e)
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@ mcp.tool()
def get_rfc_full(rfc_number: int) -> dict:
    """Return the full text of an RFC (raw, including copyright boilerplate)."""
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT rfc_number, title, status, fetched_at, full_text FROM rfc_documents WHERE rfc_number = ?",
            (rfc_number,),
        ).fetchone()
        if not row:
            return {"error": f"RFC {rfc_number} not found in index", "found": False}
        return {
            "found": True,
            "rfc_number": row["rfc_number"],
            "title": row["title"],
            "status": row["status"],
            "fetched_at": row["fetched_at"],
            "full_text": row["full_text"],
        }
    except Exception as e:
        logger.error("Error fetching RFC full text: %s", e)
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@ mcp.tool()
def list_indexed_rfcs() -> list:
    """Return a list of all indexed RFC numbers and their titles."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT rfc_number, title FROM rfc_documents ORDER BY rfc_number"
        ).fetchall()
        rfcs = [
            {"rfc_number": r["rfc_number"], "title": r["title"]}
            for r in rows
        ]
        return {"count": len(rfcs), "rfcs": rfcs}
    except Exception as e:
        logger.error("Error listing RFCs: %s", e)
        return {"error": str(e), "rfcs": []}
    finally:
        conn.close()


@ mcp.tool()
def add_rfc(rfc_number: int, topic_tag: str = None) -> dict:
    """Fetch and index a new RFC that is not in the seed list.
    Parses sections and stores in rfc_documents and rfc_sections tables.
    topic_tag is optional (for categorizing RFCs like 'HTTP', 'DNS', etc.).
    Returns success/failure confirmation.
    """
    from tools.db import add_rfc_to_db
    return add_rfc_to_db(rfc_number, topic_tag)