"""
AGY Bug Bounty MCP - PayloadsAllTheThings Knowledge Base Tools
Menyediakan pencarian full-text atas isi README.md per kategori dan payload mentah
menggunakan dua tabel SQLite:
- patt_kb: FTS5 table untuk setiap kategori dokumentasi
- patt_raw_payloads: tabel reguler untuk setiap payload mentah
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
def search_payload_docs(query: str, limit: int = 5) -> list:
    """
    Pencarian full-text di seluruh README.md kategori PATT.
    Menggunakan SQLite FTS5 dengan snippet highlighting.
    Return path, title, breadcrumb, dan relevant snippet.
    """
    if not query or not query.strip():
        return {"error": "Query tidak boleh kosong", "results": []}

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
                snippet(patt_kb, 3, '<b>', '</b>', '…', 64) AS snippet
            FROM patt_kb
            WHERE patt_kb MATCH ?
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
def get_payload_doc(path: str) -> dict:
    """
    Return isi lengkap satu README kategori PATT berdasarkan path-nya.
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT path, title, breadcrumb, content FROM patt_kb WHERE path = ?",
            (path,),
        ).fetchone()
        if not row:
            return {"error": f"Kategori tidak ditemukan: {path}", "found": False}
        return {
            "found": True,
            "path": row["path"],
            "title": row["title"],
            "breadcrumb": row["breadcrumb"],
            "content": row["content"],
        }
    except Exception as e:
        logger.error("Error fetching category: %s", e)
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@mcp.tool()
def list_payload_categories() -> list:
    """
    Return semua kategori unik beserta jumlah file payload mentah per kategori.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                breadcrumb AS category,
                COUNT(DISTINCT sp.id) as payload_count
            FROM patt_kb pk
            JOIN patt_raw_payloads sp ON sp.category = pk.title
            GROUP BY breadcrumb
            ORDER BY breadcrumb
            """
        ).fetchall()
        categories = [
            {"category": r["category"], "payload_count": r["payload_count"]}
            for r in rows
        ]
        return {"count": len(categories), "categories": categories}
    except Exception as e:
        logger.error("Error listing categories: %s", e)
        return {"error": str(e), "categories": []}
    finally:
        conn.close()


@mcp.tool()
def get_raw_payloads(category: str, limit: int = 50) -> list:
    """
    Return payload mentah dari patt_raw_payloads untuk sebuah kategori.
    Case-insensitive category match.
    """
    if not category or not category.strip():
        return {"error": "Category tidak boleh kosong", "payloads": []}

    safe_category = category.strip()
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT category, source_file, payload, line_number
            FROM patt_raw_payloads
            WHERE LOWER(category) = LOWER(?)
            ORDER BY line_number
            LIMIT ?
            """,
            (safe_category, limit),
        ).fetchall()
        payloads = [
            {
                "category": r["category"],
                "source_file": r["source_file"],
                "payload": r["payload"],
                "line": r["line_number"],
            }
            for r in rows
        ]
        return {"count": len(payloads), "category": safe_category, "payloads": payloads}
    except Exception as e:
        logger.error("Error fetching payloads: %s", e)
        return {"error": str(e), "payloads": []}
    finally:
        conn.close()
