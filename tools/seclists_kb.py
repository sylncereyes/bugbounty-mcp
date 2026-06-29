"""
AGY Bug Bounty MCP - SecLists Knowledge Base Tools
Berisi metadata wordlist mentah (bukan isi file) dari SecLists untuk penetration testing.
Menggunakan SQLite FTS5 untuk pencarian metadata yang cepat tanpa perlu mengetahui nama file.
"""
import sqlite3
import re
from mcp_instance import mcp
from tools.db import DB_PATH
import logging
import itertools
from pathlib import Path

logger = logging.getLogger("agy")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@mcp.tool()
def list_wordlist_categories() -> list:
    """
    Return daftar category unik beserta jumlah file dan total baris per category.
    Berdasarkan seclists_index tabel metadata.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                category,
                COUNT(DISTINCT filename) as file_count,
                SUM(line_count) as total_lines,
                SUM(size_bytes) as total_size
            FROM seclists_index
            GROUP BY category
            ORDER BY category
            """
        ).fetchall()
        categories = [
            {
                "category": r["category"],
                "file_count": r["file_count"],
                "total_lines": r["total_lines"],
                "total_size": r["total_size"],
            }
            for r in rows
        ]
        return {"count": len(categories), "categories": categories}
    except Exception as e:
        logger.error("Error listing categories: %s", e)
        return {"error": str(e), "categories": []}
    finally:
        conn.close()


@mcp.tool()
def find_wordlist(query: str, category: str = None) -> list:
    """
    Cari wordlist berdasarkan kategori, kata kunci nama file, atau isi kata kunci.
    Bukan pencarian full-text file, hanya metadata nama file, kategori, maka cari yang
    sesuai string (case-insensitive).
    """
    if not query or not query.strip():
        return {"error": "Query tidak boleh kosong", "results": []}

    safe_query = query.strip().lower()
    conn = _get_conn()
    try:
        where_clause = "WHERE (LOWER(filename) LIKE ? OR LOWER(category) LIKE ?)"
        params = [f"%{safe_query}%", f"%{safe_query}%"]

        if category:
            where_clause += " AND LOWER(category) = ?"
            params.append(category.strip().lower())

        sql = f"""
        SELECT
            id, file_path, category, subcategory, filename, line_count, size_bytes
        FROM seclists_index
        {where_clause}
        ORDER BY category, filename
        LIMIT 20
        """

        rows = conn.execute(sql, params).fetchall()
        results = [
            {
                "id": r["id"],
                "file_path": r["file_path"],
                "category": r["category"],
                "subcategory": r["subcategory"],
                "filename": r["filename"],
                "line_count": r["line_count"],
                "size_bytes": r["size_bytes"],
            }
            for r in rows
        ]
        return {"count": len(results), "query": query, "category": category, "results": results}
    except Exception as e:
        logger.error("Error finding wordlist: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def get_wordlist_path(query_or_path: str) -> dict:
    """
    Jika input berupa path absolut yang ada di metadata seclists_index,
    langsung return path absolutnya.
    Jika berupa query, treat sebagai query untuk find_wordlist dan return hasil teratas.
    Tool ini yang paling praktis untuk AI karena bisa langsung pakai output sebagai -w ffuf,gobuster.
    """
    if not query_or_path or not query_or_path.strip():
        return {"error": "Query/path tidak boleh kosong", "found": False}

    input_safe = query_or_path.strip()

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT file_path, category, filename FROM seclists_index WHERE file_path = ?",
            (input_safe,),
        ).fetchone()

        if row:
            return {
                "found": True,
                "mode": "exact_path",
                "file_path": row["file_path"],
                "category": row["category"],
                "filename": row["filename"],
                "note": "Path persis cocok"
            }

        results = find_wordlist(query_or_path, category=None)
        if results and results.get("results"):
            r = results["results"][0]
            return {
                "found": True,
                "mode": "search",
                "file_path": r["file_path"],
                "category": r["category"],
                "filename": r["filename"],
                "note": f"Di-index sebagai hasil pencarian teratas untuk '{query_or_path}'"
            }

        return {"found": False, "error": f"Kata kunci '{query_or_path}' tidak ditemukan"}
    finally:
        conn.close()


def _safe_read_lines(filepath: str, limit: int = 100, mode: str = "head", timeout_seconds: int = 5) -> dict:
    """
    Baca maksimal `limit` baris dari file wordlist.
    WAJIB aman untuk file besar — iterasi baris per baris.
    """
    try:
        start_time = __import__("time").time()
        line_count = 0
        lines_read = []

        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            if mode == "head":
                for line in f:
                    if __import__("time").time() - start_time > timeout_seconds:
                        return {"error": f"Read timeout after {timeout_seconds}s", "lines": []}
                    lines_read.append(line.rstrip('\n\r'))
                    line_count += 1
                    if len(lines_read) >= limit:
                        break
            elif mode == "tail":
                buffer = []
                for line in f:
                    if __import__("time").time() - start_time > timeout_seconds:
                        return {"error": f"Read timeout after {timeout_seconds}s", "lines": []}
                    buffer.append(line.rstrip('\n\r'))
                    if len(buffer) > limit:
                        buffer.pop(0)
                    line_count += 1
                lines_read = buffer
            elif mode == "random":
                all_lines = []
                for line in f:
                    if __import__("time").time() - start_time > timeout_seconds:
                        return {"error": f"Read timeout after {timeout_seconds}s", "lines": []}
                    all_lines.append(line.rstrip('\n\r'))
                    line_count += 1
                    if len(all_lines) >= max(1000, limit * 10):
                        break

                import random
                if all_lines:
                    lines_read = random.sample(all_lines, min(limit, len(all_lines)))
                else:
                    lines_read = []
            else:
                return {"error": f"Mode tidak valid: {mode}", "lines": []}

        return {
            "success": True,
            "lines": lines_read,
            "count": len(lines_read),
            "total_lines": line_count,
            "mode": mode
        }
    except Exception as e:
        return {"error": f"Error reading file: {e}", "lines": []}


@mcp.tool()
def get_wordlist_sample(path_or_filename: str, n: int = 50, mode: str = "head") -> dict:
    """
    Baca sampel baris dari file wordlist.
    PENTING: JANGAN load seluruh file ke memory — iteration baris per baris.
    """
    if not path_or_filename or not path_or_filename.strip():
        return {"error": "Path/filename tidak boleh kosong", "sample": []}

    safe_input = path_or_filename.strip()
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT file_path FROM seclists_index WHERE file_path = ? OR filename = ?",
            (safe_input, safe_input),
        ).fetchone()

        if not row:
            return {"error": f"File tidak ditemukan: {path_or_filename}", "sample": []}

        file_path = row["file_path"]
        if not os.path.isfile(file_path):
            return {"error": f"Path tidak valid di filesystem: {file_path}", "sample": []}

        result = _safe_read_lines(file_path, limit=n, mode=mode, timeout_seconds=5)

        return {
            "file_path": file_path,
            "n": n,
            "mode": mode,
            **result
        }
    finally:
        conn.close()


@mcp.tool()
def grep_wordlist(path_or_filename: str, pattern: str, limit: int = 100, regex: bool = False) -> list:
    """
    Cari baris yang match pattern (substring) di file wordlist tertentu.
    Membaca file baris per baris — AMAN untuk file besar dan ada protection timeout.
    """
    if not path_or_filename or not path_or_filename.strip():
        return {"error": "Path/filename tidak boleh kosong"}
    if not pattern or not pattern.strip():
        return {"error": "Pattern tidak boleh kosong"}

    safe_input = path_or_filename.strip()
    safe_pattern = pattern.strip()

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT file_path FROM seclists_index WHERE file_path = ? OR filename = ?",
            (safe_input, safe_input),
        ).fetchone()

        if not row:
            return {"error": f"File tidak ditemukan: {path_or_filename}"}

        file_path = row["file_path"]
        if not os.path.isfile(file_path):
            return {"error": f"Path tidak valid di filesystem: {file_path}"}

        matches = []
        start_time = __import__("time").time()
        timeout_seconds = 5

        try:
            if regex:
                compiled = re.compile(safe_pattern, re.IGNORECASE)
                check_fn = lambda line: bool(compiled.search(line))
            else:
                lower_pattern = safe_pattern.lower()
                check_fn = lambda line: lower_pattern in line.lower()

            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if __import__("time").time() - start_time > timeout_seconds:
                        return {"error": f"Grep timeout after {timeout_seconds}s", "matches": []}

                    line_content = line.rstrip('\n\r')
                    if check_fn(line_content):
                        matches.append(line_content)
                        if len(matches) >= limit:
                            break

            return {
                "file_path": file_path,
                "pattern": safe_pattern,
                "regex_mode": regex,
                "matches": matches,
                "match_count": len(matches),
                "total_read": start_time,
                "timeout_seconds": timeout_seconds
            }
        except re.error as e:
            return {"error": f"Regex tidak valid: {e}"}
        except Exception as e:
            return {"error": f"Error saat grep: {e}"}
    finally:
        conn.close()


@mcp.tool()
def list_seclists_sources() -> list:
    """
    Return daftar source yang terdeteksi untuk SecLists index (git apt dll).
    Membantu user pilih mana yang ingin dipakai.
    """
    sources = [
        {
            "name": "apt",
            "description": "System package manager (seclists dari apt)",
            "command": "apt install seclists",
            "coverage": "Standard wordlists untuk penetration testing",
            "update_method": "apt update && apt upgrade"
        },
        {
            "name": "git",
            "description": "GitHub repository (danielmiessler/SecLists)",
            "command": "git clone --depth 1 https://github.com/danielmiessler/SecLists.git",
            "coverage": "Seluruh repository wordlist, termasuk yang terbaru",
            "update_method": "git pull --ff-only"
        }
    ]
    return {"count": len(sources), "sources": sources}
