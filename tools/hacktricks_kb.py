#!/usr/bin/env python3
"""
AGY Bug Bounty MCP - Hacktricks Knowledge Base Tools
Search Hacktricks methodology and snippets using SQLite FTS5.
"""
import sqlite3
from pathlib import Path
from mcp_instance import mcp
from tools.db import DB_PATH


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_hacktricks_schema() -> None:
    """Initialize Hacktricks tables."""
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hacktricks_entries (
                id              INTEGER PRIMARY KEY,
                path            TEXT UNIQUE,
                title           TEXT,
                content         TEXT,
                methodology     TEXT,
                fetched_at      TEXT
            )
        """)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS hacktricks_fts USING fts5(
                path, title, content, methodology,
                content='hacktricks_entries', content_rowid='id'
            )
        """)
    print("Hacktricks schema initialized")


init_hacktricks_schema()


@mcp.tool()
def sync_hacktricks(hacktricks_dir: str | None = None) -> dict:
    """Sync Hacktricks methodolog dari cloned repo."""
    import os
    from datetime import datetime

    hacktricks_path = hacktricks_dir or str(DB_PATH.parent.parent / "knowledge_base" / "hacktricks")
    conn = _get_conn()
    count = 0

    if not os.path.isdir(hacktricks_path):
        return {"error": f"Directory not found: {hacktricks_path}", "synced": 0}

    # Clear existing
    conn.execute("DELETE FROM hacktricks_entries")
    conn.execute("DELETE FROM hacktricks_fts")

    for md_file in Path(hacktricks_path).rglob("*.md"):
        try:
            content = md_file.read_text(encoding='utf-8')
            # Remove frontmatter if exists
            if content.startswith('---'):
                parts = content.split('---', 2)
                if len(parts) > 2:
                    content = parts[2].strip()

            # Get title from first h1
            title = md_file.stem
            for line in content.split('\n')[:10]:
                if line.startswith('# '):
                    title = line[2:].strip()
                    break

            conn.execute(
                """INSERT INTO hacktricks_entries (path, title, content, methodology) VALUES (?, ?, ?, ?)""",
                (str(md_file), title, content[:2000], md_file.parent.name)
            )
            count += 1
        except Exception as e:
            pass

    # Populate FTS
    for row in conn.execute("SELECT id, path, title, content, methodology FROM hacktricks_entries"):
        conn.execute(
            "INSERT INTO hacktricks_fts (rowid, path, title, content, methodology) VALUES (?, ?, ?, ?, ?)",
            (row["id"], row["path"], row["title"], row["content"], row["methodology"])
        )

    conn.commit()
    conn.close()

    return {"synced": count}


@mcp.tool()
def search_hacktricks(query: str, methodology: str | None = None, limit: int = 20) -> list:
    """Full-text search Hacktricks entries."""
    conn = _get_conn()

    q = query.replace('"', ' ').replace("'", " ")
    if methodology:
        rows = conn.execute(
            """SELECT path, title, content, methodology
               FROM hacktricks_fts
               WHERE hacktricks_fts MATCH ? AND methodology = ?
               LIMIT ?""",
            (q, methodology, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT path, title, content, methodology
               FROM hacktricks_fts
               WHERE hacktricks_fts MATCH ?
               LIMIT ?""",
            (q, limit)
        ).fetchall()

    conn.close()
    return [{"path": r["path"], "title": r["title"], "content": r["content"][:300],
             "methodology": r["methodology"]} for r in rows]


@mcp.tool()
def get_hacktricks_by_path(path: str) -> dict:
    """Get Hacktricks entry by file path."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM hacktricks_entries WHERE path = ?", (path,)).fetchone()
    conn.close()
    if not row:
        return {"found": False}
    return {"found": True, "path": row["path"], "title": row["title"],
            "content": row["content"], "methodology": row["methodology"]}