"""
AGY Bug Bounty MCP - OWASP API Security Top 10 Knowledge Base
Provides full-text search over indexed OWASP API Security Top 10 2023 content
using SQLite FTS5.
"""
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from mcp_instance import mcp
from tools.db import DB_PATH, db_connection


def _extract_section(text: str, section_name: str) -> str:
    """Extract a section from markdown text by header name."""
    pattern = rf"##\s+{re.escape(section_name)}\s*\n(.*?)(?=\n##\s+|\Z)"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def _parse_api_top10_file(filepath: Path) -> dict[str, Any] | None:
    """Parse a single API Top 10 markdown file and extract structured data."""
    content = filepath.read_text(encoding="utf-8")

    # Extract api_id from filename (e.g., 0xa1-broken-object-level-authorization.md -> API1:2023)
    # Filenames follow pattern 0xa[1-9a]-*.md where the second hex digit is the API number
    match = re.match(r"0x[a]([1-9a])-(.+)\.md", filepath.name)
    if not match:
        return None

    # Convert hex digit to decimal for API number
    hex_digit = match.group(1)
    api_num = int(hex_digit, 16)
    api_id = f"API{api_num}:2023"

    # Extract title from first heading - remove API ID prefix if present
    title_match = re.match(r"#\s+(.+)", content)
    title = title_match.group(1).strip() if title_match else ""
    # Remove API ID prefix from title (e.g., "API1:2023 " or "API10:2023 ")
    title = re.sub(r"^API\d+:2023\s+", "", title)

    # Extract description (Is the API Vulnerable? section - handle case variations)
    description = _extract_section(content, "Is the API Vulnerable?")
    if not description:
        description = _extract_section(content, "Is the API Vulnerable")

    # Extract example attack scenarios (handle variations)
    example_attack_scenarios = _extract_section(content, "Example Attack Scenarios")
    if not example_attack_scenarios:
        example_attack_scenarios = _extract_section(content, "Example Attack Scenario")

    # Extract mitigation (How To Prevent - handle variations)
    mitigation = _extract_section(content, "How To Prevent")
    if not mitigation:
        mitigation = _extract_section(content, "How to Prevent")

    # Source URL
    source_url = f"https://owasp.org/API-Security/editions/2023/en/{filepath.name}"

    return {
        "api_id": api_id,
        "title": title,
        "edition": "2023",
        "description": description,
        "example_attack_scenarios": example_attack_scenarios,
        "mitigation": mitigation,
        "source_url": source_url,
    }


def init_api_top10_schema() -> None:
    """Initialize the API Top 10 database schema."""
    with db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS api_top10_entries (
                id INTEGER PRIMARY KEY,
                api_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                edition TEXT NOT NULL,
                description TEXT,
                example_attack_scenarios TEXT,
                mitigation TEXT,
                source_url TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS api_top10_fts USING fts5(
                api_id, title, description, example_attack_scenarios, mitigation,
                content='api_top10_entries', content_rowid='id',
                tokenize='porter unicode61'
            );

            -- Triggers to keep FTS5 in sync
            CREATE TRIGGER IF NOT EXISTS api_top10_fts_insert AFTER INSERT ON api_top10_entries BEGIN
                INSERT INTO api_top10_fts(rowid, api_id, title, description, example_attack_scenarios, mitigation)
                VALUES (new.id, new.api_id, new.title, new.description, new.example_attack_scenarios, new.mitigation);
            END;

            CREATE TRIGGER IF NOT EXISTS api_top10_fts_delete AFTER DELETE ON api_top10_entries BEGIN
                INSERT INTO api_top10_fts(api_top10_fts, rowid, api_id, title, description, example_attack_scenarios, mitigation)
                VALUES ('delete', old.id, old.api_id, old.title, old.description, old.example_attack_scenarios, old.mitigation);
            END;

            CREATE TRIGGER IF NOT EXISTS api_top10_fts_update AFTER UPDATE ON api_top10_entries BEGIN
                INSERT INTO api_top10_fts(api_top10_fts, rowid, api_id, title, description, example_attack_scenarios, mitigation)
                VALUES ('delete', old.id, old.api_id, old.title, old.description, old.example_attack_scenarios, old.mitigation);
                INSERT INTO api_top10_fts(rowid, api_id, title, description, example_attack_scenarios, mitigation)
                VALUES (new.id, new.api_id, new.title, new.description, new.example_attack_scenarios, new.mitigation);
            END;
        """)


def populate_api_top10_from_repo(repo_path: str = "/tmp/API-Security") -> dict[str, Any]:
    """Parse markdown files from the OWASP API Security repo and populate the database."""
    edition_dir = Path(repo_path) / "editions" / "2023" / "en"
    if not edition_dir.exists():
        return {"error": f"Repository path not found: {edition_dir}", "success": False}

    # Only process the 10 actual risk category files (0xa1 through 0xaa)
    # Skip header/notice/toc/intro files (0x00-0x04, 0x10, 0x11) and appendix files (0xb0, 0xb1, 0xd0, 0xd1)
    api_files = sorted(edition_dir.glob("0x[a][1-9a]-*.md"))
    if not api_files:
        return {"error": f"No markdown files found in {edition_dir}", "success": False}

    results = {"success": True, "processed": 0, "errors": []}

    with db_connection() as conn:
        for md_file in api_files:
            try:
                parsed = _parse_api_top10_file(md_file)
                if not parsed:
                    results["errors"].append(f"Failed to parse: {md_file.name}")
                    continue

                # Upsert
                conn.execute(
                    """
                    INSERT INTO api_top10_entries (api_id, title, edition, description, example_attack_scenarios, mitigation, source_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(api_id) DO UPDATE SET
                        title = excluded.title,
                        edition = excluded.edition,
                        description = excluded.description,
                        example_attack_scenarios = excluded.example_attack_scenarios,
                        mitigation = excluded.mitigation,
                        source_url = excluded.source_url
                    """,
                    (
                        parsed["api_id"],
                        parsed["title"],
                        parsed["edition"],
                        parsed["description"],
                        parsed["example_attack_scenarios"],
                        parsed["mitigation"],
                        parsed["source_url"],
                    ),
                )
                results["processed"] += 1

            except Exception as e:
                results["errors"].append(f"{md_file.name}: {e}")

    return results


# Initialize schema on import
init_api_top10_schema()


@mcp.tool()
def api_top10_search(query: str, limit: int = 5) -> dict:
    """
    Full-text search across all OWASP API Security Top 10 2023 categories.
    Uses SQLite FTS5 with snippet highlighting.
    Returns up to `limit` results with api_id, title, and relevant snippet.
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}

    safe_query = query.strip()
    if '"' not in safe_query and "'" not in safe_query:
        safe_query = " OR ".join(safe_query.split())

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT
                api_id,
                title,
                snippet(api_top10_fts, 2, '<b>', '</b>', '…', 64) AS snippet
            FROM api_top10_fts
            WHERE api_top10_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (safe_query, limit),
        ).fetchall()

        results = [
            {
                "api_id": r["api_id"],
                "title": r["title"],
                "snippet": r["snippet"],
            }
            for r in rows
        ]
        return {"query": query, "count": len(results), "results": results}
    except Exception as e:
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def api_top10_get(api_id: str) -> dict:
    """
    Return the full content of a single API Top 10 category by its API-ID
    (e.g. 'API1:2023', 'API7:2023').
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT api_id, title, edition, description, example_attack_scenarios, mitigation, source_url FROM api_top10_entries WHERE api_id = ?",
            (api_id.upper(),),
        ).fetchone()
        if not row:
            return {"error": f"Category not found: {api_id}", "found": False}
        return {
            "found": True,
            "api_id": row["api_id"],
            "title": row["title"],
            "edition": row["edition"],
            "description": row["description"],
            "example_attack_scenarios": row["example_attack_scenarios"],
            "mitigation": row["mitigation"],
            "source_url": row["source_url"],
        }
    except Exception as e:
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@mcp.tool()
def api_top10_list() -> dict:
    """
    List all 10 API Security Top 10 2023 categories (api_id + title only, for quick overview).
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT api_id, title FROM api_top10_entries ORDER BY api_id"
        ).fetchall()
        categories = [
            {"api_id": r["api_id"], "title": r["title"]}
            for r in rows
        ]
        return {"count": len(categories), "categories": categories}
    except Exception as e:
        return {"error": str(e), "categories": []}
    finally:
        conn.close()


@mcp.tool()
def api_top10_sync() -> dict:
    """
    Re-sync the API Top 10 data from the local OWASP API Security repository.
    Useful after updating the repo with `git pull`.
    """
    result = populate_api_top10_from_repo()
    return result