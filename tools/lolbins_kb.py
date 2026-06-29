#!/usr/bin/env python3
"""
AGY Bug Bounty MCP - Living-off-the-Land Binaries Knowledge Base Tools
Provides search over GTFOBins (Linux) and LOLBAS (Windows) entries using SQLite FTS5.
"""
import sqlite3
import yaml
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from mcp_instance import mcp
from tools.db import DB_PATH
import logging

logger = logging.getLogger("agy")

CACHE_DIR = Path(__file__).parent.parent / "knowledge_base"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _sync_gtfobins() -> dict:
    """Sync GTFOBins entries from cloned repository to database."""
    gtfobins_dir = CACHE_DIR / "gtfobins" / "_gtfobins"
    if not gtfobins_dir.exists():
        return {"error": "GTFOBins cache not found. Run git clone first.", "synced": 0}

    source_url = "https://github.com/GTFOBins/GTFOBins.github.io"
    fetched_at = datetime.now(timezone.utc).isoformat()
    synced = 0
    parse_errors = []
    unique_violations = 0

    with _get_conn() as conn:
        # Clear existing entries for fresh sync
        conn.execute("DELETE FROM gtfobins_entries")
        conn.execute("DELETE FROM lolbins_search WHERE source_table = 'gtfobins_entries'")

        for bin_file in gtfobins_dir.iterdir():
            if bin_file.name.startswith('.'):
                continue

            binary_name = bin_file.name
            try:
                content = bin_file.read_text(encoding='utf-8')
                # Parse YAML frontmatter - content is just YAML, no markdown after
                data = yaml.safe_load(content)
                if not data or 'functions' not in data:
                    parse_errors.append(f"{bin_file.name}: no functions found")
                    continue

                functions = data['functions']
                for func_type, entries in functions.items():
                    if not isinstance(entries, list):
                        entries = [entries]

                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue

                        code = entry.get('code', '')
                        if not code:
                            continue

                        # Handle multiline code (strip leading whitespace artifact)
                        if isinstance(code, str):
                            code = code.strip()

                        # Get description from comment field
                        description = entry.get('comment', '')
                        if isinstance(description, str):
                            description = description.strip()

                        try:
                            conn.execute(
                                """INSERT OR IGNORE INTO gtfobins_entries
                                   (binary_name, function_type, code, description, mitre_technique_id, source_url, fetched_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (binary_name, func_type, code, description, None, source_url, fetched_at)
                            )
                            # Check if row was actually inserted (not a duplicate)
                            if conn.execute(
                                "SELECT COUNT(*) FROM gtfobins_entries WHERE binary_name = ? AND function_type = ? AND code = ?",
                                (binary_name, func_type, code)
                            ).fetchone()[0] == 1:
                                # Insert into FTS5
                                conn.execute(
                                    """INSERT INTO lolbins_search
                                       (binary_name, platform, category, payload, description, source_table, source_id)
                                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                    (binary_name, 'linux', func_type, code, description or '', 'gtfobins_entries',
                                     conn.execute("SELECT last_insert_rowid()").fetchone()[0])
                                )
                                synced += 1
                        except sqlite3.IntegrityError:
                            unique_violations += 1

            except yaml.YAMLError as e:
                parse_errors.append(f"{bin_file.name}: YAML parse error - {e}")
            except Exception as e:
                parse_errors.append(f"{bin_file.name}: {e}")

        conn.commit()

    return {
        "synced": synced,
        "parse_errors": parse_errors,
        "unique_violations": unique_violations,
    }


def _sync_lolbas() -> dict:
    """Sync LOLBAS entries from cloned repository to database."""
    lolbas_dir = CACHE_DIR / "lolbas" / "yml"
    if not lolbas_dir.exists():
        return {"error": "LOLBAS cache not found. Run git clone first.", "synced": 0}

    source_url = "https://github.com/LOLBAS-Project/LOLBAS"
    fetched_at = datetime.now(timezone.utc).isoformat()
    synced = 0
    parse_errors = []

    with _get_conn() as conn:
        # Clear existing entries for fresh sync
        conn.execute("DELETE FROM lolbas_entries")
        conn.execute("DELETE FROM lolbins_search WHERE source_table = 'lolbas_entries'")

        # Walk all yml subdirectories (OSBinaries, OSLibraries, OSScripts, OtherMSBinaries)
        for subdir in ["OSBinaries", "OSLibraries", "OSScripts", "OtherMSBinaries"]:
            subdir_path = lolbas_dir / subdir
            if not subdir_path.exists():
                continue

            for yml_file in subdir_path.glob("*.yml"):
                try:
                    content = yml_file.read_text(encoding='utf-8')
                    data = yaml.safe_load(content)
                    if not data:
                        parse_errors.append(f"{yml_file.name}: empty or invalid YAML")
                        continue

                    binary_name = data.get('Name', yml_file.stem)
                    commands = data.get('Commands', [])

                    # Extract full paths if available
                    full_paths = data.get('Full_Path', [])
                    full_path = full_paths[0].get('Path', '') if full_paths else ''

                    for cmd_entry in commands:
                        if not isinstance(cmd_entry, dict):
                            continue

                        command = cmd_entry.get('Command', '')
                        if not command:
                            continue

                        cmd_desc = cmd_entry.get('Description', '')
                        usecase = cmd_entry.get('Usecase', '')
                        category = cmd_entry.get('Category', '')
                        privs = cmd_entry.get('Privileges', '')
                        mitre_id = cmd_entry.get('MitreID', '')
                        os = cmd_entry.get('OperatingSystem', '')

                        conn.execute(
                            """INSERT OR IGNORE INTO lolbas_entries
                               (binary_name, full_path, command, command_description, usecase,
                                category, privileges_required, mitre_attack_id, operating_system,
                                source_url, fetched_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (binary_name, full_path, command, cmd_desc, usecase,
                             category, privs, mitre_id, os, source_url, fetched_at)
                        )
                        # Check if row was actually inserted
                        if conn.execute(
                            "SELECT COUNT(*) FROM lolbas_entries WHERE binary_name = ? AND command = ?",
                            (binary_name, command)
                        ).fetchone()[0] == 1:
                            conn.execute(
                                """INSERT INTO lolbins_search
                                   (binary_name, platform, category, payload, description, source_table, source_id)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (binary_name, 'windows', category, command, cmd_desc or '', 'lolbas_entries',
                                 conn.execute("SELECT last_insert_rowid()").fetchone()[0])
                            )
                            synced += 1

                except yaml.YAMLError as e:
                    parse_errors.append(f"{yml_file.name}: YAML parse error - {e}")
                except Exception as e:
                    parse_errors.append(f"{yml_file.name}: {e}")

        conn.commit()

    return {
        "synced": synced,
        "parse_errors": parse_errors,
    }


def sync_lolbins() -> dict:
    """Sync both GTFOBins and LOLBAS entries to database. Idempotent - can be run repeatedly."""
    gtfobins_result = _sync_gtfobins()
    lolbas_result = _sync_lolbas()

    return {
        "gtfobins": gtfobins_result,
        "lolbas": lolbas_result,
        "success": True,
    }


@mcp.tool()
def search_lolbins(query: str, platform: str = None, limit: int = 10) -> dict:
    """
    Full-text search across both GTFOBins (Linux) and LOLBAS (Windows) entries.
    Uses SQLite FTS5 with snippet highlighting.

    Args:
        query: Search query string (supports FTS5 syntax)
        platform: Optional filter by platform ('linux' or 'windows')
        limit: Maximum results to return (default 10)

    Returns:
        Dict with query, count, and results list
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty", "results": []}

    safe_query = query.strip()
    if '"' not in safe_query and "'" not in safe_query:
        safe_query = ' OR '.join(safe_query.split())

    conn = _get_conn()
    try:
        if platform:
            platform = platform.lower()
            rows = conn.execute(
                """SELECT binary_name, platform, category, payload, description,
                          snippet(lolbins_search, 4, '<b>', '</b>', '…', 64) AS snippet
                   FROM lolbins_search
                   WHERE lolbins_search MATCH ? AND platform = ?
                   LIMIT ?""",
                (safe_query, platform, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT binary_name, platform, category, payload, description,
                          snippet(lolbins_search, 4, '<b>', '</b>', '…', 64) AS snippet
                   FROM lolbins_search
                   WHERE lolbins_search MATCH ?
                   LIMIT ?""",
                (safe_query, limit)
            ).fetchall()

        results = [
            {
                "binary_name": r["binary_name"],
                "platform": r["platform"],
                "category": r["category"],
                "payload": r["payload"],
                "description": r["description"],
                "snippet": r["snippet"],
            }
            for r in rows
        ]
        return {"query": query, "platform": platform, "count": len(results), "results": results}
    except Exception as e:
        logger.error("FTS5 search error: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def get_gtfobins_by_binary(binary_name: str) -> dict:
    """
    Get all GTFOBins entries for a specific binary name.

    Args:
        binary_name: Name of the binary (e.g., 'sudo', 'find', 'nmap')

    Returns:
        Dict with binary_name, count, and entries list
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """SELECT function_type, code, description, mitre_technique_id, fetched_at
               FROM gtfobins_entries
               WHERE binary_name = ?
               ORDER BY function_type""",
            (binary_name,)
        ).fetchall()

        entries = [
            {
                "function_type": r["function_type"],
                "code": r["code"],
                "description": r["description"],
                "mitre_technique_id": r["mitre_technique_id"],
            }
            for r in rows
        ]
        return {"binary_name": binary_name, "count": len(entries), "entries": entries}
    except Exception as e:
        logger.error("Error fetching GTFOBins entries: %s", e)
        return {"error": str(e), "entries": []}
    finally:
        conn.close()


@mcp.tool()
def get_lolbas_by_binary(binary_name: str) -> dict:
    """
    Get all LOLBAS entries for a specific binary/library/script name.

    Args:
        binary_name: Name of the binary (e.g., 'Regsvr32', 'certutil')

    Returns:
        Dict with binary_name, count, and entries list
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """SELECT binary_name, full_path, command, command_description, usecase,
                      category, privileges_required, mitre_attack_id, operating_system
               FROM lolbas_entries
               WHERE binary_name = ?
               ORDER BY category""",
            (binary_name,)
        ).fetchall()

        entries = [
            {
                "binary_name": r["binary_name"],
                "full_path": r["full_path"],
                "command": r["command"],
                "command_description": r["command_description"],
                "usecase": r["usecase"],
                "category": r["category"],
                "privileges_required": r["privileges_required"],
                "mitre_attack_id": r["mitre_attack_id"],
                "operating_system": r["operating_system"],
            }
            for r in rows
        ]
        return {"binary_name": binary_name, "count": len(entries), "entries": entries}
    except Exception as e:
        logger.error("Error fetching LOLBAS entries: %s", e)
        return {"error": str(e), "entries": []}
    finally:
        conn.close()


@mcp.tool()
def list_lolbins_by_category(category: str, platform: str = None) -> dict:
    """
    List all LOLBins entries filtered by category and optionally by platform.

    Args:
        category: Category to filter by (e.g., 'shell', 'file-read', 'Download', 'AWL Bypass')
        platform: Optional filter ('linux' or 'windows')

    Returns:
        Dict with filter info, count, and results list
    """
    conn = _get_conn()
    try:
        if platform:
            platform = platform.lower()
            rows = conn.execute(
                """SELECT binary_name, platform, payload, description
                   FROM lolbins_search
                   WHERE category = ? AND platform = ?""",
                (category, platform)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT binary_name, platform, payload, description
                   FROM lolbins_search
                   WHERE category = ?""",
                (category,)
            ).fetchall()

        results = [
            {
                "binary_name": r["binary_name"],
                "platform": r["platform"],
                "payload": r["payload"],
                "description": r["description"],
            }
            for r in rows
        ]
        return {
            "filter": {"category": category, "platform": platform},
            "count": len(results),
            "results": results
        }
    except Exception as e:
        logger.error("Error listing LOLBins by category: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def get_lolbins_stats() -> dict:
    """
    Return statistics about indexed GTFOBins and LOLBAS entries.
    """
    conn = _get_conn()
    try:
        gtfobins_count = conn.execute("SELECT COUNT(*) FROM gtfobins_entries").fetchone()[0]
        lolbas_count = conn.execute("SELECT COUNT(*) FROM lolbas_entries").fetchone()[0]

        # Count by platform
        linux_bins = conn.execute(
            "SELECT COUNT(DISTINCT binary_name) FROM gtfobins_entries"
        ).fetchone()[0]

        windows_bins = conn.execute(
            "SELECT COUNT(DISTINCT binary_name) FROM lolbas_entries"
        ).fetchone()[0]

        return {
            "gtfobins_entries": gtfobins_count,
            "lolbas_entries": lolbas_count,
            "total_entries": gtfobins_count + lolbas_count,
            "unique_linux_binaries": linux_bins,
            "unique_windows_binaries": windows_bins,
        }
    except Exception as e:
        logger.error("Error getting LOLBins stats: %s", e)
        return {"error": str(e)}
    finally:
        conn.close()