#!/usr/bin/env python3
"""
AGY Bug Bounty MCP - HackTheBox Retired Machines Knowledge Base Tools
Provides full-text search over indexed HTB retired machines using SQLite FTS5.
Also manages writeup links and cached writeup content.
"""
import sqlite3
import requests
import time
from mcp_instance import mcp
from tools.db import DB_PATH
import logging

logger = logging.getLogger("agy")

# API constants
HTB_API_BASE = 'https://labs.hackthebox.com/api/v4/machine/list/retired/paginated'
HEADERS = {
    "Authorization": f"Bearer {__import__('os').getenv('HTB_API_TOKEN', '')}",
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": "https://labs.hackthebox.com/",
    "Origin": "https://labs.hackthebox.com"
}


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@mcp.tool()
def search_htb_machines(query: str, limit: int = 10) -> dict:
    """
    Full-text search across all indexed HackTheBox retired machines.
    Uses SQLite FTS5 with snippet highlighting.
    Returns up to `limit` results with machine details and relevant snippet.
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
                htb_machines_index.htb_machine_id,
                htb_machines_index.name,
                htb_machines_index.os,
                htb_machines_index.difficulty_text,
                htb_machines_index.release_date,
                htb_machines_index.difficulty,
                htb_machines_index.static_points,
                htb_machines_index.stars,
                htb_machines_index.avatar,
                htb_machines_index.free,
                htb_machines_index.user_owns_count,
                htb_machines_index.root_owns_count,
                htb_machines_index.is_competitive,
                htb_machines_index.recommended,
                snippet(htb_machines_index_fts, 2, '<b>', '</b>', '…', 64) AS snippet
            FROM htb_machines_index_fts
            JOIN htb_machines_index ON htb_machines_index_fts.rowid = htb_machines_index.rowid
            WHERE htb_machines_index_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (safe_query, limit),
        ).fetchall()
        results = [
            {
                "htb_machine_id": r["htb_machine_id"],
                "name": r["name"],
                "os": r["os"],
                "difficulty_text": r["difficulty_text"],
                "release_date": r["release_date"],
                "difficulty": r["difficulty"],
                "static_points": r["static_points"],
                "stars": r["stars"],
                "avatar": r["avatar"],
                "free": r["free"],
                "user_owns_count": r["user_owns_count"],
                "root_owns_count": r["root_owns_count"],
                "is_competitive": r["is_competitive"],
                "recommended": r["recommended"],
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
def get_htb_machine(htb_machine_id: int) -> dict:
    """
    Return the full details of a single HTB retired machine by its ID.
    """
    conn = _get_conn()
    try:
        row = conn.execute(
            """
            SELECT
                htb_machine_id, name, os, difficulty_text, release_date, points,
                stars, avatar, free, difficulty, static_points, user_owns_count,
                root_owns_count, is_competitive, recommended, indexed_at, updated_at
            FROM htb_machines_index
            WHERE htb_machine_id = ?
            """,
            (htb_machine_id,),
        ).fetchone()
        if not row:
            return {"error": f"Machine not found: {htb_machine_id}", "found": False}
        return {
            "found": True,
            "htb_machine_id": row["htb_machine_id"],
            "name": row["name"],
            "os": row["os"],
            "difficulty_text": row["difficulty_text"],
            "release_date": row["release_date"],
            "points": row["points"],
            "stars": row["stars"],
            "avatar": row["avatar"],
            "free": row["free"],
            "difficulty": row["difficulty"],
            "static_points": row["static_points"],
            "user_owns_count": row["user_owns_count"],
            "root_owns_count": row["root_owns_count"],
            "is_competitive": row["is_competitive"],
            "recommended": row["recommended"],
            "indexed_at": row["indexed_at"],
            "updated_at": row["updated_at"],
        }
    except Exception as e:
        logger.error("Error fetching machine: %s", e)
        return {"error": str(e), "found": False}
    finally:
        conn.close()


@mcp.tool()
def list_htb_machines_by_difficulty(difficulty_text: str = None, limit: int = 20, offset: int = 0) -> dict:
    """
    List HTB retired machines, optionally filtered by difficulty (Easy, Medium, Hard, Insane).
    Returns paginated results.
    """
    conn = _get_conn()
    try:
        if difficulty_text:
            rows = conn.execute(
                """
                SELECT htb_machine_id, name, os, difficulty_text, release_date, difficulty,
                       static_points, stars, avatar, free, user_owns_count, root_owns_count
                FROM htb_machines_index
                WHERE difficulty_text = ?
                ORDER BY difficulty, htb_machine_id
                LIMIT ? OFFSET ?
                """,
                (difficulty_text, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT htb_machine_id, name, os, difficulty_text, release_date, difficulty,
                       static_points, stars, avatar, free, user_owns_count, root_owns_count
                FROM htb_machines_index
                ORDER BY difficulty, htb_machine_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        results = [
            {
                "htb_machine_id": r["htb_machine_id"],
                "name": r["name"],
                "os": r["os"],
                "difficulty_text": r["difficulty_text"],
                "release_date": r["release_date"],
                "difficulty": r["difficulty"],
                "static_points": r["static_points"],
                "stars": r["stars"],
                "avatar": r["avatar"],
                "free": r["free"],
                "user_owns_count": r["user_owns_count"],
                "root_owns_count": r["root_owns_count"],
            }
            for r in rows
        ]

        # Get total count
        if difficulty_text:
            total = conn.execute(
                "SELECT COUNT(*) FROM htb_machines_index WHERE difficulty_text = ?",
                (difficulty_text,)
            ).fetchone()[0]
        else:
            total = conn.execute("SELECT COUNT(*) FROM htb_machines_index").fetchone()[0]

        return {
            "filter": difficulty_text,
            "count": len(results),
            "total": total,
            "offset": offset,
            "limit": limit,
            "results": results,
        }
    except Exception as e:
        logger.error("Error listing machines: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def list_htb_machines_by_os(os: str = None, limit: int = 20, offset: int = 0) -> dict:
    """
    List HTB retired machines, optionally filtered by OS (Linux, Windows).
    Returns paginated results.
    """
    conn = _get_conn()
    try:
        if os:
            rows = conn.execute(
                """
                SELECT htb_machine_id, name, os, difficulty_text, release_date, difficulty,
                       static_points, stars, avatar, free, user_owns_count, root_owns_count
                FROM htb_machines_index
                WHERE os = ?
                ORDER BY difficulty, htb_machine_id
                LIMIT ? OFFSET ?
                """,
                (os, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT htb_machine_id, name, os, difficulty_text, release_date, difficulty,
                       static_points, stars, avatar, free, user_owns_count, root_owns_count
                FROM htb_machines_index
                ORDER BY difficulty, htb_machine_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        results = [
            {
                "htb_machine_id": r["htb_machine_id"],
                "name": r["name"],
                "os": r["os"],
                "difficulty_text": r["difficulty_text"],
                "release_date": r["release_date"],
                "difficulty": r["difficulty"],
                "static_points": r["static_points"],
                "stars": r["stars"],
                "avatar": r["avatar"],
                "free": r["free"],
                "user_owns_count": r["user_owns_count"],
                "root_owns_count": r["root_owns_count"],
            }
            for r in rows
        ]

        # Get total count
        if os:
            total = conn.execute(
                "SELECT COUNT(*) FROM htb_machines_index WHERE os = ?",
                (os,)
            ).fetchone()[0]
        else:
            total = conn.execute("SELECT COUNT(*) FROM htb_machines_index").fetchone()[0]

        return {
            "filter": os,
            "count": len(results),
            "total": total,
            "offset": offset,
            "limit": limit,
            "results": results,
        }
    except Exception as e:
        logger.error("Error listing machines: %s", e)
        return {"error": str(e), "results": []}
    finally:
        conn.close()


@mcp.tool()
def search_htb_writeup_links(htb_machine_id: int) -> dict:
    """
    Return all known writeup links for a specific HTB machine.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT id, htb_machine_id, writeup_url, source_domain, found_at
            FROM htb_writeup_links
            WHERE htb_machine_id = ?
            ORDER BY found_at DESC
            """,
            (htb_machine_id,),
        ).fetchall()

        results = [
            {
                "id": r["id"],
                "htb_machine_id": r["htb_machine_id"],
                "writeup_url": r["writeup_url"],
                "source_domain": r["source_domain"],
                "found_at": r["found_at"],
            }
            for r in rows
        ]

        return {
            "htb_machine_id": htb_machine_id,
            "count": len(results),
            "writeups": results,
        }
    except Exception as e:
        logger.error("Error fetching writeup links: %s", e)
        return {"error": str(e), "writeups": []}
    finally:
        conn.close()


@mcp.tool()
def add_htb_writeup_link(htb_machine_id: int, writeup_url: str, source_domain: str = None) -> dict:
    """
    Add a writeup link for an HTB machine. The source_domain is auto-extracted if not provided.
    Validates that the machine exists in the retired index before inserting.
    """
    if not source_domain:
        from urllib.parse import urlparse
        source_domain = urlparse(writeup_url).netloc

    conn = _get_conn()
    try:
        # Guardrail: verify machine exists in retired index
        machine = conn.execute(
            "SELECT 1 FROM htb_machines_index WHERE htb_machine_id = ?",
            (htb_machine_id,)
        ).fetchone()
        if not machine:
            return {
                "success": False,
                "error": f"Machine {htb_machine_id} not found in retired index — cannot add writeup link"
            }

        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO htb_writeup_links (htb_machine_id, writeup_url, source_domain)
            VALUES (?, ?, ?)
            """,
            (htb_machine_id, writeup_url, source_domain),
        )
        conn.commit()

        if cursor.rowcount > 0:
            return {
                "success": True,
                "message": f"Writeup link added for machine {htb_machine_id}",
                "id": cursor.lastrowid,
            }
        else:
            return {
                "success": False,
                "message": f"Writeup link already exists for machine {htb_machine_id}",
            }
    except Exception as e:
        logger.error("Error adding writeup link: %s", e)
        return {"error": str(e), "success": False}
    finally:
        conn.close()


@mcp.tool()
def get_htb_writeup_content(writeup_url: str) -> dict:
    """
    Fetch and cache writeup content from a URL.
    Returns cached content if available and not expired (7 days).
    """
    conn = _get_conn()
    try:
        # Check cache first
        row = conn.execute(
            """
            SELECT content, fetched_at, expires_at
            FROM htb_writeup_content_cache
            WHERE writeup_url = ?
            """,
            (writeup_url,),
        ).fetchone()

        if row:
            # Check if expired
            if row["expires_at"] is None or row["expires_at"] > time.time():
                return {
                    "cached": True,
                    "writeup_url": writeup_url,
                    "content": row["content"],
                    "fetched_at": row["fetched_at"],
                }

        # Fetch fresh content
        import re
        resp = requests.get(writeup_url, timeout=30, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        resp.raise_for_status()

        # Extract main content (simple heuristic - get article text)
        content = resp.text
        # Remove scripts and styles
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
        content = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL)
        # Get text content
        content = re.sub(r'<[^>]+>', ' ', content)
        content = re.sub(r'\s+', ' ', content).strip()

        # Cache for 7 days
        expires_at = time.time() + 7 * 24 * 3600
        conn.execute(
            """
            INSERT OR REPLACE INTO htb_writeup_content_cache (writeup_url, content, expires_at)
            VALUES (?, ?, ?)
            """,
            (writeup_url, content, expires_at),
        )
        conn.commit()

        return {
            "cached": False,
            "writeup_url": writeup_url,
            "content": content[:50000],  # Limit to 50KB
            "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        logger.error("Error fetching writeup content: %s", e)
        return {"error": str(e), "writeup_url": writeup_url}
    finally:
        conn.close()


@mcp.tool()
def get_htb_stats() -> dict:
    """
    Return statistics about the HTB retired machines index.
    """
    conn = _get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) FROM htb_machines_index").fetchone()[0]

        by_difficulty = conn.execute(
            """
            SELECT difficulty_text, COUNT(*) as count
            FROM htb_machines_index
            GROUP BY difficulty_text
            ORDER BY MIN(difficulty)
            """
        ).fetchall()

        by_os = conn.execute(
            """
            SELECT os, COUNT(*) as count
            FROM htb_machines_index
            GROUP BY os
            ORDER BY count DESC
            """
        ).fetchall()

        writeup_count = conn.execute("SELECT COUNT(*) FROM htb_writeup_links").fetchone()[0]
        cached_writeups = conn.execute("SELECT COUNT(*) FROM htb_writeup_content_cache").fetchone()[0]

        return {
            "total_machines": total,
            "by_difficulty": [{"difficulty": r["difficulty_text"], "count": r["count"]} for r in by_difficulty],
            "by_os": [{"os": r["os"], "count": r["count"]} for r in by_os],
            "total_writeup_links": writeup_count,
            "cached_writeups": cached_writeups,
        }
    except Exception as e:
        logger.error("Error getting stats: %s", e)
        return {"error": str(e)}
    finally:
        conn.close()


@mcp.tool()
def sync_htb_machines_from_api() -> dict:
    """
    Sync retired machines from HTB API (requires HTB_API_TOKEN in .env).
    This is an administrative tool - typically run once or on schedule.
    """
    import os
    from dotenv import load_dotenv

    load_dotenv(dotenv_path='/home/kali/bugbounty-mcp/.env', override=True)
    token = os.getenv('HTB_API_TOKEN')

    if not token or token == 'your_token_here':
        return {"error": "HTB_API_TOKEN not configured in .env", "synced": 0}

    # Update headers with current token
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://labs.hackthebox.com/",
        "Origin": "https://labs.hackthebox.com"
    }

    conn = _get_conn()
    cursor = conn.cursor()

    try:
        # Fetch first page to get total pages
        resp = requests.get(f"{HTB_API_BASE}?retired=1&page=1", headers=headers, timeout=30)
        if resp.status_code == 401:
            return {"error": "Unauthorized - check HTB_API_TOKEN", "synced": 0}
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}", "synced": 0}

        first_page = resp.json()
        total_pages = first_page['meta']['last_page']
        synced = 0
        skipped = 0

        for page in range(1, total_pages + 1):
            if page == 1:
                data = first_page
            else:
                time.sleep(1)  # Rate limiting
                resp = requests.get(f"{HTB_API_BASE}?retired=1&page={page}", headers=headers, timeout=30)
                if resp.status_code != 200:
                    logger.error(f"Failed to fetch page {page}: {resp.status_code}")
                    break
                data = resp.json()

            for machine in data['data']:
                # Verify retired (active is None for retired machines)
                if machine.get('active') is None:
                    cursor.execute('''
                        INSERT INTO htb_machines_index (
                            htb_machine_id, name, os, difficulty_text, release_date, points, stars,
                            avatar, free, difficulty, static_points, user_owns_count, root_owns_count,
                            is_competitive, recommended, is_retired_verified, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'))
                        ON CONFLICT(htb_machine_id) DO UPDATE SET
                            name=excluded.name,
                            os=excluded.os,
                            difficulty_text=excluded.difficulty_text,
                            release_date=excluded.release_date,
                            points=excluded.points,
                            stars=excluded.stars,
                            avatar=excluded.avatar,
                            free=excluded.free,
                            difficulty=excluded.difficulty,
                            static_points=excluded.static_points,
                            user_owns_count=excluded.user_owns_count,
                            root_owns_count=excluded.root_owns_count,
                            is_competitive=excluded.is_competitive,
                            recommended=excluded.recommended,
                            is_retired_verified=excluded.is_retired_verified,
                            updated_at=datetime('now')
                    ''', (
                        machine['id'],
                        machine['name'],
                        machine.get('os'),
                        machine.get('difficultyText'),
                        machine.get('release'),
                        machine.get('points', 0),
                        machine.get('star', 0.0),
                        machine.get('avatar') or '',
                        machine.get('free', False),
                        machine.get('difficulty', 0),
                        machine.get('static_points', 0),
                        machine.get('user_owns_count', 0),
                        machine.get('root_owns_count', 0),
                        machine.get('is_competitive', False),
                        machine.get('recommended', False)
                    ))
                    synced += 1
                else:
                    skipped += 1

            conn.commit()
            logger.info(f"Page {page}/{total_pages} processed")

        return {
            "synced": synced,
            "skipped": skipped,
            "total_pages": total_pages,
            "message": f"Sync complete: {synced} machines indexed, {skipped} skipped"
        }
    except Exception as e:
        logger.error("Error syncing from API: %s", e)
        conn.rollback()
        return {"error": str(e), "synced": 0}
    finally:
        conn.close()


# Domains to exclude from writeup discovery (official HTB sites, not community writeups)
EXCLUDE_DOMAINS = {
    "hackthebox.com",
    "www.hackthebox.com",
    "forum.hackthebox.com",
    "labs.hackthebox.com",
    "app.hackthebox.com",
    "academy.hackthebox.com",
}


@mcp.tool()
def find_htb_writeup(machine_name: str) -> dict:
    """
    Auto-discover writeups for an HTB retired machine using DDGS search.
    - Validates machine exists in retired index (case-insensitive name match)
    - Searches DDGS for "{machine_name} hackthebox writeup" (max 5 results)
    - Filters out official HTB domains (EXCLUDE_DOMAINS)
    - Stores found URLs in htb_writeup_links table
    - Returns list of discovered writeup URLs
    """
    from ddgs import DDGS
    from urllib.parse import urlparse

    conn = _get_conn()
    try:
        # Guardrail: verify machine exists in retired index (case-insensitive)
        machine = conn.execute(
            "SELECT htb_machine_id, name FROM htb_machines_index WHERE LOWER(name) = LOWER(?)",
            (machine_name.strip(),)
        ).fetchone()

        if not machine:
            return {
                "error": f"Machine '{machine_name}' tidak ditemukan di index retired — mungkin masih aktif atau nama salah",
                "found": 0,
                "writeups": []
            }

        htb_machine_id = machine["htb_machine_id"]
        actual_name = machine["name"]

        # Search DDGS
        query = f"{actual_name} hackthebox writeup"
        results = []
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=5):
                url = r.get("href") or r.get("url")
                if url:
                    domain = urlparse(url).netloc
                    # Filter out excluded domains
                    if domain in EXCLUDE_DOMAINS:
                        continue
                    # Insert into writeup_links
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO htb_writeup_links (htb_machine_id, writeup_url, source_domain)
                        VALUES (?, ?, ?)
                        """,
                        (htb_machine_id, url, domain)
                    )
                    results.append({"writeup_url": url, "source_domain": domain})

        conn.commit()

        return {
            "machine_name": actual_name,
            "htb_machine_id": htb_machine_id,
            "found": len(results),
            "writeups": results
        }
    except Exception as e:
        logger.error("Error finding writeup for %s: %s", machine_name, e)
        return {"error": str(e), "found": 0, "writeups": []}
    finally:
        conn.close()