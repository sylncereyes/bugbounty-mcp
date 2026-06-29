#!/usr/bin/env python3
"""
CTF Writeups Knowledge Base - MCP Tools
Provides search, content fetch (with cache), and tag listing for CTFtime.org writeups.
"""

import sqlite3
import json
import re
import time
import requests
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

DB_PATH = Path(__file__).parent.parent / "database" / "bugbounty.db"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",  # Removed 'br' (brotli) - not available in all environments
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

CACHE_TTL_DAYS = 60
STUB_LENGTH_THRESHOLD = 200  # chars - if content shorter and has "Original writeup" link, fetch external

# Non-article domains that should NOT be fetched as articles
NON_ARTICLE_DOMAINS = [
    "youtube.com",
    "youtu.be",
    "twitter.com",
    "x.com",
    "t.co",
    "vimeo.com",
    "twitch.tv",
    "drive.google.com",
    "docs.google.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "pastebin.com",
    "gist.github.com",
]


def is_non_article_url(url: str) -> bool:
    """Check if URL points to a non-article domain (video, social media, etc.)."""
    from urllib.parse import urlparse
    try:
        domain = urlparse(url).netloc.lower()
        for nd in NON_ARTICLE_DOMAINS:
            if nd in domain:
                return True
    except Exception:
        pass
    return False


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_cache_table(conn):
    """Create content cache table if not exists."""
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS ctf_writeup_content_cache (
            writeup_id INTEGER PRIMARY KEY,
            content TEXT NOT NULL,
            source_url TEXT NOT NULL,      -- URL where content was fetched from (ctftime or external)
            fetched_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT                -- fetched_at + 60 days
        )
    """)
    conn.commit()


def search_ctf_writeups(query: str, tag: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Search CTF writeups index using FTS5.

    Args:
        query: Search query (matches event_name, task_name, tags, author, team)
        tag: Optional tag filter (exact match in tags JSON array)
        limit: Maximum results to return

    Returns:
        List of dicts with ctftime_writeup_id, event_name, task_name, tags, author, team, ctftime_url
    """
    conn = get_conn()
    try:
        c = conn.cursor()

        # Build FTS query
        fts_query = query
        if tag:
            # Add tag filter - FTS5 doesn't directly support JSON array search,
            # so we'll filter in Python after FTS search
            pass

        sql = """
            SELECT i.ctftime_writeup_id, i.event_name, i.task_name, i.tags, i.author, i.team, i.ctftime_url,
                   bm25(ctf_writeups_index_fts) as rank
            FROM ctf_writeups_index_fts f
            JOIN ctf_writeups_index i ON i.rowid = f.rowid
            WHERE ctf_writeups_index_fts MATCH ?
            ORDER BY rank
            LIMIT ?
        """
        rows = c.execute(sql, (fts_query, limit * 3 if tag else limit)).fetchall()

        results = []
        for row in rows:
            tags_list = json.loads(row["tags"]) if row["tags"] else []
            if tag and tag not in tags_list:
                continue
            results.append({
                "ctftime_writeup_id": row["ctftime_writeup_id"],
                "event_name": row["event_name"],
                "task_name": row["task_name"],
                "tags": tags_list,
                "author": row["author"],
                "team": row["team"],
                "ctftime_url": row["ctftime_url"],
            })
            if len(results) >= limit:
                break

        return results
    finally:
        conn.close()


def get_ctf_writeup_content(writeup_id: int) -> Dict[str, Any]:
    """
    Fetch writeup content with caching and stub detection.

    Args:
        writeup_id: ctftime_writeup_id

    Returns:
        Dict with: writeup_id, content, source_url, source_type ("ctftime" or "external"),
                   disclaimer, cached (bool), fetched_at
    """
    conn = get_conn()
    init_cache_table(conn)

    try:
        c = conn.cursor()

        # Get writeup metadata
        row = c.execute(
            "SELECT ctftime_writeup_id, ctftime_url FROM ctf_writeups_index WHERE ctftime_writeup_id = ?",
            (writeup_id,)
        ).fetchone()

        if not row:
            return {"error": f"Writeup {writeup_id} not found in index"}

        ctftime_url = row["ctftime_url"]

        # Check cache
        cache_row = c.execute(
            "SELECT content, source_url, fetched_at, expires_at FROM ctf_writeup_content_cache WHERE writeup_id = ?",
            (writeup_id,)
        ).fetchone()

        if cache_row and cache_row["expires_at"]:
            expires = datetime.fromisoformat(cache_row["expires_at"])
            if datetime.now() < expires:
                return {
                    "writeup_id": writeup_id,
                    "content": cache_row["content"],
                    "source_url": cache_row["source_url"],
                    "source_type": "ctftime" if "ctftime.org" in cache_row["source_url"] else "external",
                    "cached": True,
                    "fetched_at": cache_row["fetched_at"],
                    "disclaimer": "Konten milik penulis writeup aslinya, parafrase kalau dipakai ulang, jangan copy-paste mentah."
                }

        # Fetch from ctftime
        try:
            resp = requests.get(ctftime_url, headers=HEADERS, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            return {"error": f"Failed to fetch {ctftime_url}: {e}"}

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract main content area - look for the writeup content
        # Based on investigation, content is in the main body after the header
        content_div = soup.find("div", class_=re.compile(r"container|content|main|writeup", re.I))
        if not content_div:
            # Fallback: find the largest text block after the breadcrumb
            content_div = soup.body

        # Get text content
        full_text = content_div.get_text(separator="\n", strip=True) if content_div else soup.get_text(separator="\n", strip=True)

        # Check for "Original writeup" link
        original_link = None
        for link in soup.find_all("a", href=True):
            if "original writeup" in link.get_text(strip=True).lower():
                href = link["href"]
                if isinstance(href, str):
                    original_link = href
                break

        source_url = ctftime_url
        source_type = "ctftime"

        # Heuristic: if content is short AND has original writeup link, fetch external
        if len(full_text) < STUB_LENGTH_THRESHOLD and original_link:
            # Check if it's a non-article domain (video, social media, etc.)
            if is_non_article_url(original_link):
                # Return stub info instead of trying to fetch
                full_text = f"Link eksternal (video/media), bukan teks — kunjungi langsung: {original_link}"
                source_url = original_link
                source_type = "stub"
            else:
                try:
                    ext_resp = requests.get(original_link, headers=HEADERS, timeout=30)
                    ext_resp.raise_for_status()
                    ext_soup = BeautifulSoup(ext_resp.text, "html.parser")

                    # Try to find article/content
                    article = ext_soup.find("article") or ext_soup.find("main") or ext_soup.find("div", class_=re.compile(r"content|post|writeup", re.I))
                    if article:
                        ext_content = article.get_text(separator="\n", strip=True)
                    else:
                        # Fallback: largest text block
                        ext_content = ext_soup.get_text(separator="\n", strip=True)

                    if len(ext_content) > len(full_text):
                        full_text = ext_content
                        source_url = original_link
                        source_type = "external"
                except Exception as e:
                    # If external fetch fails, use ctftime content
                    pass

        # Clean up content
        full_text = re.sub(r'\n{3,}', '\n\n', full_text)  # Collapse excessive newlines
        full_text = full_text.strip()

        # Save to cache
        now = datetime.now()
        expires = now + timedelta(days=CACHE_TTL_DAYS)
        c.execute("""
            INSERT OR REPLACE INTO ctf_writeup_content_cache (writeup_id, content, source_url, fetched_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (writeup_id, full_text, source_url, now.isoformat(), expires.isoformat()))
        conn.commit()

        return {
            "writeup_id": writeup_id,
            "content": full_text,
            "source_url": source_url,
            "source_type": source_type,
            "cached": False,
            "fetched_at": now.isoformat(),
            "disclaimer": "Konten milik penulis writeup aslinya, parafrase kalau dipakai ulang, jangan copy-paste mentah."
        }

    finally:
        conn.close()


def list_ctf_writeup_tags() -> List[Dict[str, Any]]:
    """
    Get distinct tags with writeup counts.

    Returns:
        List of dicts with tag and count, sorted by count descending
    """
    conn = get_conn()
    try:
        c = conn.cursor()
        rows = c.execute("SELECT tags FROM ctf_writeups_index WHERE tags IS NOT NULL AND tags != '[]'").fetchall()

        tag_counts = {}
        for row in rows:
            try:
                tags = json.loads(row["tags"])
                for tag in tags:
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
            except json.JSONDecodeError:
                continue

        # Sort by count descending
        sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)

        return [{"tag": tag, "count": count} for tag, count in sorted_tags]
    finally:
        conn.close()


# MCP tool registration
def register_tools(mcp):
    """Register all CTF writeup tools with the MCP server."""

    @mcp.tool()
    def search_ctf_writeups_tool(query: str, tag: Optional[str] = None, limit: int = 10) -> str:
        """Search CTF writeups from CTFtime.org index.

        Args:
            query: Search query (matches event name, task name, tags, author, team)
            tag: Optional tag filter (exact match)
            limit: Maximum results (default 10)
        """
        results = search_ctf_writeups(query, tag, limit)
        if not results:
            return "No writeups found matching query."

        lines = [f"Found {len(results)} writeup(s):"]
        for r in results:
            tags_str = ", ".join(r["tags"]) if r["tags"] else "no tags"
            lines.append(f"  • #{r['ctftime_writeup_id']}: {r['event_name']} / {r['task_name']} [{tags_str}] by {r['author']} ({r['team']})")
            lines.append(f"    URL: {r['ctftime_url']}")
        return "\n".join(lines)

    @mcp.tool()
    def get_ctf_writeup_content_tool(writeup_id: int) -> str:
        """Get full writeup content with caching (60-day TTL).

        Args:
            writeup_id: CTFtime writeup ID (from search_ctf_writeups)
        """
        result = get_ctf_writeup_content(writeup_id)

        if "error" in result:
            return f"Error: {result['error']}"

        source_info = f"Source: {result['source_type']} ({result['source_url']})"
        cache_info = "Cached" if result['cached'] else "Fresh fetch"

        return f"""Writeup #{result['writeup_id']}
{source_info} | {cache_info} | Fetched: {result['fetched_at']}

{result['disclaimer']}

--- CONTENT ---
{result['content']}
"""

    @mcp.tool()
    def list_ctf_writeup_tags_tool() -> str:
        """List all distinct tags with writeup counts."""
        tags = list_ctf_writeup_tags()
        if not tags:
            return "No tags found."

        lines = [f"Total distinct tags: {len(tags)}"]
        for t in tags[:50]:  # Limit output
            lines.append(f"  {t['tag']}: {t['count']} writeup(s)")
        if len(tags) > 50:
            lines.append(f"  ... and {len(tags) - 50} more tags")
        return "\n".join(lines)


if __name__ == "__main__":
    # Quick test
    print("Testing search...")
    results = search_ctf_writeups("forensics", limit=3)
    print(json.dumps(results, indent=2))

    print("\nTesting get content...")
    if results:
        content = get_ctf_writeup_content(results[0]["ctftime_writeup_id"])
        print(json.dumps({k: v[:200] if k == "content" else v for k, v in content.items()}, indent=2))

    print("\nTesting tags...")
    tags = list_ctf_writeup_tags()
    print(json.dumps(tags[:10], indent=2))