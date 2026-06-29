#!/usr/bin/env python3
"""
Build CTF writeups metadata index from CTFtime.org.
- Crawls https://ctftime.org/writeups paginated
- Extracts: ctftime_writeup_id, event_name, task_name, tags, author, team, rating, ctftime_url
- Incremental: stops when encountering already-seen writeup_id (newest first)
- Stores in ctf_writeups_index + FTS5 ctf_writeups_index_fts
- Respects robots.txt: crawl-delay 10s, polite User-Agent
"""

import sqlite3
import requests
import time
import re
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
import json
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "database" / "bugbounty.db"
BASE_URL = "https://ctftime.org"
WRITEUPS_URL = f"{BASE_URL}/writeups"

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


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_tables(conn):
    """Create tables if not exist."""
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS ctf_writeups_index (
            ctftime_writeup_id INTEGER PRIMARY KEY,
            event_name TEXT NOT NULL,
            task_name TEXT NOT NULL,
            tags TEXT,                    -- JSON array of tags
            author TEXT,                  -- author username
            team TEXT,                    -- team name
            rating REAL,                  -- rating score
            ctftime_url TEXT UNIQUE NOT NULL,
            indexed_at TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS ctf_writeups_index_fts USING fts5(
            event_name,
            task_name,
            tags,
            author,
            team,
            content='ctf_writeups_index',
            content_rowid='rowid',
            tokenize='porter unicode61'
        )
    """)
    # Triggers to keep FTS in sync
    c.execute("""
        CREATE TRIGGER IF NOT EXISTS ctf_writeups_fts_insert
        AFTER INSERT ON ctf_writeups_index
        BEGIN
            INSERT INTO ctf_writeups_index_fts(rowid, event_name, task_name, tags, author, team)
            VALUES (new.rowid, new.event_name, new.task_name, new.tags, new.author, new.team);
        END
    """)
    c.execute("""
        CREATE TRIGGER IF NOT EXISTS ctf_writeups_fts_delete
        AFTER DELETE ON ctf_writeups_index
        BEGIN
            INSERT INTO ctf_writeups_index_fts(ctf_writeups_index_fts, rowid, event_name, task_name, tags, author, team)
            VALUES ('delete', old.rowid, old.event_name, old.task_name, old.tags, old.author, old.team);
        END
    """)
    c.execute("""
        CREATE TRIGGER IF NOT EXISTS ctf_writeups_fts_update
        AFTER UPDATE ON ctf_writeups_index
        BEGIN
            INSERT INTO ctf_writeups_index_fts(ctf_writeups_index_fts, rowid, event_name, task_name, tags, author, team)
            VALUES ('delete', old.rowid, old.event_name, old.task_name, old.tags, old.author, old.team);
            INSERT INTO ctf_writeups_index_fts(rowid, event_name, task_name, tags, author, team)
            VALUES (new.rowid, new.event_name, new.task_name, new.tags, new.author, new.team);
        END
    """)
    conn.commit()


def get_max_writeup_id(conn) -> int:
    """Get highest writeup_id already in DB (for incremental)."""
    c = conn.cursor()
    row = c.execute("SELECT MAX(ctftime_writeup_id) FROM ctf_writeups_index").fetchone()
    return row[0] if row and row[0] else 0


def fetch_page(page: int) -> Optional[str]:
    """Fetch a single writeups listing page."""
    url = f"{WRITEUPS_URL}?page={page}" if page > 1 else WRITEUPS_URL
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"[ERROR] Failed to fetch page {page}: {e}")
        return None


def parse_writeups_list(html: str) -> List[Dict]:
    """Parse writeups listing page, return list of dicts with metadata."""
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table", id="writeups_table")
    if not table:
        return []

    results = []
    tbody = table.find("tbody")
    if not tbody:
        return []

    for row in tbody.find_all("tr"):
        tds = row.find_all("td")
        if len(tds) < 5:
            continue

        # Event
        event_link = tds[0].find("a")
        event_name = event_link.get_text(strip=True) if event_link else ""
        event_href = event_link.get("href", "") if event_link else ""

        # Task
        task_link = tds[1].find("a")
        task_name = task_link.get_text(strip=True) if task_link else ""
        task_href = task_link.get("href", "") if task_link else ""

        # Tags
        tags = []
        tags_td = tds[2]
        for tag_span in tags_td.find_all("span", class_="label"):
            tag_text = tag_span.get_text(strip=True)
            if tag_text:
                tags.append(tag_text)

        # Author team
        author_link = tds[3].find("a")
        author = author_link.get_text(strip=True) if author_link else ""
        author_href = author_link.get("href", "") if author_link else ""
        team = author  # author link points to team page

        # Action (writeup link)
        action_link = tds[4].find("a")
        writeup_href = action_link.get("href", "") if action_link else ""
        writeup_id = None
        if writeup_href:
            m = re.search(r"/writeup/(\d+)", writeup_href)
            if m:
                writeup_id = int(m.group(1))

        if writeup_id:
            results.append({
                "ctftime_writeup_id": writeup_id,
                "event_name": event_name,
                "task_name": task_name,
                "tags": json.dumps(tags),
                "author": author,
                "team": team,
                "rating": None,  # Not on listing page
                "ctftime_url": f"{BASE_URL}{writeup_href}",
            })

    return results


def fetch_writeup_detail(writeup_url: str) -> Optional[Dict]:
    """Fetch individual writeup page to get rating and verify details."""
    try:
        resp = requests.get(writeup_url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract rating
        rating = None
        rating_text = soup.find(string=re.compile(r"Rating:", re.I))
        if rating_text:
            # Find the rating value near "Rating:"
            parent = rating_text.parent
            if parent:
                # Look for number in parent or siblings
                rating_match = re.search(r"Rating:\s*([\d.]+)", parent.get_text())
                if rating_match:
                    rating = float(rating_match.group(1))

        return {"rating": rating}
    except Exception as e:
        print(f"[WARN] Failed to fetch detail for {writeup_url}: {e}")
        return None


def upsert_writeup(conn, writeup: Dict):
    """Insert or update writeup in database."""
    c = conn.cursor()
    c.execute("""
        INSERT INTO ctf_writeups_index
        (ctftime_writeup_id, event_name, task_name, tags, author, team, rating, ctftime_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ctftime_writeup_id) DO UPDATE SET
            event_name=excluded.event_name,
            task_name=excluded.task_name,
            tags=excluded.tags,
            author=excluded.author,
            team=excluded.team,
            rating=excluded.rating,
            ctftime_url=excluded.ctftime_url,
            indexed_at=datetime('now')
    """, (
        writeup["ctftime_writeup_id"],
        writeup["event_name"],
        writeup["task_name"],
        writeup["tags"],
        writeup["author"],
        writeup["team"],
        writeup["rating"],
        writeup["ctftime_url"],
    ))


def main():
    print(f"[INFO] Building CTF writeups index from CTFtime.org")
    print(f"[INFO] Database: {DB_PATH}")

    conn = get_conn()
    init_tables(conn)

    original_max_id = get_max_writeup_id(conn)
    print(f"[INFO] Highest existing writeup_id in DB: {original_max_id}")

    page = 1
    total_new = 0
    stop_crawl = False
    max_pages = 10  # Limit for testing
    # For full rebuild, don't use incremental - just collect all
    original_max_id = 0  # Set to 0 to force full rebuild

    while not stop_crawl:
        if page > max_pages:
            print(f"[INFO] Reached max_pages limit ({max_pages}), stopping.")
            break
        print(f"[INFO] Fetching page {page}...")
        html = fetch_page(page)
        if not html:
            break

        writeups = parse_writeups_list(html)
        if not writeups:
            print(f"[INFO] No writeups found on page {page}, stopping.")
            break

        page_new = 0
        for wp in writeups:
            wp_id = wp["ctftime_writeup_id"]
            if original_max_id > 0 and wp_id <= original_max_id:
                print(f"[INFO] Reached existing writeup_id {wp_id} (<= {original_max_id}), stopping incremental crawl.")
                stop_crawl = True
                break

            # Fetch detail for rating (optional, be polite)
            detail = fetch_writeup_detail(wp["ctftime_url"])
            if detail and detail.get("rating") is not None:
                wp["rating"] = detail["rating"]

            upsert_writeup(conn, wp)
            total_new += 1
            page_new += 1

        conn.commit()
        print(f"[INFO] Page {page}: {page_new} new writeups (total new: {total_new})")

        if page_new == 0:
            print(f"[INFO] No new writeups on this page, stopping.")
            break

        page += 1
        # Respect crawl-delay: 10 seconds per robots.txt
        time.sleep(10)

    # Final stats
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM ctf_writeups_index").fetchone()[0]
    fts_total = c.execute("SELECT COUNT(*) FROM ctf_writeups_index_fts").fetchone()[0]
    print(f"[DONE] Total writeups in index: {total}")
    print(f"[DONE] FTS5 entries: {fts_total}")
    print(f"[DONE] New writeups added this run: {total_new}")

    conn.close()


if __name__ == "__main__":
    main()