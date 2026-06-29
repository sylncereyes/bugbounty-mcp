"""Build PortSwigger Web Security Academy topic index.
Respects robots.txt (except /bappstore/bapps/download/).
Stores only metadata (title, url, category, level), NOT full content.
"""
import time
import requests
from bs4 import BeautifulSoup
from pathlib import Path
import sqlite3
import os

USER_AGENT = "personal-research-bot/1.0 (internal use)"
HEADERS = {"User-Agent": USER_AGENT, "Accept": "text/html"}
BASE_URL = "https://portswigger.net"

# Resolve DB path
REPO_ROOT = Path(__file__).parent.parent
DB_PATH = REPO_ROOT / "database" / "bugbounty.db"

def _db_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_portswigger_tables():
    """Create portswigger_index and portswigger_content_cache tables."""
    with _db_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS portswigger_index (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT NOT NULL,
                url             TEXT UNIQUE NOT NULL,
                category        TEXT,
                level           TEXT,
                created_at      TEXT DEFAULT (datetime('now'))
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS portswigger_content_cache (
                url             TEXT PRIMARY KEY,
                content         TEXT,
                fetched_at      TEXT DEFAULT (datetime('now')),
                expires_at      TEXT  -- 7 days cache
            )
        """)
        conn.commit()

def _fetch_topics():
    """Fetch all topics from /web-security/all-topics."""
    resp = requests.get(f"{BASE_URL}/web-security/all-topics", headers=HEADERS, timeout=10)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, 'html.parser')
    
    topics = []
    seen_urls = set()
    
    for link in soup.find_all('a', href=True):
        href = link.get('href', '')
        
        # Skip if not a topic link or already seen
        if not href:
            continue
        if href in seen_urls:
            continue
            
        # Topic links: /web-security/<topic-name> or full URL
        is_topic = False
        if href.startswith('/web-security/') and '/lab/' not in href:
            is_topic = True
        elif href.startswith('https://portswigger.net/web-security/') and '/lab/' not in href:
            is_topic = True
            
        if not is_topic:
            continue
            
        # Get title from <h3> inside link
        h3 = link.find('h3')
        title = h3.get_text(strip=True) if h3 else link.get_text(strip=True)
        
        if not title or len(title) < 3:
            continue
            
        # Normalize URL
        if href.startswith('http'):
            full_url = href
        else:
            full_url = f"{BASE_URL}{href}"
            
        # Infer category from URL
        category = ""
        if '/web-security/' in full_url:
            try:
                parts = full_url.split('/web-security/')
                category = parts[1].split('/')[0] if len(parts) > 1 else ""
            except:
                pass
        
        seen_urls.add(href)
        topics.append({
            'title': title,
            'url': full_url,
            'category': category,
            'level': ''  # Level info not easily available on all-topics page
        })
    
    return topics

if __name__ == "__main__":
    init_portswigger_tables()
    print("Building PortSwigger topic index...")
    
    topics = _fetch_topics()
    print(f"Found {len(topics)} topics")
    
    # Clear and rebuild
    with _db_conn() as conn:
        conn.execute("DELETE FROM portswigger_index")
        for t in topics:
            conn.execute(
                "INSERT OR REPLACE INTO portswigger_index (title, url, category, level) VALUES (?, ?, ?, ?)",
                (t['title'], t['url'], t['category'], t['level'])
            )
        conn.commit()
    
    print(f"Indexed {len(topics)} PortSwigger topics")