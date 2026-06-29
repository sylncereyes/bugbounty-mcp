"""PortSwigger Web Security Academy Knowledge-Base MCP tool.
Fetches content on-demand with 7-day TTL cache.
Only stores index/metadata permanently.
"""
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
from tools import db
from mcp_instance import mcp

HEADERS = {"User-Agent": "personal-research-bot/1.0 (internal use)"}
BASE_URL = "https://portswigger.net"


def _get_db():
    return db


@mcp.tool(name="portswigger_search", description="Search PortSwigger Web Security Academy topics by title or category")
def search_portswigger_topics(query: str = "", category: str = None, limit: int = 10):
    """Search topics in portswigger_index by title/category."""
    db_mod = _get_db()
    
    with db_mod.db_connection() as conn:
        sql = "SELECT title, url, category, level FROM portswigger_index WHERE 1=1"
        params = []
        
        if query:
            sql += " AND (title LIKE ? OR category LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])
        
        if category:
            sql += " AND category = ?"
            params.append(category)
        
        sql += " LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


@mcp.tool(name="portswigger_fetch", description="Fetch PortSwigger topic content (live fetch with 7-day cache)")
def fetch_portswigger_topic(url: str = None):
    """Fetch topic content with cache. Returns content or error dict."""
    if not url:
        return {"error": "URL parameter required"}
    
    db_mod = _get_db()
    
    # Check cache first
    with db_mod.db_connection() as conn:
        cached = conn.execute(
            "SELECT content, fetched_at FROM portswigger_content_cache WHERE url = ?", (url,)
        ).fetchone()
        
        if cached:
            fetched_at = datetime.fromisoformat(cached["fetched_at"])
            expires_at = fetched_at + timedelta(days=7)
            if datetime.now() < expires_at:
                return {
                    "content": cached["content"],
                    "source_url": url,
                    "cached": True,
                    "fetched_at": cached["fetched_at"]
                }
    
    # Fetch live
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Extract main content - find the article content after h1
        content_parts = []
        h1 = soup.find('h1')
        if h1:
            # Get the parent container and collect all meaningful content
            current = h1.parent
            while current and current.name != 'body':
                # Get all text from this container
                text = current.get_text(separator='\n', strip=True)
                # Skip navigation/footer elements
                if 'account' not in text.lower()[:100] and 'products' not in text.lower()[:100]:
                    content_parts.append(text)
                current = current.parent
        
        # Fallback: get all text if no h1 found
        if not content_parts:
            content_parts = [soup.get_text(separator='\n', strip=True)]
        
        # Combine and clean
        content = '\n\n'.join(content_parts)
        
        # Cache the result
        with db_mod.db_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO portswigger_content_cache 
                   (url, content, fetched_at, expires_at) 
                   VALUES (?, ?, datetime('now'), datetime('now', '+7 days'))""",
                (url, content)
            )
            conn.commit()
        
        return {
            "content": content,
            "source_url": url,
            "cached": False,
            "disclaimer": "Konten milik PortSwigger Web Security Academy, dipakai sebagai referensi internal."
        }
        
    except Exception as e:
        return {"error": str(e), "source_url": url}


@mcp.tool(name="portswigger_categories", description="List unique categories in PortSwigger index with topic counts")
def list_portswigger_categories():
    """Return distinct categories with topic counts."""
    db_mod = _get_db()
    
    with db_mod.db_connection() as conn:
        rows = conn.execute(
            "SELECT category, COUNT(*) as count FROM portswigger_index GROUP BY category ORDER BY count DESC"
        ).fetchall()
        return [{"category": r["category"], "count": r["count"]} for r in rows]