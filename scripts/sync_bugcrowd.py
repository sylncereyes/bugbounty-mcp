"""Bugcrowd CrowdStream scraper – incremental sync.

* Respects robots.txt (disallows only paths containing ?preview and /external_redirect).
* Uses polite User-Agent and 1-2s delay.
* Fetches data via JSON API endpoint.
* For each disclosure extracts fields required for DB insertion.
* UPSERTs into `bugcrowd_reports` and updates FTS5 virtual table.
* Stores watermark (`bugcrowd_last_sync`) in `sync_metadata` table.
"""
import time
import json
import sqlite3
import os
import re
import html
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

import requests
from bs4 import BeautifulSoup

REPO_ROOT = Path(__file__).parent.parent
DB_PATH = REPO_ROOT / "database" / "bugbounty.db"

USER_AGENT = "personal-research-bot/1.0 (internal use)"
HEADERS = {"User-Agent": USER_AGENT, "Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
HEADERS_HTML = {"User-Agent": USER_AGENT, "Accept": "text/html"}

def _db_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def _get_watermark() -> Optional[str]:
    with _db_conn() as conn:
        row = conn.execute("SELECT value FROM sync_metadata WHERE key = 'bugcrowd_last_sync'").fetchone()
        return row["value"] if row else None

def _set_watermark(date_str: str) -> None:
    with _db_conn() as conn:
        conn.execute(
            "INSERT INTO sync_metadata (key, value) VALUES ('bugcrowd_last_sync', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (date_str,),
        )
        conn.commit()

def _fetch_listing(page: int) -> List[Dict]:
    """Fetch crowdstream listing via JSON API."""
    # Use filter_by=disclosures to get disclosed submissions with disclosure_report_url
    url = f"https://bugcrowd.com/crowdstream.json?page={page}&filter_by=disclosures"
    resp = requests.get(url, headers=HEADERS, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    
    disclosures = []
    for item in data.get("results", []):
        # id is the disclosure UUID
        disclosure_id = item.get("id", "")
        
        # title: for disclosed items, there's a title field; for non-disclosed, use submission_state_text
        title = item.get("title") or item.get("submission_state_text") or ""
        
        # program: engagement_name
        program = item.get("engagement_name", "")
        
        # priority: convert numeric to P1-P5
        priority_num = item.get("priority", 0)
        priority = f"P{priority_num}" if priority_num else ""
        
        # reward_amount (handle null -> empty string)
        reward_raw = item.get("amount")
        reward_amount = reward_raw if reward_raw else ""
        
        # disclosed_date: convert "24 Jun 2026" -> "2026-06-24" for proper sorting
        disclosed_date_raw = item.get("disclosed_at") or item.get("accepted_at") or ""
        disclosed_date = ""
        if disclosed_date_raw:
            try:
                parsed_date = datetime.strptime(disclosed_date_raw, "%d %b %Y")
                disclosed_date = parsed_date.strftime("%Y-%m-%d")
            except ValueError:
                disclosed_date = disclosed_date_raw  # keep raw if parsing fails
        
        # Build URL for detail page
        disclosure_url = ""
        if item.get("disclosure_report_url"):
            disclosure_url = f"https://bugcrowd.com{item['disclosure_report_url']}"
        
        disclosures.append({
            "uuid": disclosure_id,
            "title": title,
            "program": program,
            "priority": priority,
            "reward_amount": reward_amount,
            "disclosed_date": disclosed_date,
            "url": disclosure_url,
            "disclosed": item.get("disclosed", False),
        })
    return disclosures

def _fetch_detail(url: str) -> Dict:
    """Fetch detail page for VRT category and additional info."""
    if not url:
        return {"vrt_category": "", "summary": ""}
    
    resp = requests.get(url, headers=HEADERS_HTML, timeout=10)
    resp.raise_for_status()
    
    # VRT Category: cari di seluruh HTML (React stores it in data-react-props)
    vrt_category = ""
    vrt_match = re.search(r'"updated_field":"VRT","to_value":"([^"]+)"', resp.text)
    if vrt_match:
        vrt_raw = html.unescape(vrt_match.group(1))
        vrt_raw = vrt_raw.replace("\\u003e", "> ").replace("\\u002f", "/")
        vrt_category = vrt_raw
    
    soup = BeautifulSoup(resp.text, "html.parser")
    
    # Summary: cari di article dengan h5="Summary"
    summary = ""
    for article in soup.find_all("article"):
        h5 = article.find("h5")
        if h5 and "Summary" in h5.get_text(strip=True):
            summary = article.get_text(separator=" ", strip=True)
            break
    
    return {
        "vrt_category": vrt_category,
        "summary": summary,
    }

def _upsert_report(report: Dict) -> bool:
    """Insert or replace a disclosure. Returns True if a new row was added.
    
    Perhatian: urutan eksekusi krusial untuk FTS5 sync!
    - INSERT OR REPLACE di SQLite sebenarnya DELETE lalu INSERT baru.
    - Baris yang baru bisa mendapat rowid BERBEDA dari sebelumnya.
    - Jika kita DELETE FTS setelah INSERT, rowid YANG BARU tidak akan ketemu (masih pakai rowid lama).
    - Jika kita DELETE FTS sebelum INSERT, semua entry FTS akan hilang untuk row ini.
    
    Solusi: 
    1. Query rowid LAMA sebelum insert.
    2. DELETE FTS pakai rowid LAMA (jika ada).
    3. BARU INSERT OR REPLACE ke tabel utama.
    4. Ambil rowid BARU dari cursor.lastrowid.
    5. INSERT FTS pakai rowid BARU.
    """
    with _db_conn() as conn:
        cur = conn.cursor()
        # Check existence and get OLD rowid BEFORE insert
        old_rowid = None
        cur.execute("SELECT rowid FROM bugcrowd_reports WHERE disclosure_uuid = ?", (report["uuid"],))
        existing = cur.fetchone()
        if existing:
            old_rowid = existing[0]
        
        exists = existing is not None
        
        # UPSERT - INSERT OR REPLACE causes implicit delete + insert
        cur.execute(
            """
            INSERT OR REPLACE INTO bugcrowd_reports (
                disclosure_uuid, title, program, vrt_category, priority,
                reward_amount, summary, url, disclosed_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["uuid"],
                report["title"],
                report["program"],
                report["vrt_category"],
                report["priority"],
                report["reward_amount"],
                report["summary"],
                report["url"],
                report["disclosed_date"],
            ),
        )
        
        # Now get the NEW rowid (might be different after REPLACE)
        new_rowid = cur.lastrowid
        
        # Delete OLD FTS entry if it existed (prevents orphan entries)
        if old_rowid:
            cur.execute("DELETE FROM bugcrowd_reports_fts WHERE rowid = ?", (old_rowid,))
        
        # Insert FTS entry with NEW rowid
        cur.execute(
            "INSERT INTO bugcrowd_reports_fts(rowid, title, summary, vrt_category) VALUES (?, ?, ?, ?)",
            (new_rowid, report["title"], report["summary"], report["vrt_category"]),
        )
        conn.commit()
        return not exists

def sync_bugcrowd(max_pages: int = 5) -> Dict:
    """Sync CrowdStream disclosures up to *max_pages*.
    Returns a summary dict with number of new disclosures and date range.
    """
    new_count = 0
    dates = []
    watermark = _get_watermark()
    
    for page in range(1, max_pages + 1):
        listings = _fetch_listing(page)
        if not listings:
            break
        for item in listings:
            # If we have a watermark, skip older items
            if watermark and item["disclosed_date"] and item["disclosed_date"] <= watermark:
                continue
            
            # Note: VRT category is NOT available on public detail pages (requires Bugcrowd account).
            # Detail fetch disabled - VRT would always be empty anyway.
            detail = {"vrt_category": "", "summary": ""}
            
            report = {
                "uuid": item["uuid"],
                "title": item["title"],
                "program": item["program"],
                "vrt_category": detail.get("vrt_category", ""),
                "priority": item["priority"],
                "reward_amount": item.get("reward_amount", ""),
                "summary": detail.get("summary", ""),
                "url": item["url"],
                "disclosed_date": item["disclosed_date"],
            }
            if _upsert_report(report):
                new_count += 1
            if report["disclosed_date"]:
                dates.append(report["disclosed_date"])
            time.sleep(1.5)  # polite delay between detail fetches
        time.sleep(1.5)  # delay between pages
    
    # Update watermark to newest date we processed (or keep old if none)
    if dates:
        latest = max(dates)
        _set_watermark(latest)
    
    return {
        "new_reports": new_count,
        "date_range": {
            "from": min(dates) if dates else None,
            "to": max(dates) if dates else None,
        },
    }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sync Bugcrowd CrowdStream disclosures")
    parser.add_argument("--pages", type=int, default=1, help="Number of pages to sync")
    args = parser.parse_args()
    result = sync_bugcrowd(max_pages=args.pages)
    print(json.dumps(result, indent=2))