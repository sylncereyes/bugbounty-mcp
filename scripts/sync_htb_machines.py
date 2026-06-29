#!/usr/bin/env python3
"""
Sync HackTheBox retired machines from official API.
Only processes machines with retired=true (verified from API response).
Increments UPSERT into htb_machines_index table.
"""

import os
import sys
import time
import sqlite3
import requests
from dotenv import load_dotenv

# Load environment from project root
load_dotenv(dotenv_path='/home/kali/bugbounty-mcp/.env', override=True)

DB_PATH = '/home/kali/bugbounty-mcp/database/bugbounty.db'
API_BASE = 'https://labs.hackthebox.com/api/v4/machine/list/retired/paginated'
HEADERS = {
    "Authorization": f"Bearer {os.getenv('HTB_API_TOKEN')}",
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": "https://labs.hackthebox.com/",
    "Origin": "https://labs.hackthebox.com"
}

def verify_token():
    """Verify API token is set and valid"""
    token = os.getenv('HTB_API_TOKEN')
    if not token or token == 'your_token_here':
        print("ERROR: HTB_API_TOKEN not set in .env")
        return False
    return True

def fetch_page(page):
    """Fetch a single page of retired machines"""
    url = f"{API_BASE}?retired=1&page={page}"
    resp = requests.get(url, headers=HEADERS, timeout=30)
    if resp.status_code == 401:
        print("ERROR: Unauthorized - check HTB_API_TOKEN")
        return None
    if resp.status_code != 200:
        print(f"ERROR: HTTP {resp.status_code}: {resp.text[:200]}")
        return None
    return resp.json()

def is_retired_machine(machine):
    """
    Verify machine is retired.
    The endpoint is /machine/list/retired so all should be retired,
    but we double-check fields as a guardrail.
    """
    # The API doesn't seem to have an explicit 'retired' boolean field
    # 'active' is None for retired machines
    # The endpoint itself is /list/retired so we trust it, but verify active is None
    return machine.get('active') is None

def upsert_machine(cursor, machine):
    """Insert or update a machine in the database"""
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
        machine.get('avatar'),
        machine.get('free', False),
        machine.get('difficulty', 0),
        machine.get('static_points', 0),
        machine.get('user_owns_count', 0),
        machine.get('root_owns_count', 0),
        machine.get('is_competitive', False),
        machine.get('recommended', False)
    ))

def main():
    if not verify_token():
        sys.exit(1)

    print("Starting HTB retired machines sync...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get total pages from first request
    first_page = fetch_page(1)
    if not first_page:
        conn.close()
        sys.exit(1)
    
    total_pages = first_page['meta']['last_page']
    total_machines = first_page['meta']['total']
    print(f"Total pages: {total_pages}, Total machines: {total_machines}")
    
    processed = 0
    skipped = 0
    
    # Process first page
    for machine in first_page['data']:
        if is_retired_machine(machine):
            upsert_machine(cursor, machine)
            processed += 1
        else:
            print(f"SKIPPED (not retired): {machine['name']} (id={machine['id']}, active={machine.get('active')})")
            skipped += 1
    
    conn.commit()
    print(f"Page 1: processed {processed}, skipped {skipped}")
    
    # Process remaining pages
    for page in range(2, total_pages + 1):
        time.sleep(1)  # Rate limiting
        
        data = fetch_page(page)
        if not data:
            print(f"Failed to fetch page {page}, stopping")
            break
        
        page_processed = 0
        page_skipped = 0
        for machine in data['data']:
            if is_retired_machine(machine):
                upsert_machine(cursor, machine)
                page_processed += 1
            else:
                print(f"SKIPPED (not retired): {machine['name']} (id={machine['id']}, active={machine.get('active')})")
                page_skipped += 1
        
        conn.commit()
        processed += page_processed
        skipped += page_skipped
        print(f"Page {page}/{total_pages}: processed {page_processed}, skipped {page_skipped} (total: {processed})")
    
    conn.close()
    print(f"\nSync complete: {processed} machines indexed, {skipped} skipped")

if __name__ == '__main__':
    main()