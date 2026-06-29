#!/usr/bin/env python3
"""
build_cve_kev_index.py
Fetches and indexes CISA Known Exploited Vulnerabilities (KEV) Catalog into SQLite tables.
Table is rebuilt from scratch each run (DROP+CREATE) - simple, no incremental needed.
"""

import sys
import os
import sqlite3
import json
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "bugbounty.db")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def build_index():
    """Build CVE KEV index from CISA catalog into SQLite tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    
    cursor = conn.cursor()
    
    # Drop and recreate tables (rebuild from scratch)
    cursor.executescript("""
        DROP TABLE IF EXISTS cve_entries;
        DROP TABLE IF EXISTS cve_entries_fts;
        
        CREATE TABLE cve_entries (
            cve_id              TEXT PRIMARY KEY,
            vendor_project      TEXT,
            product             TEXT,
            vulnerability_name  TEXT,
            date_added          TEXT,
            short_description   TEXT,
            required_action     TEXT,
            due_date            TEXT,
            known_ransomware_use TEXT,
            cwe_ids             TEXT,     -- JSON array of CWE IDs (if present in source)
            notes               TEXT,
            raw_json            TEXT,     -- Full original JSON object
            indexed_at          TEXT DEFAULT (datetime('now'))
        );
        
        CREATE VIRTUAL TABLE cve_entries_fts USING fts5(
            cve_id UNINDEXED,
            vulnerability_name,
            short_description,
            vendor_project,
            product,
            tokenize='porter unicode61',
            content='cve_entries',
            content_rowid='rowid'
        );
        
        -- Triggers to keep FTS5 in sync
        CREATE TRIGGER cve_entries_fts_insert
        AFTER INSERT ON cve_entries
        BEGIN
            INSERT INTO cve_entries_fts(rowid, cve_id, vulnerability_name, short_description, vendor_project, product)
            VALUES (new.rowid, new.cve_id, new.vulnerability_name, new.short_description, new.vendor_project, new.product);
        END;
        
        CREATE TRIGGER cve_entries_fts_delete
        AFTER DELETE ON cve_entries
        BEGIN
            INSERT INTO cve_entries_fts(cve_entries_fts, rowid, cve_id, vulnerability_name, short_description, vendor_project, product)
            VALUES ('delete', old.rowid, old.cve_id, old.vulnerability_name, old.short_description, old.vendor_project, old.product);
        END;
        
        CREATE TRIGGER cve_entries_fts_update
        AFTER UPDATE ON cve_entries
        BEGIN
            INSERT INTO cve_entries_fts(cve_entries_fts, rowid, cve_id, vulnerability_name, short_description, vendor_project, product)
            VALUES ('delete', old.rowid, old.cve_id, old.vulnerability_name, old.short_description, old.vendor_project, old.product);
            INSERT INTO cve_entries_fts(rowid, cve_id, vulnerability_name, short_description, vendor_project, product)
            VALUES (new.rowid, new.cve_id, new.vulnerability_name, new.short_description, new.vendor_project, new.product);
        END;
    """)
    
    # Fetch KEV catalog
    print(f"[INFO] Fetching CISA KEV catalog from {KEV_URL}...")
    req = urllib.request.Request(
        KEV_URL,
        headers={"User-Agent": "AGY-BugBounty-MCP/1.0 (bug bounty research)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.load(response)
    except Exception as e:
        print(f"[ERROR] Failed to fetch KEV catalog: {e}")
        conn.close()
        return
    
    vulnerabilities = data.get("vulnerabilities", [])
    print(f"[INFO] Found {len(vulnerabilities)} vulnerabilities in KEV catalog")
    
    inserted = 0
    errors = 0
    
    for vuln in vulnerabilities:
        try:
            cve_id = vuln.get("cveID", "").strip()
            if not cve_id:
                errors += 1
                continue
            
            # Extract CWE IDs if present in source
            cwe_ids = vuln.get("cwes", [])
            if cwe_ids and isinstance(cwe_ids, list):
                cwe_ids_json = json.dumps(cwe_ids)
            else:
                cwe_ids_json = json.dumps([])
            
            cursor.execute("""
                INSERT INTO cve_entries (
                    cve_id, vendor_project, product, vulnerability_name, date_added,
                    short_description, required_action, due_date, known_ransomware_use,
                    cwe_ids, notes, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                vuln.get("vendorProject", "").strip(),
                vuln.get("product", "").strip(),
                vuln.get("vulnerabilityName", "").strip(),
                vuln.get("dateAdded", "").strip(),
                vuln.get("shortDescription", "").strip(),
                vuln.get("requiredAction", "").strip(),
                vuln.get("dueDate", "").strip(),
                vuln.get("knownRansomwareCampaignUse", "").strip(),
                cwe_ids_json,
                vuln.get("notes", "").strip(),
                json.dumps(vuln, ensure_ascii=False)
            ))
            inserted += 1
        except Exception as e:
            print(f"[WARN] Failed to insert {vuln.get('cveID', 'UNKNOWN')}: {e}")
            errors += 1
    
    conn.commit()
    conn.close()
    
    print(f"[OK] Indexed {inserted} CVEs to cve_entries")
    print(f"[OK] FTS5 index populated via triggers")
    if errors:
        print(f"[WARN] {errors} entries had errors")


if __name__ == "__main__":
    build_index()