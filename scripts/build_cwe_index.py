#!/usr/bin/env python3
"""
Build CWE knowledge base from MITRE CWE API.
Fetches CWE Top 25 2025 (view 1435) members and their details.
Creates tables: cwe_entries, cwe_observed_examples, cwe_entries_fts
"""
import sys
import json
import time
import sqlite3
import os
from pathlib import Path
import urllib.request

# Add tools to path for db functions
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from db import get_connection, db_connection

# ─────────────────────────────────────────────
# CWE SCHEMA INITIALIZATION
# ─────────────────────────────────────────────

def init_cwe_schema() -> None:
    """Initialize CWE tables and FTS5 index."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript("""
            -- Drop existing tables for fresh rebuild
            DROP TABLE IF EXISTS cwe_observed_examples;
            DROP TABLE IF EXISTS cwe_entries_fts;
            DROP TABLE IF EXISTS cwe_entries;

            -- Main CWE entries table
            CREATE TABLE cwe_entries (
                cwe_id          INTEGER PRIMARY KEY,
                name            TEXT NOT NULL,
                abstraction     TEXT,
                structure       TEXT,
                status          TEXT,
                description     TEXT,
                extended_description TEXT,
                likelihood_of_exploit TEXT,
                is_top25        BOOLEAN DEFAULT 0,
                raw_json        TEXT,
                fetched_at      TEXT DEFAULT (datetime('now'))
            );

            -- Observed examples (CVE references) from API
            CREATE TABLE cwe_observed_examples (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cwe_id          INTEGER NOT NULL REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE,
                cve_id          TEXT,
                example_description TEXT,
                link            TEXT
            );

            -- FTS5 virtual table for full-text search
            CREATE VIRTUAL TABLE cwe_entries_fts USING fts5(
                cwe_id      UNINDEXED,
                name,
                description,
                extended_description,
                tokenize='porter unicode61'
            );

            -- Trigger to keep FTS in sync
            CREATE TRIGGER cwe_entries_ai AFTER INSERT ON cwe_entries BEGIN
                INSERT INTO cwe_entries_fts(cwe_id, name, description, extended_description)
                VALUES (new.cwe_id, new.name, new.description, new.extended_description);
            END;

            CREATE TRIGGER cwe_entries_ad AFTER DELETE ON cwe_entries BEGIN
                DELETE FROM cwe_entries_fts WHERE cwe_id = old.cwe_id;
            END;

            CREATE TRIGGER cwe_entries_au AFTER UPDATE ON cwe_entries BEGIN
                UPDATE cwe_entries_fts
                SET name = new.name,
                    description = new.description,
                    extended_description = new.extended_description
                WHERE cwe_id = old.cwe_id;
            END;

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_cwe_observed_cwe ON cwe_observed_examples(cwe_id);
            CREATE INDEX IF NOT EXISTS idx_cwe_is_top25 ON cwe_entries(is_top25);
        """)
    print("CWE schema initialized (fresh rebuild)")


# ─────────────────────────────────────────────
# API FETCH FUNCTIONS
# ─────────────────────────────────────────────

def fetch_cwe_top25_view() -> list:
    """Fetch CWE Top 25 2025 view (ID 1435) to get member CWE IDs."""
    url = "https://cwe-api.mitre.org/api/v1/cwe/view/1435"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "AGY-BugBounty-MCP/1.0 (bug bounty research)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
            views = data.get("Views", [])
            if views:
                view = views[0]
                members = view.get("Members", [])
                # Members is a list of objects with "CweID" field (string)
                cwe_ids = []
                for m in members:
                    cwe_id = m.get("CweID")
                    if cwe_id:
                        cwe_ids.append(int(cwe_id))
                return cwe_ids
            return []
    except Exception as e:
        print(f"[ERROR] Failed to fetch CWE view 1435: {e}")
        return []


def fetch_cwe_weakness(cwe_id: int) -> dict:
    """Fetch detailed weakness data from MITRE CWE API."""
    url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "AGY-BugBounty-MCP/1.0 (bug bounty research)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
            weaknesses = data.get("Weaknesses", [])
            if weaknesses:
                return weaknesses[0]
            return {}
    except Exception as e:
        print(f"[ERROR] Failed to fetch CWE-{cwe_id}: {e}")
        return {}


# ─────────────────────────────────────────────
# DATA EXTRACTION FROM API RESPONSE
# ─────────────────────────────────────────────

def extract_description(weakness: dict) -> str:
    """Extract Description text from weakness object."""
    desc = weakness.get("Description", {})
    if isinstance(desc, dict):
        # Description has "Text" array of strings
        texts = desc.get("Text", [])
        if isinstance(texts, list):
            return " ".join(texts)
        return str(texts)
    return str(desc) if desc else ""


def extract_extended_description(weakness: dict) -> str:
    """Extract ExtendedDescription text."""
    ext = weakness.get("ExtendedDescription", {})
    if isinstance(ext, dict):
        texts = ext.get("Text", [])
        if isinstance(texts, list):
            return " ".join(texts)
        return str(texts)
    return str(ext) if ext else ""


def extract_likelihood_of_exploit(weakness: dict) -> str:
    """Extract LikelihoodOfExploit."""
    loe = weakness.get("LikelihoodOfExploit", {})
    if isinstance(loe, dict):
        return str(loe.get("Text", ""))
    return str(loe) if loe else ""


def extract_potential_mitigations(weakness: dict) -> list:
    """Extract PotentialMitigations list."""
    mits = weakness.get("PotentialMitigations", {})
    if isinstance(mits, dict):
        mitigations = mits.get("Mitigation", [])
        if isinstance(mitigations, list):
            return mitigations
    return []


def extract_observed_examples(weakness: dict) -> list:
    """Extract ObservedExamples list with CVE references."""
    obs = weakness.get("ObservedExamples", [])
    # Handle both structures: list of dicts or dict with ObservedExample key
    if isinstance(obs, list):
        return obs
    elif isinstance(obs, dict):
        examples = obs.get("ObservedExample", [])
        if isinstance(examples, list):
            return examples
    return []


def extract_demonstrative_examples(weakness: dict) -> list:
    """Extract DemonstrativeExamples."""
    demos = weakness.get("DemonstrativeExamples", {})
    if isinstance(demos, dict):
        examples = demos.get("DemonstrativeExample", [])
        if isinstance(examples, list):
            return examples
    return []


def extract_detection_methods(weakness: dict) -> list:
    """Extract DetectionMethods."""
    dm = weakness.get("DetectionMethods", {})
    if isinstance(dm, dict):
        methods = dm.get("DetectionMethod", [])
        if isinstance(methods, list):
            return methods
    return []


def extract_common_consequences(weakness: dict) -> list:
    """Extract CommonConsequences."""
    cc = weakness.get("CommonConsequences", {})
    if isinstance(cc, dict):
        consequences = cc.get("Consequence", [])
        if isinstance(consequences, list):
            return consequences
    return []


# ─────────────────────────────────────────────
# DATABASE INSERT FUNCTIONS
# ─────────────────────────────────────────────

def insert_cwe_entry(cwe_id: int, weakness: dict, is_top25: bool = False) -> bool:
    """Insert a CWE entry into database."""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        name = weakness.get("Name", "")
        abstraction = weakness.get("Abstraction", "")
        structure = weakness.get("Structure", "")
        status = weakness.get("Status", "")
        description = extract_description(weakness)
        extended_description = extract_extended_description(weakness)
        likelihood_of_exploit = extract_likelihood_of_exploit(weakness)
        raw_json = json.dumps(weakness, ensure_ascii=False)
        
        cursor.execute("""
            INSERT INTO cwe_entries 
            (cwe_id, name, abstraction, structure, status, description, extended_description, 
             likelihood_of_exploit, is_top25, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cwe_id, name, abstraction, structure, status, description, 
              extended_description, likelihood_of_exploit, 1 if is_top25 else 0, raw_json))
        
        # Insert observed examples (CVE references)
        observed = extract_observed_examples(weakness)
        for ex in observed:
            cve_id = ex.get("Reference", "")
            example_description = ex.get("Description", "")
            link = ex.get("Link", "")
            if cve_id:
                cursor.execute("""
                    INSERT INTO cwe_observed_examples (cwe_id, cve_id, example_description, link)
                    VALUES (?, ?, ?, ?)
                """, (cwe_id, cve_id, example_description, link))
        
        return True


# ─────────────────────────────────────────────
# MAIN BUILD FUNCTION
# ─────────────────────────────────────────────

def build_cwe_index():
    """Main function to build CWE knowledge base."""
    print("=== Building CWE Knowledge Base ===")
    print()
    
    # Step 1: Initialize schema
    init_cwe_schema()
    
    # Step 2: Get Top 25 CWE IDs
    print("Fetching CWE Top 25 2025 (View 1435)...")
    top25_ids = fetch_cwe_top25_view()
    print(f"Found {len(top25_ids)} CWE IDs in Top 25 2025: {top25_ids}")
    print()
    
    if not top25_ids:
        print("[ERROR] No CWE IDs retrieved. Exiting.")
        return
    
    # Step 3: Fetch and insert each CWE
    success_count = 0
    for cwe_id in top25_ids:
        print(f"Fetching CWE-{cwe_id}...")
        weakness = fetch_cwe_weakness(cwe_id)
        if weakness:
            is_top25 = cwe_id in top25_ids
            if insert_cwe_entry(cwe_id, weakness, is_top25):
                success_count += 1
                print(f"  ✓ CWE-{cwe_id}: {weakness.get('Name', 'Unknown')}")
            else:
                print(f"  ✗ CWE-{cwe_id}: Insert failed")
        else:
            print(f"  ✗ CWE-{cwe_id}: Fetch failed")
        time.sleep(1)  # Rate limiting - 1 second delay
    
    print()
    print(f"=== Build Complete: {success_count}/{len(top25_ids)} CWEs indexed ===")


if __name__ == "__main__":
    build_cwe_index()