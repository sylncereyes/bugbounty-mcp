"""
build_rfc_index.py
Fetches and indexes HTTP-related RFCs into SQLite tables for MCP tools.
Table is rebuilt from scratch each run.
"""
import sys
import os
import sqlite3
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import shared RFC parsing functions from db.py
from tools.db import (
    fetch_rfc_text,
    extract_rfc_title,
    extract_rfc_status,
    clean_rfc_pagination,
    parse_rfc_sections,
)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "bugbounty.db")

# Seed list of HTTP-related RFCs - easy to extend
RFC_SEED_LIST = [
    {"number": 9110, "title": "HTTP Semantics"},
    {"number": 9111, "title": "HTTP Caching"},
    {"number": 9112, "title": "HTTP/1.1"},
    {"number": 9113, "title": "HTTP/2"},
    {"number": 9114, "title": "HTTP/3"},
    {"number": 6265, "title": "HTTP State Management Mechanism (Cookies)"},
    {"number": 6797, "title": "HTTP Strict Transport Security (HSTS)"},
    {"number": 7616, "title": "HTTP Digest Access Authentication"},
    {"number": 7617, "title": "The 'Basic' HTTP Authentication Scheme"},
    {"number": 6585, "title": "Additional HTTP Status Codes"},
    {"number": 5789, "title": "PATCH Method for HTTP"},
    {"number": 7239, "title": "Forwarded HTTP Extension"},
    {"number": 8246, "title": "HTTP Immutable Responses"},
    {"number": 8941, "title": "Structured Field Values for HTTP"},
    {"number": 9218, "title": "Extensible Prioritization Scheme for HTTP"},
    {"number": 3986, "title": "Uniform Resource Identifier (URI): Generic Syntax"},
]


def build_index():
    """Build RFC index from seed list into SQLite tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    cursor = conn.cursor()

    # Drop and recreate tables (rebuild from scratch)
    cursor.executescript("""
        DROP TABLE IF EXISTS rfc_sections;
        DROP TABLE IF EXISTS rfc_documents;

        CREATE TABLE rfc_documents (
            rfc_number INTEGER PRIMARY KEY,
            title TEXT,
            status TEXT,
            fetched_at TEXT,
            full_text TEXT
        );

        CREATE VIRTUAL TABLE rfc_sections USING fts5(
            rfc_number UNINDEXED,
            section_number,
            section_title,
            content,
            tokenize='porter unicode61'
        );
    """)

    fetched_count = 0
    section_count = 0
    errors = []

    for rfc_entry in RFC_SEED_LIST:
        rfc_number = rfc_entry["number"]
        print(f"[INFO] Fetching RFC {rfc_number}...")

        raw_text = fetch_rfc_text(rfc_number)
        if raw_text.startswith("[ERROR]"):
            errors.append(rfc_number)
            print(f"[WARN] Could not fetch RFC {rfc_number}, skipping...")
            continue

        # Clean pagination but keep full text raw
        cleaned_text = clean_rfc_pagination(raw_text, rfc_number)

        # Extract status info from header
        status = extract_rfc_status(cleaned_text)

        # Use title from seed list (pre-verified)
        title = rfc_entry["title"]

        # Insert into rfc_documents
        cursor.execute(
            "INSERT INTO rfc_documents (rfc_number, title, status, fetched_at, full_text) VALUES (?, ?, ?, ?, ?)",
            (rfc_number, title, status, datetime.now(timezone.utc).isoformat(), cleaned_text)
        )
        fetched_count += 1

        # Parse and insert sections
        sections = parse_rfc_sections(cleaned_text)
        for section_num, section_title, content in sections:
            cursor.execute(
                "INSERT INTO rfc_sections (rfc_number, section_number, section_title, content) VALUES (?, ?, ?, ?)",
                (rfc_number, section_num, section_title, content)
            )
            section_count += 1

        # Delay 1 second between requests (polite)
        time.sleep(1)

    conn.commit()
    conn.close()

    print(f"[OK] Indexed {fetched_count} RFCs to rfc_documents")
    print(f"[OK] Indexed {section_count} sections to rfc_sections (FTS5)")
    if errors:
        print(f"[WARN] Failed to fetch: {errors}")


if __name__ == "__main__":
    build_index()