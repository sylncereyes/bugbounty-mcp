#!/usr/bin/env python3
"""
build_api_top10_index.py
Parses OWASP API Security Top 10 2023 markdown files from
/tmp/API-Security/editions/2023/en/ (cloned from OWASP/API-Security repo),
extracts API ID, title, and structured content, then indexes them into
a SQLite FTS5 table (api_top10_entries + api_top10_fts) inside database/bugbounty.db.

Table is rebuilt from scratch each run (idempotent).
"""
import sys
import os
import re
import sqlite3
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

API_SRC = Path("/tmp/API-Security/editions/2023/en")
DB_PATH = Path(__file__).parent.parent / "database" / "bugbounty.db"

# Only process the 10 actual risk category files (0xa1 through 0xaa)
# Skip: 0x00-0x04 (header/notice/toc/intro), 0x10 (acknowledgements), 0x11 (how-to-use-top-10)
# Skip: 0xb0, 0xb1 (appendix), 0xd0, 0xd1 (appendix)
API_FILE_PATTERN = re.compile(r"^0x(a[1-9]|aa)-.+\.md$")


def extract_section(text: str, section_name: str) -> str:
    """Extract a section from markdown text by header name."""
    pattern = rf"##\s+{re.escape(section_name)}\s*\n(.*?)(?=\n##\s+|\Z)"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def extract_api_id(filename: str) -> str:
    """Extract API ID from filename like '0xa1-broken-object-level-authorization.md' -> 'API1:2023'"""
    match = re.match(r"0x([a-f][0-9a-f])-", filename)
    if not match:
        return ""
    hex_id = match.group(1)
    # Convert hex to decimal: a1=161 -> 1, a2=162 -> 2, ..., aa=170 -> 10
    num = int(hex_id, 16) - 160  # 0xa1 = 161, 161-160=1
    return f"API{num}:2023"


def extract_title(content: str) -> str:
    """Extract title from first heading - remove API ID prefix if present"""
    title_match = re.match(r"#\s+(.+)", content)
    title = title_match.group(1).strip() if title_match else ""
    # Remove "API#:2023 " prefix if present
    title = re.sub(r"^API\d+:2023\s+", "", title)
    return title


def clean_content(text: str) -> str:
    """Clean content for indexing"""
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def build_index():
    if not API_SRC.exists():
        print(f"[ERROR] API Security source not found at {API_SRC}")
        print("[INFO] Run: git clone https://github.com/OWASP/API-Security.git /tmp/API-Security")
        sys.exit(1)

    entries = []
    skipped = 0

    for fpath in sorted(API_SRC.glob("*.md")):
        if not API_FILE_PATTERN.match(fpath.name):
            skipped += 1
            continue

        try:
            raw = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[WARN] Skipping {fpath.name}: {e}")
            skipped += 1
            continue

        content = clean_content(raw)
        if not content:
            skipped += 1
            continue

        api_id = extract_api_id(fpath.name)
        if not api_id:
            print(f"[WARN] Could not extract API ID from {fpath.name}")
            skipped += 1
            continue

        title = extract_title(content)
        description = extract_section(content, "Is the API Vulnerable?")
        if not description:
            description = extract_section(content, "Is the API Vulnerable")
        example_attack_scenarios = extract_section(content, "Example Attack Scenarios")
        if not example_attack_scenarios:
            example_attack_scenarios = extract_section(content, "Example Attack Scenario")
        mitigation = extract_section(content, "How To Prevent")
        if not mitigation:
            mitigation = extract_section(content, "How to Prevent")
        source_url = f"https://owasp.org/API-Security/editions/2023/en/{fpath.name}"

        entries.append((
            api_id,
            title,
            "2023",
            description,
            example_attack_scenarios,
            mitigation,
            source_url
        ))

    if skipped:
        print(f"[INFO] Skipped {skipped} non-category files")

    if not entries:
        print("[ERROR] No API Top 10 entries found")
        sys.exit(1)

    # Sort by API number
    entries.sort(key=lambda x: int(x[0].split(":")[0].replace("API", "")))
    print(f"[INFO] Parsed {len(entries)} API Top 10 categories")

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")

    cursor = conn.cursor()
    cursor.executescript("""
        DROP TABLE IF EXISTS api_top10_entries;
        DROP TABLE IF EXISTS api_top10_fts;
        CREATE TABLE api_top10_entries (
            id INTEGER PRIMARY KEY,
            api_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            edition TEXT NOT NULL DEFAULT '2023',
            description TEXT,
            example_attack_scenarios TEXT,
            mitigation TEXT,
            source_url TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE VIRTUAL TABLE api_top10_fts USING fts5(
            api_id, title, description, example_attack_scenarios, mitigation,
            content='api_top10_entries', content_rowid='id',
            tokenize='porter unicode61'
        );
        CREATE TRIGGER api_top10_fts_ai AFTER INSERT ON api_top10_entries BEGIN
            INSERT INTO api_top10_fts(rowid, api_id, title, description, example_attack_scenarios, mitigation)
            VALUES (new.id, new.api_id, new.title, new.description, new.example_attack_scenarios, new.mitigation);
        END;
        CREATE TRIGGER api_top10_fts_ad AFTER DELETE ON api_top10_entries BEGIN
            INSERT INTO api_top10_fts(api_top10_fts, rowid, api_id, title, description, example_attack_scenarios, mitigation)
            VALUES ('delete', old.id, old.api_id, old.title, old.description, old.example_attack_scenarios, old.mitigation);
        END;
        CREATE TRIGGER api_top10_fts_au AFTER UPDATE ON api_top10_entries BEGIN
            INSERT INTO api_top10_fts(api_top10_fts, rowid, api_id, title, description, example_attack_scenarios, mitigation)
            VALUES ('delete', old.id, old.api_id, old.title, old.description, old.example_attack_scenarios, old.mitigation);
            INSERT INTO api_top10_fts(rowid, api_id, title, description, example_attack_scenarios, mitigation)
            VALUES (new.id, new.api_id, new.title, new.description, new.example_attack_scenarios, new.mitigation);
        END;
    """)

    conn.executemany(
        "INSERT INTO api_top10_entries (api_id, title, edition, description, example_attack_scenarios, mitigation, source_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
        entries,
    )
    conn.commit()
    conn.close()

    print(f"[OK] Indexed {len(entries)} API Top 10 categories into api_top10_entries + api_top10_fts (FTS5)")


if __name__ == "__main__":
    build_index()