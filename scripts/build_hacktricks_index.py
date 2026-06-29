"""
build_hacktricks_index.py
Parses all .md files in knowledge_base/hacktricks_src/src/, cleans gitbook/mdbook
shortcodes, and indexes them into a SQLite FTS5 table (hacktricks_kb) inside
the existing database/bugbounty.db database.

Table is rebuilt from scratch each run.
"""
import sys
import os
import re
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HACKTRICKS_SRC = os.path.join(
    os.path.dirname(__file__), "..", "knowledge_base", "hacktricks_src", "src"
)
DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "database", "bugbounty.db"
)

SKIP_DIRS = {"images", ".gitbook"}

_SHORTCODE_RE = re.compile(
    r'\{\{#include\s+[^}]*\}\}'
    r'|\{\{#ref[^}]*\}\}'
    r'|{%\s*(raw|endraw|debug)\s*%}'
    r'|{%\s*(endfor|endwith)\s*%}'
    r'|{%\s*for\s+.*?%}'
    r'|{%\s*with\s+.*?%}',
    re.IGNORECASE | re.DOTALL,
)


def clean_content(text: str) -> str:
    text = _SHORTCODE_RE.sub("", text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = text.strip()
    return text


def extract_title(content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("# ") and not stripped.startswith("## "):
            return stripped[2:].strip()
    return ""


def build_breadcrumb(rel_dir: str) -> str:
    if not rel_dir:
        return ""
    parts = rel_dir.replace("-", " ").title().split(os.sep)
    return " / ".join(parts)


def build_index():
    if not os.path.isdir(HACKTRICKS_SRC):
        print(f"[ERROR] HackTricks source not found at {HACKTRICKS_SRC}")
        sys.exit(1)

    entries = []

    for root, dirs, files in os.walk(HACKTRICKS_SRC):
        rel_dir = os.path.relpath(root, HACKTRICKS_SRC)
        if rel_dir == ".":
            rel_dir = ""

        parts = rel_dir.split(os.sep)
        if parts and parts[0] in SKIP_DIRS:
            continue

        skip = False
        for part in parts:
            if part in SKIP_DIRS:
                skip = True
                break
        if skip:
            continue

        for fname in files:
            if not fname.endswith(".md"):
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, HACKTRICKS_SRC)

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            except Exception as e:
                print(f"[WARN] Skipping {rel_path}: {e}")
                continue

            content = clean_content(raw)
            if not content:
                continue

            title = extract_title(content)
            if not title:
                title = os.path.splitext(fname)[0].replace("-", " ").title()

            breadcrumb = build_breadcrumb(rel_dir)

            entries.append((rel_path, title, breadcrumb, content))

    print(f"[INFO] Parsed {len(entries)} markdown pages")

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    cursor = conn.cursor()
    cursor.executescript("""
        DROP TABLE IF EXISTS hacktricks_kb;
        CREATE VIRTUAL TABLE hacktricks_kb USING fts5(
            path,
            title,
            breadcrumb,
            content,
            tokenize='porter unicode61'
        );
    """)

    conn.executemany(
        "INSERT INTO hacktricks_kb (path, title, breadcrumb, content) VALUES (?, ?, ?, ?)",
        entries,
    )
    conn.commit()
    conn.close()

    print(f"[OK] Indexed {len(entries)} pages into hacktricks_kb (FTS5)")


if __name__ == "__main__":
    build_index()
