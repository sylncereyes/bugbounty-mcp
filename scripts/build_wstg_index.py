"""
build_wstg_index.py
Parses all OWASP WSTG test case markdown files from
knowledge_base/owasp_wstg_src/document/4-Web_Application_Security_Testing/,
extracts WSTG-ID, title, breadcrumb, and content, then indexes them into
a SQLite FTS5 table (owasp_wstg_kb) inside database/bugbounty.db.

Table is rebuilt from scratch each run.
"""
import sys
import os
import re
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

WSTG_SRC = os.path.join(
    os.path.dirname(__file__),
    "..",
    "knowledge_base",
    "owasp_wstg_src",
    "document",
    "4-Web_Application_Security_Testing",
)
DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "database", "bugbounty.db"
)

SKIP_DIRS = {"images"}
SKIP_FILES = {"README.md"}

_WSTG_ID_RE = re.compile(r"WSTG-[A-Z]{4}-\d{2}")


def extract_wstg_id(content: str) -> str | None:
    m = _WSTG_ID_RE.search(content)
    return m.group(0) if m else None


def extract_title(content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("# ") and not stripped.startswith("## "):
            return stripped[2:].strip()
    return ""


def breadcrumb_from_dirname(dirname: str) -> str:
    parts = dirname.split("-", 1)
    if len(parts) > 1:
        return parts[1].replace("_", " ")
    return dirname.replace("_", " ")


def clean_content(text: str) -> str:
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def build_index():
    if not os.path.isdir(WSTG_SRC):
        print(f"[ERROR] WSTG source not found at {WSTG_SRC}")
        sys.exit(1)

    entries = []
    skipped = 0

    for root, dirs, files in os.walk(WSTG_SRC):
        rel_dir = os.path.relpath(root, WSTG_SRC)
        parts = rel_dir.split(os.sep)

        skip_this = False
        for part in parts:
            if part in SKIP_DIRS:
                skip_this = True
                break
        if skip_this:
            continue

        for fname in files:
            if not fname.endswith(".md"):
                continue
            if fname in SKIP_FILES:
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, WSTG_SRC)

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            except Exception as e:
                print(f"[WARN] Skipping {rel_path}: {e}")
                continue

            content = clean_content(raw)
            if not content:
                continue

            wstg_id = extract_wstg_id(content)
            if not wstg_id:
                skipped += 1
                continue

            title = extract_title(content)
            if not title:
                title = os.path.splitext(fname)[0].replace("_", " ").replace("-", " ").strip()

            if parts[0] == ".":
                breadcrumb = ""
            else:
                category_dir = parts[0]
                breadcrumb = breadcrumb_from_dirname(category_dir)

            entries.append((wstg_id, title, breadcrumb, content, rel_path))

    if skipped:
        print(f"[INFO] Skipped {skipped} files without WSTG-ID")

    if not entries:
        print("[ERROR] No WSTG test cases found")
        sys.exit(1)

    entries.sort(key=lambda x: x[0])
    print(f"[INFO] Parsed {len(entries)} WSTG test cases")

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    cursor = conn.cursor()
    cursor.executescript("""
        DROP TABLE IF EXISTS owasp_wstg_kb;
        CREATE VIRTUAL TABLE owasp_wstg_kb USING fts5(
            wstg_id,
            title,
            breadcrumb,
            content,
            path,
            tokenize='porter unicode61'
        );
    """)

    conn.executemany(
        "INSERT INTO owasp_wstg_kb (wstg_id, title, breadcrumb, content, path) VALUES (?, ?, ?, ?, ?)",
        entries,
    )
    conn.commit()
    conn.close()

    print(f"[OK] Indexed {len(entries)} WSTG test cases into owasp_wstg_kb (FTS5)")


if __name__ == "__main__":
    build_index()
