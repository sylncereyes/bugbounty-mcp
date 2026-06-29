"""
build_patt_index.py
Parses all category README.md files and raw payload files from
PayloadsAllTheThings, indexes them into two SQLite tables in bugbounty.db:
- patt_kb: FTS5 table for category documentation search
- patt_raw_payloads: regular table for storing individual payloads

Tabel di-rebuild dari nol setiap kali skrip dijalankan.
"""
import sys
import os
import re
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PATT_SRC = os.path.join(
    os.path.dirname(__file__), "..", "knowledge_base", "patt_src"
)
DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "database", "bugbounty.db"
)

SKIP_DIRS = {"_template_vuln", ".git", "images", "_LEARNING_AND_SOCIALS", "Methodology and Resources"}
SKIP_FILES = {"LICENSE", "CONTRIBUTING.md", "mkdocs.yml", "README.md", "DISCLAIMER.md", "custom.css", "pyvenv.cfg", "book.json", "package.json", ".gitignore", "Makefile"}

_RAW_PAYLOAD_EXT = {".txt", ".lst", ".fuzz", ".csv", ".json"}


def clean_content(text: str) -> str:
    """Hapus YAML front matter dan markup Markdown ringan, pertahankan blok kode."""
    if text.strip().startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            text = text[end + 3:].strip()
    text = re.sub(r'> \[(.*?)\]\(.*?\)', '', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def extract_title(content: str) -> str:
    """Ambil baris H1 pertama sebagai title."""
    for line in content.splitlines():
        m = re.match(r'^#\s*(.+)$', line.strip())
        if m:
            return m.group(1).strip()
    return ""


def build_breadcrumb(rel_dir: str) -> str:
    """Ubah nama folder path relatif jadi breadcrumb ramah manusia."""
    if not rel_dir:
        return ""
    parts = rel_dir.split(os.sep)
    processed = []
    for p in parts:
        if p in SKIP_DIRS:
            continue
        processed.append(p.replace(" ", " ").title())
    return " / ".join(processed)


def build_index():
    if not os.path.isdir(PATT_SRC):
        print(f"[ERROR] Source PATT tidak ditemukan di {PATT_SRC}")
        sys.exit(1)

    entries = []
    raw_payloads = []

    for root, dirs, files in os.walk(PATT_SRC):
        rel_dir = os.path.relpath(root, PATT_SRC)
        if rel_dir == ".":
            rel_dir = ""

        skip = False
        for part in rel_dir.split(os.sep) if rel_dir else []:
            if part and part in SKIP_DIRS:
                skip = True
                break
        if skip:
            continue

        if rel_dir and rel_dir != "docs" and rel_dir != "tools":
            for fname in files:
                if fname.endswith(".md") and fname not in SKIP_FILES:
                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, PATT_SRC)
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
                        title = os.path.splitext(fname)[0].title()

                    breadcrumb = build_breadcrumb(rel_dir)
                    entries.append((rel_path, title, breadcrumb, content))

        if "Intruder" in dirs:
            intruder_dir = os.path.join(root, "Intruder")
            rel_intruder_dir = os.path.relpath(intruder_dir, PATT_SRC)
            for fname in os.listdir(intruder_dir):
                if fname.lower().endswith(('.txt', '.lst', '.fuzz', '.csv', '.json')):
                    fpath = os.path.join(intruder_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                            lines = fh.readlines()
                    except Exception as e:
                        print(f"[WARN] Skipping raw payload {fpath}: {e}")
                        continue

                    category = rel_intruder_dir.split(os.sep)[0] if rel_intruder_dir != "." else "Unknown"
                    for line_num, line in enumerate(lines, 1):
                        payload = line.strip()
                        if payload and not payload.startswith('#'):
                            raw_payloads.append((category, rel_path if 'rel_path' in locals() else rel_intruder_dir + '/' + fname, payload, line_num))

    print(f"[INFO] Parsed {len(entries)} kategori README")

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    cursor = conn.cursor()
    cursor.executescript("""
        DROP TABLE IF EXISTS patt_kb;
        CREATE VIRTUAL TABLE patt_kb USING fts5(
            path,
            title,
            breadcrumb,
            content,
            tokenize='porter unicode61'
        );
        DROP TABLE IF EXISTS patt_raw_payloads;
        CREATE TABLE patt_raw_payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            source_file TEXT NOT NULL,
            payload TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX idx_patt_raw_category ON patt_raw_payloads(category);
        CREATE INDEX idx_patt_raw_source_file ON patt_raw_payloads(source_file);
    """)

    conn.executemany(
        "INSERT INTO patt_kb (path, title, breadcrumb, content) VALUES (?, ?, ?, ?)",
        entries,
    )
    conn.executemany(
        "INSERT INTO patt_raw_payloads (category, source_file, payload, line_number) VALUES (?, ?, ?, ?)",
        raw_payloads,
    )
    conn.commit()
    conn.close()

    print(f"[OK] Di-index {len(entries)} kategori ke patt_kb (FTS5)")
    print(f"[OK] Disimpan {len(raw_payloads)} payload mentah ke patt_raw_payloads")


if __name__ == "__main__":
    build_index()
