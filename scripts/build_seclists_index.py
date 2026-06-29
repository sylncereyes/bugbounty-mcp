"""
build_seclists_index.py
Mengumpulkan metadata wordlist mentah dari SecLists (atau apt source) ke tabel SQLite
seclists_index. Table tidak berisi isi file, cuma metadata path, kategori, jumlah baris.

Tabel di-rebuild dari nol setiap kali skrip dijalankan.
"""
import sys
import os
import re
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

SECLISTS_SRC = os.path.join(
    os.path.dirname(__file__), "..", "knowledge_base", "seclists_src"
)
DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "database", "bugbounty.db"
)

SKIP_FILES = {"README.md", "LICENSE", "CONTRIBUTING.md", "LICENSE.md", "pyvenv.cfg"}
SKIP_DIRS = {".git", ".github", "__pycache__", ".vscode"}
_KNOWN_SOURCE_TYPES = {"apt", "git"}
_SOURCE_TYPE = "git"  # default to git clone, can be overridden by environment var


def get_wordlist_line_count(filepath: str) -> int:
    """Hitung jumlah baris file wordlist secara efisien tanpa load seluruh file."""
    try:
        with open(filepath, "rb") as f:
            line_count = 0
            for line in f:
                if line.strip():
                    line_count += 1
        return line_count
    except Exception:
        return 0


def build_index():
    if not os.path.isdir(SECLISTS_SRC):
        print(f"[ERROR] Source SecLists tidak ditemukan di {SECLISTS_SRC}")
        sys.exit(1)

    entries = []

    for root, dirs, files in os.walk(SECLISTS_SRC):
        rel_dir = os.path.relpath(root, SECLISTS_SRC)

        skip = False
        parts = rel_dir.split(os.sep)
        for part in parts:
            if part in SKIP_DIRS:
                skip = True
                break
        if skip:
            continue

        category = "Unknown"
        if parts[0] != ".":
            category = parts[0]

        subcategory = ""
        if len(parts) >= 2:
            subcategory = parts[1]

        for fname in files:
            if fname in SKIP_FILES:
                continue
            if not (fname.lower().endswith(".txt") or fname.lower().endswith(".lst") or
                    fname.lower().endswith(".csv") or fname.lower().endswith(".json") or
                    fname.lower().endswith(".in")):
                continue

            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                line_count = get_wordlist_line_count(fpath)
            except Exception as e:
                print(f"[WARN] Skip {fpath}: {e}")
                continue

            entries.append((
                fpath, category, subcategory, fname, line_count, size
            ))

    print(f"[INFO] Parsed {len(entries)} wordlist file(s)")

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    cursor = conn.cursor()
    cursor.executescript("""
        DROP TABLE IF EXISTS seclists_index;
        CREATE TABLE seclists_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT,
            filename TEXT NOT NULL,
            line_count INTEGER NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(file_path)
        );
        CREATE INDEX idx_seclists_category ON seclists_index(category);
        CREATE INDEX idx_seclists_subcategory ON seclists_index(subcategory);
        CREATE INDEX idx_seclists_filename ON seclists_index(filename);
    """)

    conn.executemany(
        """
        INSERT INTO seclists_index (
            file_path, category, subcategory, filename, line_count, size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_path) DO NOTHING
        """,
        entries,
    )
    conn.commit()
    conn.close()

    print(f"[OK] Di-index {len(entries)} wordlist file ke seclists_index")


if __name__ == "__main__":
    build_index()
