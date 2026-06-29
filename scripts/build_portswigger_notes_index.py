#!/usr/bin/env python3
"""
Build PortSwigger Notes knowledge base from .docx files.
Reads from PORTSWIGGER_NOTES_PATH environment variable (external directory).
Creates tables: portswigger_kb, portswigger_kb_fts
"""
import sys
import os
from pathlib import Path

# Add tools to path for db functions
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from db import get_connection, db_connection

import docx
from dotenv import load_dotenv

load_dotenv()


# ─────────────────────────────────────────────
# PATH VALIDATION
# ─────────────────────────────────────────────

def get_portswigger_notes_path() -> Path:
    """Get and validate the PortSwigger notes path from environment variable."""
    path_str = os.getenv("PORTSWIGGER_NOTES_PATH")
    if not path_str:
        raise RuntimeError(
            "PORTSWIGGER_NOTES_PATH environment variable not set. "
            "Set it in .env to the folder containing your .docx files."
        )
    path = Path(path_str)
    if not path.is_dir():
        raise RuntimeError(
            f"PORTSWIGGER_NOTES_PATH does not exist or is not a directory: {path}. "
            "Set PORTSWIGGER_NOTES_PATH in .env to a folder containing .docx files."
        )
    return path


# ─────────────────────────────────────────────
# SCHEMA INITIALIZATION
# ─────────────────────────────────────────────

def init_portswigger_schema() -> None:
    """Initialize PortSwigger tables and FTS5 index."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript("""
            -- Drop existing tables for fresh rebuild
            DROP TABLE IF EXISTS portswigger_kb_fts;
            DROP TABLE IF EXISTS portswigger_kb;

            -- Main PortSwigger knowledge base table
            CREATE TABLE portswigger_kb (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_title       TEXT NOT NULL,
                section_title   TEXT NOT NULL,
                section_type    TEXT NOT NULL,
                parent_lab_title TEXT,
                content         TEXT NOT NULL,
                order_index     INTEGER NOT NULL,
                created_at      TEXT DEFAULT (datetime('now'))
            );

            -- FTS5 virtual table for full-text search
            CREATE VIRTUAL TABLE portswigger_kb_fts USING fts5(
                doc_title,
                section_title,
                content,
                tokenize='porter unicode61'
            );

            -- Triggers to keep FTS in sync
            CREATE TRIGGER portswigger_kb_ai AFTER INSERT ON portswigger_kb BEGIN
                INSERT INTO portswigger_kb_fts(doc_title, section_title, content)
                VALUES (new.doc_title, new.section_title, new.content);
            END;

            CREATE TRIGGER portswigger_kb_ad AFTER DELETE ON portswigger_kb BEGIN
                DELETE FROM portswigger_kb_fts WHERE rowid = old.rowid;
            END;

            CREATE TRIGGER portswigger_kb_au AFTER UPDATE ON portswigger_kb BEGIN
                UPDATE portswigger_kb_fts
                SET doc_title = new.doc_title,
                    section_title = new.section_title,
                    content = new.content
                WHERE rowid = old.rowid;
            END;

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_portswigger_doc ON portswigger_kb(doc_title);
            CREATE INDEX IF NOT EXISTS idx_portswigger_type ON portswigger_kb(section_type);
            CREATE INDEX IF NOT EXISTS idx_portswigger_parent ON portswigger_kb(parent_lab_title);
            CREATE INDEX IF NOT EXISTS idx_portswigger_order ON portswigger_kb(doc_title, order_index);
        """)
    print("PortSwigger schema initialized (fresh rebuild)")


# ─────────────────────────────────────────────
# PARSING FUNCTIONS
# ─────────────────────────────────────────────

def parse_docx_file(file_path: Path) -> list:
    """
    Parse a .docx file into sections based on Heading 2 boundaries.
    Returns list of dicts with: doc_title, section_title, section_type, parent_lab_title, content, order_index
    """
    doc = docx.Document(file_path)
    doc_title = file_path.stem  # filename without extension
    
    sections = []
    current_section = None
    current_lab_title = None
    order_index = 0
    
    # Helper to finalize and store a section
    def finalize_section():
        nonlocal current_section, sections, order_index
        if current_section:
            current_section["order_index"] = order_index
            current_section["doc_title"] = doc_title
            sections.append(current_section)
            order_index += 1
            current_section = None
    
    for para in doc.paragraphs:
        style = para.style.name if para.style else ""
        text = para.text.strip()
        
        if not text:
            # Skip empty paragraphs but preserve them in content if we're in a section
            if current_section:
                current_section["content"] += "\n"
            continue
        
        # Check if this is a Heading 2 (section boundary)
        if style == "Heading 2":
            # Finalize previous section
            finalize_section()
            
            # Strip whitespace from heading text for classification comparison
            # (but preserve original text in section_title for display)
            heading_text = text.strip()
            
            # Determine section type based on heading text (using stripped version for comparison)
            if heading_text.startswith("Lab:"):
                # New lab - THIS IS THE ONLY THING THAT RESETS current_lab_title
                section_type = "lab"
                section_title = text  # Keep original text with whitespace for display
                current_lab_title = heading_text[4:].strip()  # Extract lab name after "Lab:"
                parent_lab_title = current_lab_title
            elif heading_text == "Hint":
                section_type = "lab_hint"
                section_title = f"{current_lab_title} - Hint" if current_lab_title else "Hint"
                parent_lab_title = current_lab_title
            elif heading_text in ("Solution", "Solutions") or heading_text.startswith("Solution –"):
                # Handle "Solution", "Solutions", "Solution – Burp Suite Professional", "Solution – Burp Suite Community Edition"
                section_type = "lab_solution"
                section_title = f"{current_lab_title} - Solution" if current_lab_title else "Solution"
                parent_lab_title = current_lab_title
            elif heading_text in ("Community Solutions", "Solutions Community"):
                # Handle both "Community Solutions" and typo "Solutions Community"
                section_type = "community_solutions"
                section_title = f"{current_lab_title} - Community Solutions" if current_lab_title else "Community Solutions"
                parent_lab_title = current_lab_title
            else:
                # Other Heading 2 (concept, sub-heading within lab, etc.)
                # DO NOT reset current_lab_title - only a new "Lab:" heading does that
                section_type = "concept"
                section_title = text  # Keep original text with whitespace for display
                parent_lab_title = current_lab_title  # Preserve current lab context
            
            # Start new section
            current_section = {
                "section_title": section_title,
                "section_type": section_type,
                "parent_lab_title": parent_lab_title,
                "content": ""
            }
        else:
            # Regular content paragraph (Normal, Normal (Web), List Paragraph)
            if current_section is None:
                # Content before first Heading 2 = concept section with doc_title as section_title
                current_section = {
                    "section_title": doc_title,
                    "section_type": "concept",
                    "parent_lab_title": None,
                    "content": ""
                }
            
            # Append paragraph text to content
            if current_section["content"]:
                current_section["content"] += "\n"
            current_section["content"] += text
    
    # Finalize last section
    finalize_section()
    
    return sections


def insert_sections(sections: list) -> int:
    """Insert parsed sections into database."""
    with db_connection() as conn:
        cursor = conn.cursor()
        for section in sections:
            cursor.execute("""
                INSERT INTO portswigger_kb 
                (doc_title, section_title, section_type, parent_lab_title, content, order_index)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                section["doc_title"],
                section["section_title"],
                section["section_type"],
                section["parent_lab_title"],
                section["content"],
                section["order_index"]
            ))
    return len(sections)


# ─────────────────────────────────────────────
# MAIN BUILD FUNCTION
# ─────────────────────────────────────────────

def build_portswigger_index():
    """Main function to build PortSwigger knowledge base from .docx files."""
    print("=== Building PortSwigger Notes Knowledge Base ===\n")
    
    # Validate path
    notes_path = get_portswigger_notes_path()
    print(f"Reading from: {notes_path}")
    
    # Find .docx files
    docx_files = list(notes_path.glob("*.docx"))
    if not docx_files:
        raise RuntimeError(f"No .docx files found in {notes_path}")
    
    print(f"Found {len(docx_files)} .docx files:")
    for f in docx_files:
        print(f"  - {f.name}")
    print()
    
    # Initialize schema
    init_portswigger_schema()
    
    # Parse and index each file
    total_sections = 0
    for docx_file in docx_files:
        print(f"Parsing: {docx_file.name}...")
        sections = parse_docx_file(docx_file)
        count = insert_sections(sections)
        total_sections += count
        print(f"  ✓ {count} sections indexed")
    
    print()
    print(f"=== Build Complete: {total_sections} sections from {len(docx_files)} documents ===")


if __name__ == "__main__":
    build_portswigger_index()