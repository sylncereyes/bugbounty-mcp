"""
TryHackMe Knowledge Base Module
================================
Manual room index + notes system with FTS5 search.
No auto-sync from API (blocked by Vercel challenge) — rooms added manually or via bulk import.
"""

import csv
import io
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from mcp_instance import mcp
from tools.db import db_connection

# CSV source for THM room metadata (community-maintained, data as of Dec 2024)
THM_CSV_URL = "https://raw.githubusercontent.com/adnan-kutay-yuksel/tryhackme-all-rooms-database/main/tryhackme-all-rooms-database.csv"


# ──────────────────────────────────────────────────────────────────────────────
# Database Initialization
# ──────────────────────────────────────────────────────────────────────────────

def init_thm_db() -> None:
    """Create THM tables if they don't exist."""
    with db_connection() as conn:
        # thm_rooms_index — metadata index
        conn.execute("""
            CREATE TABLE IF NOT EXISTS thm_rooms_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_code TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                difficulty TEXT,
                room_type TEXT,
                tags TEXT,
                is_free INTEGER DEFAULT 1,
                user_count INTEGER DEFAULT 0,
                thm_created_at TEXT,
                indexed_at TEXT DEFAULT (datetime('now')),
                last_updated TEXT DEFAULT (datetime('now'))
            )
        """)

        # thm_notes — user notes per task
        conn.execute("""
            CREATE TABLE IF NOT EXISTS thm_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_code TEXT NOT NULL REFERENCES thm_rooms_index(room_code) ON DELETE CASCADE,
                task_number INTEGER,
                task_title TEXT,
                content TEXT NOT NULL,
                tools_used TEXT,
                flags_found TEXT,
                added_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                UNIQUE(room_code, task_number)
            )
        """)

        # FTS5 virtual table for full-text search on notes
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS thm_notes_fts USING fts5(
                room_code,
                task_title,
                content,
                tools_used,
                content='thm_notes',
                content_rowid='id'
            )
        """)

        # Triggers to keep FTS in sync
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS thm_notes_ai AFTER INSERT ON thm_notes BEGIN
                INSERT INTO thm_notes_fts(rowid, room_code, task_title, content, tools_used)
                VALUES (new.id, new.room_code, new.task_title, new.content, new.tools_used);
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS thm_notes_ad AFTER DELETE ON thm_notes BEGIN
                INSERT INTO thm_notes_fts(thm_notes_fts, rowid, room_code, task_title, content, tools_used)
                VALUES ('delete', old.id, old.room_code, old.task_title, old.content, old.tools_used);
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS thm_notes_au AFTER UPDATE ON thm_notes BEGIN
                INSERT INTO thm_notes_fts(thm_notes_fts, rowid, room_code, task_title, content, tools_used)
                VALUES ('delete', old.id, old.room_code, old.task_title, old.content, old.tools_used);
                INSERT INTO thm_notes_fts(rowid, room_code, task_title, content, tools_used)
                VALUES (new.id, new.room_code, new.task_title, new.content, new.tools_used);
            END
        """)

        # Indexes for common queries
        conn.execute("CREATE INDEX IF NOT EXISTS idx_thm_rooms_difficulty ON thm_rooms_index(difficulty)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_thm_rooms_type ON thm_rooms_index(room_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_thm_notes_room ON thm_notes(room_code)")

        conn.commit()


# Initialize on module load
init_thm_db()


# ──────────────────────────────────────────────────────────────────────────────
# Core Functions
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_difficulty(diff: str | None) -> str | None:
    """Normalize difficulty to lowercase string."""
    if not diff:
        return None
    diff = diff.lower().strip()
    # Map common variations
    mapping = {
        "easy": "easy",
        "beginner": "easy",
        "medium": "medium",
        "intermediate": "medium",
        "hard": "hard",
        "advanced": "hard",
        "insane": "insane",
        "expert": "insane",
        "info": "info",
        "informational": "info",
    }
    return mapping.get(diff, diff)


def _normalize_room_type(rtype: str | None) -> str | None:
    """Normalize room type to lowercase string."""
    if not rtype:
        return None
    return rtype.lower().strip()


def _thm_add_room_impl(
    room_code: str,
    title: str,
    description: str | None = None,
    difficulty: str | None = None,
    room_type: str | None = None,
    tags: list[str] | None = None,
    is_free: int = 1,
    user_count: int = 0,
    thm_created_at: str | None = None,
) -> dict[str, Any]:
    """
    Add or update a THM room in the index.
    Returns: {"status": "ok", "room_code": ..., "action": "inserted"/"updated"}
    """
    room_code = room_code.strip().lower()
    if not room_code:
        raise ValueError("room_code cannot be empty")

    now = datetime.now().isoformat()
    diff = _normalize_difficulty(difficulty)
    rtype = _normalize_room_type(room_type)
    tags_json = json.dumps(tags or [])

    with db_connection() as conn:
        # Check if exists
        existing = conn.execute(
            "SELECT 1 FROM thm_rooms_index WHERE room_code = ?", (room_code,)
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE thm_rooms_index SET
                    title = ?, description = ?, difficulty = ?, room_type = ?,
                    tags = ?, is_free = ?, user_count = ?, thm_created_at = ?,
                    last_updated = ?
                WHERE room_code = ?
                """,
                (title, description, diff, rtype, tags_json, is_free, user_count,
                 thm_created_at, now, room_code),
            )
            action = "updated"
        else:
            conn.execute(
                """
                INSERT INTO thm_rooms_index
                (room_code, title, description, difficulty, room_type, tags,
                 is_free, user_count, thm_created_at, indexed_at, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (room_code, title, description, diff, rtype, tags_json,
                 is_free, user_count, thm_created_at, now, now),
            )
            action = "inserted"
        conn.commit()

    return {"status": "ok", "room_code": room_code, "action": action}


def _thm_import_rooms_impl(file_path: str) -> dict[str, Any]:
    """
    Bulk import rooms from JSON or CSV file.
    JSON format: [{"room_code": "...", "title": "...", "difficulty": "...", ...}, ...]
    CSV format: columns matching room fields
    Returns: {"imported": N, "skipped": N, "errors": [...]}
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    imported = 0
    skipped = 0
    errors = []

    if path.suffix.lower() == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("JSON must be a list of room objects")

        for idx, room in enumerate(data):
            try:
                if not room.get("room_code") or not room.get("title"):
                    errors.append(f"Row {idx}: missing room_code or title")
                    skipped += 1
                    continue
                _thm_add_room_impl(
                    room_code=room["room_code"],
                    title=room["title"],
                    description=room.get("description"),
                    difficulty=room.get("difficulty"),
                    room_type=room.get("room_type"),
                    tags=room.get("tags"),
                    is_free=room.get("is_free", 1),
                    user_count=room.get("user_count", 0),
                    thm_created_at=room.get("thm_created_at"),
                )
                imported += 1
            except Exception as e:
                errors.append(f"Row {idx}: {e}")
                skipped += 1

    elif path.suffix.lower() == ".csv":
        import csv
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                try:
                    if not row.get("room_code") or not row.get("title"):
                        errors.append(f"Row {idx}: missing room_code or title")
                        skipped += 1
                        continue
                    # Parse tags from CSV (comma-separated string or JSON)
                    tags = row.get("tags")
                    if tags:
                        try:
                            tags = json.loads(tags)
                        except json.JSONDecodeError:
                            tags = [t.strip() for t in tags.split(",") if t.strip()]

                    _thm_add_room_impl(
                        room_code=row["room_code"],
                        title=row["title"],
                        description=row.get("description"),
                        difficulty=row.get("difficulty"),
                        room_type=row.get("room_type"),
                        tags=tags,
                        is_free=int(row.get("is_free", 1)),
                        user_count=int(row.get("user_count", 0)),
                        thm_created_at=row.get("thm_created_at"),
                    )
                    imported += 1
                except Exception as e:
                    errors.append(f"Row {idx}: {e}")
                    skipped += 1
    else:
        raise ValueError("Unsupported file format. Use .json or .csv")

    return {"imported": imported, "skipped": skipped, "errors": errors}


def _thm_list_rooms_impl(
    difficulty: str | None = None,
    room_type: str | None = None,
    free_only: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List rooms with optional filters."""
    diff = _normalize_difficulty(difficulty)
    rtype = _normalize_room_type(room_type)

    query = """
        SELECT room_code, title, difficulty, room_type, tags, is_free, user_count
        FROM thm_rooms_index
        WHERE 1=1
    """
    params = []
    if diff:
        query += " AND difficulty = ?"
        params.append(diff)
    if rtype:
        query += " AND room_type = ?"
        params.append(rtype)
    if free_only:
        query += " AND is_free = 1"
    query += " ORDER BY user_count DESC LIMIT ?"
    params.append(limit)

    with db_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    return [
        {
            "room_code": r[0],
            "title": r[1],
            "difficulty": r[2],
            "room_type": r[3],
            "tags": json.loads(r[4]) if r[4] else [],
            "is_free": bool(r[5]),
            "user_count": r[6],
        }
        for r in rows
    ]


def _thm_get_room_impl(room_code: str) -> dict[str, Any] | None:
    """Get room metadata by room_code."""
    room_code = room_code.strip().lower()
    with db_connection() as conn:
        row = conn.execute(
            """
            SELECT room_code, title, description, difficulty, room_type, tags,
                   is_free, user_count, thm_created_at, indexed_at, last_updated
            FROM thm_rooms_index WHERE room_code = ?
            """,
            (room_code,),
        ).fetchone()

    if not row:
        return None

    return {
        "room_code": row[0],
        "title": row[1],
        "description": row[2],
        "difficulty": row[3],
        "room_type": row[4],
        "tags": json.loads(row[5]) if row[5] else [],
        "is_free": bool(row[6]),
        "user_count": row[7],
        "thm_created_at": row[8],
        "indexed_at": row[9],
        "last_updated": row[10],
    }


def _thm_add_note_impl(
    room_code: str,
    task_number: int,
    task_title: str,
    content: str,
    tools_used: list[str] | None = None,
    flags_found: list[str] | None = None,
) -> dict[str, Any]:
    """
    Add or update a note for a room task.
    Validates room_code exists in thm_rooms_index.
    Returns: {"status": "ok", "room_code": ..., "task_number": ..., "action": "inserted"/"updated"}
    """
    room_code = room_code.strip().lower()
    if not room_code:
        raise ValueError("room_code cannot be empty")
    if task_number < 1:
        raise ValueError("task_number must be >= 1")

    # Validate room exists
    room = _thm_get_room_impl(room_code)
    if not room:
        raise ValueError(f"Room '{room_code}' not found in index. Add it first with thm_add_room.")

    now = datetime.now().isoformat()
    tools_json = json.dumps(tools_used or [])
    flags_json = json.dumps(flags_found or [])

    with db_connection() as conn:
        existing = conn.execute(
            "SELECT 1 FROM thm_notes WHERE room_code = ? AND task_number = ?",
            (room_code, task_number),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE thm_notes SET
                    task_title = ?, content = ?, tools_used = ?, flags_found = ?, updated_at = ?
                WHERE room_code = ? AND task_number = ?
                """,
                (task_title, content, tools_json, flags_json, now, room_code, task_number),
            )
            action = "updated"
        else:
            conn.execute(
                """
                INSERT INTO thm_notes
                (room_code, task_number, task_title, content, tools_used, flags_found, added_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (room_code, task_number, task_title, content, tools_json, flags_json, now, now),
            )
            action = "inserted"
        conn.commit()

    return {"status": "ok", "room_code": room_code, "task_number": task_number, "action": action}


def _thm_search_notes_impl(query: str, limit: int = 10) -> list[dict[str, Any]]:
    """
    Full-text search on notes using FTS5.
    Returns list of matching notes with room metadata and snippet.
    """
    if not query or not query.strip():
        return []

    safe_query = query.strip()
    if '"' not in safe_query and "'" not in safe_query:
        safe_query = ' OR '.join(safe_query.split())

    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                n.room_code,
                r.title as room_title,
                r.difficulty,
                r.tags,
                n.task_number,
                n.task_title,
                n.content,
                n.tools_used,
                n.flags_found,
                snippet(thm_notes_fts, 2, '<b>', '</b>', '...', 64) AS snippet
            FROM thm_notes_fts
            JOIN thm_notes n ON n.id = thm_notes_fts.rowid
            JOIN thm_rooms_index r ON r.room_code = n.room_code
            WHERE thm_notes_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (safe_query, limit),
        ).fetchall()

    results = []
    for r in rows:
        results.append({
            "room_code": r[0],
            "room_title": r[1],
            "difficulty": r[2],
            "tags": json.loads(r[3]) if r[3] else [],
            "task_number": r[4],
            "task_title": r[5],
            "content_snippet": r[9] if r[9] else (r[6][:200] + ("..." if len(r[6] or "") > 200 else "")),
            "tools_used": json.loads(r[7]) if r[7] else [],
            "flags_found": json.loads(r[8]) if r[8] else [],
        })

    return results


def _thm_get_room_notes_impl(room_code: str) -> dict[str, Any] | None:
    """Get all notes for a room, ordered by task_number."""
    room_code = room_code.strip().lower()
    room = _thm_get_room_impl(room_code)
    if not room:
        return None

    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT task_number, task_title, content, tools_used, flags_found, added_at, updated_at
            FROM thm_notes WHERE room_code = ? ORDER BY task_number ASC
            """,
            (room_code,),
        ).fetchall()

    notes = [
        {
            "task_number": r[0],
            "task_title": r[1],
            "content": r[2],
            "tools_used": json.loads(r[3]) if r[3] else [],
            "flags_found": json.loads(r[4]) if r[4] else [],
            "added_at": r[5],
            "updated_at": r[6],
        }
        for r in rows
    ]

    return {"room": room, "notes": notes}


def _thm_get_stats_impl() -> dict[str, Any]:
    """Get database statistics for THM tables."""
    with db_connection() as conn:
        rooms_total = conn.execute("SELECT COUNT(*) FROM thm_rooms_index").fetchone()[0]
        notes_total = conn.execute("SELECT COUNT(*) FROM thm_notes").fetchone()[0]
        by_difficulty = conn.execute(
            "SELECT difficulty, COUNT(*) FROM thm_rooms_index GROUP BY difficulty"
        ).fetchall()
        by_type = conn.execute(
            "SELECT room_type, COUNT(*) FROM thm_rooms_index GROUP BY room_type"
        ).fetchall()

    return {
        "rooms_total": rooms_total,
        "notes_total": notes_total,
        "by_difficulty": {d: c for d, c in by_difficulty if d},
        "by_type": {t: c for t, c in by_type if t},
    }


# ──────────────────────────────────────────────────────────────────────────────
# CSV Sync & Manual Entry Functions
# ──────────────────────────────────────────────────────────────────────────────

def sync_thm_rooms_index() -> dict:
    """
    Fetch and import room metadata from community CSV on GitHub.
    Source: adnan-kutay-yuksel/tryhackme-all-rooms-database (data as of Dec 2024).
    Return: {"fetched": N, "upserted": N, "skipped": N, "total_in_db": N}
    """
    fetched = 0
    upserted = 0
    skipped = 0
    errors = []

    try:
        resp = requests.get(THM_CSV_URL, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        if resp.status_code != 200:
            return {
                "error": f"HTTP {resp.status_code}: Failed to fetch CSV",
                "fetched": 0, "upserted": 0, "skipped": 0, "total_in_db": 0
            }

        # Parse CSV
        csv_text = resp.text
        reader = csv.DictReader(io.StringIO(csv_text))

        with db_connection() as conn:
            for row in reader:
                fetched += 1

                # Extract room_code from LINK column
                link = row.get("LINK", "").strip()
                if not link or "/room/" not in link:
                    skipped += 1
                    continue

                room_code = link.split("/room/")[-1].strip("/")
                if not room_code:
                    skipped += 1
                    continue

                # Normalize fields
                title = row.get("NAME", "").strip()
                description = row.get("DESCRIPTION", "").strip() or None
                difficulty = _normalize_difficulty(row.get("DIFFICULTY", ""))
                room_type = _normalize_room_type(row.get("ROOM TYPE", ""))

                # is_free: 1 for Free, 0 for Premium, default 1
                sub_type = row.get("SUBSCRIPTION TYPE", "").strip()
                is_free = 1 if sub_type.lower() == "free" else 0

                # thm_created_at: from CREATED DATE (DD.MM.YYYY or DD-MM-YYYY)
                thm_created_at = row.get("CREATED DATE", "").strip() or None

                # tags: combine SPECIFIC TOOLS + TARGET SYSTEMS
                tags_list = []
                specific_tools = row.get("SPECIFIC TOOLS", "").strip()
                if specific_tools and specific_tools != "-":
                    tags_list.extend([t.strip() for t in specific_tools.split(",") if t.strip() and t.strip() != "-"])
                target_systems = row.get("TARGET SYSTEMS", "").strip()
                if target_systems:
                    tags_list.extend([t.strip() for t in target_systems.split(",") if t.strip() and t.strip() != "-"])
                # Deduplicate
                tags_list = list(dict.fromkeys(tags_list))
                tags_json = json.dumps(tags_list)

                # UPSERT
                now = datetime.now().isoformat()
                existing = conn.execute(
                    "SELECT 1 FROM thm_rooms_index WHERE room_code = ?", (room_code,)
                ).fetchone()

                if existing:
                    conn.execute(
                        """UPDATE thm_rooms_index SET
                            title = ?, description = ?, difficulty = ?, room_type = ?,
                            tags = ?, is_free = ?, thm_created_at = ?, last_updated = ?
                         WHERE room_code = ?""",
                        (title, description, difficulty, room_type, tags_json,
                         is_free, thm_created_at, now, room_code)
                    )
                else:
                    conn.execute(
                        """INSERT INTO thm_rooms_index
                           (room_code, title, description, difficulty, room_type, tags,
                            is_free, user_count, thm_created_at, indexed_at, last_updated)
                           VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)""",
                        (room_code, title, description, difficulty, room_type, tags_json,
                         is_free, thm_created_at, now, now)
                    )
                upserted += 1

            conn.commit()

        # Get total count
        with db_connection() as conn:
            total_in_db = conn.execute("SELECT COUNT(*) FROM thm_rooms_index").fetchone()[0]

        return {
            "fetched": fetched,
            "upserted": upserted,
            "skipped": skipped,
            "errors": errors,
            "total_in_db": total_in_db
        }

    except Exception as e:
        return {
            "error": str(e),
            "fetched": fetched,
            "upserted": upserted,
            "skipped": skipped,
            "total_in_db": 0
        }


def add_thm_room(
    room_code: str,
    title: str,
    difficulty: str = "unknown",
    room_type: str = "unknown",
    description: str = "",
    tags: list = None,
    is_free: bool = True
) -> dict:
    """Add or update a single THM room manually to thm_rooms_index."""
    room_code = room_code.strip().lower()
    if not room_code:
        raise ValueError("room_code cannot be empty")

    diff = _normalize_difficulty(difficulty)
    rtype = _normalize_room_type(room_type)
    tags_json = json.dumps(tags or [])
    is_free_int = 1 if is_free else 0

    with db_connection() as conn:
        existing = conn.execute(
            "SELECT 1 FROM thm_rooms_index WHERE room_code = ?", (room_code,)
        ).fetchone()

        now = datetime.now().isoformat()

        if existing:
            conn.execute(
                """UPDATE thm_rooms_index SET
                    title = ?, description = ?, difficulty = ?, room_type = ?,
                    tags = ?, is_free = ?, last_updated = ?
                 WHERE room_code = ?""",
                (title, description, diff, rtype, tags_json, is_free_int, now, room_code)
            )
            action = "updated"
        else:
            conn.execute(
                """INSERT INTO thm_rooms_index
                   (room_code, title, description, difficulty, room_type, tags,
                    is_free, user_count, indexed_at, last_updated)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
                (room_code, title, description, diff, rtype, tags_json,
                 is_free_int, now, now)
            )
            action = "inserted"
        conn.commit()

    return {"status": "ok", "room_code": room_code, "action": action}


# ──────────────────────────────────────────────────────────────────────────────
# MCP Tools
# ──────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def thm_sync_rooms() -> dict:
    """
    Sync TryHackMe room index from community CSV on GitHub
    (adnan-kutay-yuksel/tryhackme-all-rooms-database, data as of Dec 2024).
    Run once to seed initial data. Idempotent — safe to re-run.
    """
    return sync_thm_rooms_index()


@mcp.tool()
def thm_add_room(
    room_code: str,
    title: str,
    difficulty: str = "unknown",
    room_type: str = "unknown",
    description: str = "",
    tags: list[str] | None = None,
    is_free: bool = True
) -> dict[str, Any]:
    """
    Add or update a TryHackMe room manually. Use for rooms not in the community CSV
    or to override/update existing data.

    Args:
        room_code: Room slug from URL (e.g., 'blue' for tryhackme.com/room/blue)
        title: Room title
        difficulty: 'easy', 'medium', 'hard', 'insane', 'info' (case-insensitive)
        room_type: 'challenge', 'walkthrough', 'ctf', etc.
        description: Optional room description
        tags: List of tags (e.g., ['web', 'sqli', 'rce'])
        is_free: True if free room, False if subscriber-only

    Returns: {"status": "ok", "room_code": "...", "action": "inserted"/"updated"}
    """
    return add_thm_room(
        room_code=room_code,
        title=title,
        difficulty=difficulty,
        room_type=room_type,
        description=description,
        tags=tags,
        is_free=is_free,
    )


@mcp.tool()
def thm_import_rooms(file_path: str) -> dict[str, Any]:
    """
    Bulk import THM rooms from a JSON or CSV file.
    Useful for importing exported room lists or community-maintained lists.

    JSON format: [{"room_code": "...", "title": "...", "difficulty": "...", ...}, ...]
    CSV format: columns matching room fields (tags as comma-separated or JSON array)

    Args:
        file_path: Path to .json or .csv file

    Returns: {"imported": N, "skipped": N, "errors": [...]}
    """
    return _thm_import_rooms_impl(file_path)


@mcp.tool()
def thm_list_rooms(
    difficulty: str | None = None,
    room_type: str | None = None,
    free_only: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    List THM rooms from local index with optional filters.

    Args:
        difficulty: Filter by difficulty ('easy', 'medium', 'hard', 'insane', 'info')
        room_type: Filter by room type ('challenge', 'walkthrough', 'ctf', etc.)
        free_only: Only show free rooms
        limit: Max results (default 50)

    Returns: List of rooms ordered by user_count DESC
    """
    return _thm_list_rooms_impl(difficulty=difficulty, room_type=room_type, free_only=free_only, limit=limit)


@mcp.tool()
def thm_add_note(
    room_code: str,
    task_number: int,
    task_title: str,
    content: str,
    tools_used: list[str] | None = None,
    flags_found: list[str] | None = None,
) -> dict[str, Any]:
    """
    Add or update notes for a specific task in a room.
    Room must exist in index (use thm_add_room first).

    Args:
        room_code: Room slug (must exist in index)
        task_number: Task number (1, 2, 3, ...)
        task_title: Title of the task
        content: Note content (markdown supported)
        tools_used: List of tools used (e.g., ['nmap', 'gobuster', 'burpsuite'])
        flags_found: List of flags found (e.g., ['THM{flag1}', 'THM{flag2}'])

    Returns: {"status": "ok", "room_code": "...", "task_number": N, "action": "inserted"/"updated"}
    """
    return _thm_add_note_impl(
        room_code=room_code,
        task_number=task_number,
        task_title=task_title,
        content=content,
        tools_used=tools_used,
        flags_found=flags_found,
    )


@mcp.tool()
def thm_search_notes(query: str, limit: int = 10) -> list[dict[str, Any]]:
    """
    Full-text search across all THM notes using FTS5.
    Searches task_title, content, and tools_used fields.

    Args:
        query: Search query (supports FTS5 syntax: "term1 term2", '"exact phrase"', "term*")
        limit: Max results (default 10)

    Returns: List of matching notes with room metadata and content snippets
    """
    return _thm_search_notes_impl(query, limit)


@mcp.tool()
def thm_get_room_notes(room_code: str) -> dict[str, Any] | None:
    """
    Get all notes for a specific room, ordered by task number.

    Args:
        room_code: Room slug

    Returns: {"room": {...metadata...}, "notes": [...]} or None if room not found
    """
    return _thm_get_room_notes_impl(room_code)


@mcp.tool()
def thm_get_stats() -> dict[str, Any]:
    """
    Get statistics for the THM knowledge base.

    Returns: {"rooms_total": N, "notes_total": N, "by_difficulty": {...}, "by_type": {...}}
    """
    return _thm_get_stats_impl()