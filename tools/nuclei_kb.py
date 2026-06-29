#!/usr/bin/env python3
"""
AGY Bug Bounty MCP - Nuclei Templates Knowledge Base Tools
Search ProjectDiscovery nuclei-templates using SQLite FTS5.
"""
import sqlite3
import yaml
import json
from pathlib import Path
from mcp_instance import mcp
from tools.db import DB_PATH


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_nuclei_schema() -> None:
    """Initialize Nuclei templates tables."""
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nuclei_templates (
                id              INTEGER PRIMARY KEY,
                template_id     TEXT UNIQUE,
                info_name       TEXT,
                info_severity   TEXT,
                info_description TEXT,
                info_tags       TEXT,
                info_author     TEXT,
                template_path   TEXT,
                protocol        TEXT,
                fetched_at       TEXT
            )
        """)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS nuclei_fts USING fts5(
                template_id, info_name, info_severity, info_description, info_tags, info_author, protocol,
                content='nuclei_templates', content_rowid='id'
            )
        """)
    print("Nuclei schema initialized")


init_nuclei_schema()


@mcp.tool()
def sync_nuclei(templates_dir: str = None) -> dict:
    """Sync nuclei-templates dari cloned repo."""
    import os
    import re
    from datetime import datetime

    templates_path = templates_dir or str(DB_PATH.parent.parent / "knowledge_base" / "nuclei-templates")
    conn = _get_conn()
    count = 0
    errors = []

    if not os.path.isdir(templates_path):
        return {"error": f"Directory not found: {templates_path}", "synced": 0}

    # Clear existing
    conn.execute("DELETE FROM nuclei_templates")
    conn.execute("DELETE FROM nuclei_fts")

    templates_by_type = ["cves", "vulnerabilities", "misconfigurations", "exposures", "default-credentials"]

    for t in templates_by_type:
        dir_path = Path(templates_path) / t
        if not dir_path.exists():
            continue

        for yml_file in dir_path.rglob("*.yaml"):
            try:
                content = yml_file.read_text(encoding='utf-8')
                data = yaml.safe_load(content)
                if not data:
                    continue

                info = data.get('info') or {}
                template_id = yml_file.stem
                conn.execute(
                    """INSERT INTO nuclei_templates
                       (template_id, info_name, info_severity, info_description, info_tags, info_author, template_path)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        template_id,
                        info.get('name') or '',
                        ', '.join(info.get('severity') or []),
                        (info.get('description') or '')[:300],
                        ','.join(info.get('tags') or [])[:200],
                        ','.join(info.get('author') or [])[:100],
                        str(yml_file),
                    )
                )
                count += 1
            except Exception as e:
                errors.append(f"{yml_file.name}: {str(e)[:50]}")

    # Populate FTS
    for row in conn.execute("SELECT id, template_id, info_name, info_severity, info_description, info_tags, info_author, protocol FROM nuclei_templates"):
        conn.execute(
            "INSERT INTO nuclei_fts (rowid, template_id, info_name, info_severity, info_description, info_tags, info_author, protocol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (row["id"], row["template_id"], row["info_name"], row["info_severity"], row["info_description"], row["info_tags"], row["info_author"], row["protocol"])
        )

    conn.commit()
    conn.close()

    return {"synced": count, "errors": errors[:5]}


@mcp.tool()
def search_nuclei_templates(query: str, severity: str = None, limit: int = 20) -> list:
    """Full-text search Nuclei templates."""
    conn = _get_conn()

    q = query.replace('"', ' ').replace("'", " ")
    if severity:
        rows = conn.execute(
            """SELECT template_id, info_name, info_severity, info_description, template_path
               FROM nuclei_fts
               WHERE nuclei_fts MATCH ? AND info_severity = ?
               LIMIT ?""",
            (q, severity.upper(), limit)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT template_id, info_name, info_severity, info_description, template_path
               FROM nuclei_fts
               WHERE nuclei_fts MATCH ?
               LIMIT ?""",
            (q, limit)
        ).fetchall()

    conn.close()
    return [{"template_id": r["template_id"], "name": r["info_name"],
             "severity": r["info_severity"], "description": r["info_description"],
             "path": r["template_path"]} for r in rows]


@mcp.tool()
def get_nuclei_template(template_id: str) -> dict:
    """Get template details by ID."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM nuclei_templates WHERE template_id = ?", (template_id,)).fetchone()
    conn.close()
    if not row:
        return {"found": False}
    return {
        "found": True,
        "template_id": row["template_id"],
        "name": row["info_name"],
        "severity": row["info_severity"],
        "description": row["info_description"],
        "tags": row["info_tags"],
        "author": row["info_author"],
        "path": row["template_path"]
    }


@mcp.tool()
def list_nuclei_severities() -> list:
    """Get unique severities in templates."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT DISTINCT info_severity FROM nuclei_templates WHERE info_severity IS NOT NULL AND info_severity != '' ORDER BY info_severity"
    ).fetchall()
    conn.close()
    return [{"severity": r["info_severity"]} for r in rows]