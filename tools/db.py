"""
AGY Bug Bounty MCP - Database Layer
Handles all SQLite operations for targets, findings, assets, and scan logs.
"""
import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

# Resolve DB path from environment or use default
_DB_PATH_ENV = os.getenv("DB_PATH", "database/bugbounty.db")
_DB_PATH_RAW = Path(_DB_PATH_ENV)
DB_PATH = _DB_PATH_RAW if _DB_PATH_RAW.is_absolute() else Path(__file__).parent.parent / _DB_PATH_ENV


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with Row factory enabled."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_connection():
    """Context manager for safe database connections with auto-commit/rollback."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Initialize the database schema."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                program_name    TEXT    NOT NULL,
                domain          TEXT    NOT NULL,
                scope           TEXT,
                out_of_scope    TEXT,
                platform        TEXT,
                bounty_range    TEXT,
                notes           TEXT,
                created_at      TEXT    DEFAULT (datetime('now')),
                updated_at      TEXT    DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id           INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                title               TEXT    NOT NULL,
                vulnerability_type  TEXT,
                owasp_category      TEXT,
                severity            TEXT    CHECK(severity IN ('Critical','High','Medium','Low','Informational')),
                cvss_score          REAL,
                cvss_vector         TEXT,
                url                 TEXT,
                parameter           TEXT,
                payload             TEXT,
                description         TEXT,
                steps_to_reproduce  TEXT,
                impact              TEXT,
                remediation         TEXT,
                evidence            TEXT,
                status              TEXT    DEFAULT 'new'
                                    CHECK(status IN ('new','reported','accepted','rejected','duplicate','fixed')),
                created_at          TEXT    DEFAULT (datetime('now')),
                updated_at          TEXT    DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS assets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id       INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                asset_type      TEXT,
                value           TEXT,
                status_code     INTEGER,
                technologies    TEXT,
                open_ports      TEXT,
                title           TEXT,
                notes           TEXT,
                discovered_at   TEXT    DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS scan_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id       INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                tool_name       TEXT,
                scan_type       TEXT,
                target_url      TEXT,
                result_summary  TEXT,
                findings_count  INTEGER DEFAULT 0,
                started_at      TEXT    DEFAULT (datetime('now')),
                completed_at    TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_owasp    ON findings(owasp_category);
            CREATE INDEX IF NOT EXISTS idx_assets_target     ON assets(target_id);
        """)


# ─────────────────────────────────────────────
# TARGET OPERATIONS
# ─────────────────────────────────────────────

def add_target(
    program_name: str,
    domain: str,
    scope: Any,
    out_of_scope: Any = None,
    platform: str = None,
    bounty_range: str = None,
    notes: str = None,
) -> int:
    """Insert a new bug bounty target. Returns the new target ID."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO targets (program_name, domain, scope, out_of_scope, platform, bounty_range, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_name,
                domain,
                json.dumps(scope) if isinstance(scope, (list, dict)) else scope,
                json.dumps(out_of_scope) if isinstance(out_of_scope, (list, dict)) else out_of_scope,
                platform,
                bounty_range,
                notes,
            ),
        )
        return cursor.lastrowid


def get_targets() -> List[Dict]:
    """Return all targets."""
    with db_connection() as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_target(target_id: int) -> Optional[Dict]:
    """Return a single target by ID."""
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return dict(row) if row else None


def delete_target(target_id: int) -> bool:
    """Delete a target and all associated findings/assets."""
    with db_connection() as conn:
        affected = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,)).rowcount
        return affected > 0


def is_in_scope(target_id: int, url: str) -> bool:
    """Check if a URL is within the target's declared scope using proper domain matching."""
    target = get_target(target_id)
    if not target:
        return False
    scope_raw = target.get("scope", "[]")
    try:
        scope_list = json.loads(scope_raw) if scope_raw else []
    except (json.JSONDecodeError, TypeError):
        scope_list = [scope_raw] if scope_raw else []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        # Fallback: treat url as hostname if no scheme present
        hostname = url.lower().split("/")[0].split(":")[0]

    for s in scope_list:
        s_lower = s.lower().strip()
        if s_lower.startswith("*."):
            base = s_lower[2:]
            # Match exact base domain or any subdomain
            if hostname == base or hostname.endswith("." + base):
                return True
        else:
            # Exact match only
            if hostname == s_lower:
                return True
    # Also check base domain from target record
    base_domain = target.get("domain", "").lower().strip()
    if base_domain and (hostname == base_domain or hostname.endswith("." + base_domain)):
        return True
    return False


# ─────────────────────────────────────────────
# FINDING OPERATIONS
# ─────────────────────────────────────────────

def save_finding(
    target_id: int,
    title: str,
    vulnerability_type: str,
    owasp_category: str,
    severity: str,
    url: str = None,
    parameter: str = None,
    payload: str = None,
    description: str = None,
    steps_to_reproduce: str = None,
    impact: str = None,
    remediation: str = None,
    cvss_score: float = None,
    cvss_vector: str = None,
    evidence: str = None,
) -> int:
    """Save a vulnerability finding. Returns the new finding ID."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO findings (
                target_id, title, vulnerability_type, owasp_category, severity,
                cvss_score, cvss_vector, url, parameter, payload,
                description, steps_to_reproduce, impact, remediation, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_id, title, vulnerability_type, owasp_category, severity,
                cvss_score, cvss_vector, url, parameter, payload,
                description, steps_to_reproduce, impact, remediation, evidence,
            ),
        )
        return cursor.lastrowid


def get_findings(
    target_id: int = None,
    severity: str = None,
    status: str = None,
    owasp_category: str = None,
) -> List[Dict]:
    """Query findings with optional filters."""
    with db_connection() as conn:
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if owasp_category:
            query += " AND owasp_category = ?"
            params.append(owasp_category)
        query += " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 WHEN 'Informational' THEN 5 ELSE 6 END, created_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_finding(finding_id: int) -> Optional[Dict]:
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else None


_VALID_STATUSES = frozenset({'new', 'reported', 'accepted', 'rejected', 'duplicate', 'fixed'})

def update_finding_status(finding_id: int, status: str) -> bool:
    """Update the status of a finding."""
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(sorted(_VALID_STATUSES))}")
    with db_connection() as conn:
        affected = conn.execute(
            "UPDATE findings SET status = ?, updated_at = datetime('now') WHERE id = ?",
            (status, finding_id),
        ).rowcount
        return affected > 0


def get_finding_stats(target_id: int = None) -> Dict:
    """Get finding statistics grouped by severity."""
    with db_connection() as conn:
        query = "SELECT severity, COUNT(*) as count FROM findings WHERE 1=1"
        params = []
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " GROUP BY severity"
        rows = conn.execute(query, params).fetchall()
        stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "total": 0}
        for row in rows:
            sev = row["severity"]
            cnt = row["count"]
            if sev in stats:
                stats[sev] = cnt
            stats["total"] += cnt
        return stats


# ─────────────────────────────────────────────
# ASSET OPERATIONS
# ─────────────────────────────────────────────

def save_asset(
    target_id: int,
    asset_type: str,
    value: str,
    status_code: int = None,
    technologies: Any = None,
    open_ports: Any = None,
    title: str = None,
    notes: str = None,
) -> int:
    """Save a discovered asset. Returns the new asset ID."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO assets (target_id, asset_type, value, status_code, technologies, open_ports, title, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_id, asset_type, value, status_code,
                json.dumps(technologies) if isinstance(technologies, (list, dict)) else technologies,
                json.dumps(open_ports) if isinstance(open_ports, (list, dict)) else open_ports,
                title, notes,
            ),
        )
        return cursor.lastrowid


def get_assets(target_id: int, asset_type: str = None) -> List[Dict]:
    with db_connection() as conn:
        query = "SELECT * FROM assets WHERE target_id = ?"
        params = [target_id]
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        query += " ORDER BY discovered_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# SCAN LOG OPERATIONS
# ─────────────────────────────────────────────

def log_scan(
    tool_name: str,
    scan_type: str,
    target_url: str,
    result_summary: str,
    target_id: int = None,
    findings_count: int = 0,
) -> int:
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_logs (target_id, tool_name, scan_type, target_url, result_summary, findings_count, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (target_id, tool_name, scan_type, target_url, result_summary, findings_count),
        )
        return cursor.lastrowid


# Initialize the database when this module is first imported
init_db()
