"""
AGY Bug Bounty MCP - Database Layer
Handles all SQLite operations for targets, findings, assets, and scan logs.
"""
import sqlite3
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
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
    """Check if a URL is within the target's declared scope using proper domain matching.
    
    For security, this ONLY checks the explicit scope list - it does NOT fall back
    to the base domain. This prevents accidental out-of-scope testing.
    
    Args:
        target_id: The target ID from database
        url: The URL to validate
    
    Returns:
        True if URL is within scope, False otherwise
    """
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
    # REMOVED: No longer fall back to base domain - requires explicit scope entry
    # This is a security hardening to prevent accidental out-of-scope testing
    return False


def validate_scope_or_fail(target_id: int, url: str) -> None:
    """Validate that a URL is within the target's declared scope.
    
    Raises:
        ValueError: If target_id is invalid or URL is out of scope
    """
    target = get_target(target_id)
    if not target:
        raise ValueError(f"INVALID_TARGET: Target ID {target_id} does not exist in database. "
                        f"Use add_target() to create a target first.")
    
    if not is_in_scope(target_id, url):
        program_name = target.get("program_name", "Unknown")
        domain = target.get("domain", "Unknown")
        raise ValueError(
            f"OUT_OF_SCOPE: URL '{url}' is NOT authorized for target '{program_name}' ({domain}). "
            f"Target scope: {target.get('scope', '[]')}. "
            f"Use add_target() to add or update target scope. "
            f"ALWAYS verify scope before running security tests."
        )


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


# ─────────────────────────────────────────────
# LOLBINS SCHEMA MIGRATION (idempotent)
# ─────────────────────────────────────────────

def init_lolbins_schema() -> None:
    """Initialize GTFOBins/LOLBAS tables for Living-off-the-Land Binaries knowledge base."""
    with db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS gtfobins_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_name TEXT NOT NULL,
                function_type TEXT NOT NULL,
                code TEXT NOT NULL,
                description TEXT,
                mitre_technique_id TEXT,
                source_url TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                UNIQUE(binary_name, function_type, code)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lolbas_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_name TEXT NOT NULL,
                full_path TEXT,
                command TEXT NOT NULL,
                command_description TEXT,
                usecase TEXT,
                category TEXT,
                privileges_required TEXT,
                mitre_attack_id TEXT,
                operating_system TEXT,
                source_url TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                UNIQUE(binary_name, command)
            )
        """)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS lolbins_search USING fts5(
                binary_name,
                platform,
                category,
                payload,
                description,
                source_table UNINDEXED,
                source_id UNINDEXED
            )
        """)


# Run LOLBins schema init
init_lolbins_schema()


# ─────────────────────────────────────────────
# RFC SCHEMA MIGRATION (idempotent)
# ─────────────────────────────────────────────

def init_rfc_schema() -> None:
    """Initialize RFC tables and add topic_tag column if missing."""
    with db_connection() as conn:
        # Create rfc_documents table if not exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rfc_documents (
                rfc_number INTEGER PRIMARY KEY,
                title TEXT,
                status TEXT,
                fetched_at TEXT,
                full_text TEXT,
                topic_tag TEXT
            )
        """)
        # Create rfc_sections FTS5 table if not exists
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS rfc_sections USING fts5(
                rfc_number UNINDEXED,
                section_number,
                section_title,
                content,
                tokenize='porter unicode61'
            )
        """)


# Run RFC schema init
init_rfc_schema()


# ─────────────────────────────────────────────
# ATT&CK/CAPEC SCHEMA MIGRATION (idempotent)
# ─────────────────────────────────────────────

def init_attck_capec_schema() -> None:
    """Initialize MITRE ATT&CK and CAPEC tables for the knowledge base."""
    with db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attck_tactics (
                tactic_id    TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                description  TEXT,
                url          TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attck_techniques (
                technique_id     TEXT PRIMARY KEY,
                name             TEXT NOT NULL,
                description      TEXT,
                detection        TEXT,
                platforms        TEXT,
                tactic_ids       TEXT,
                is_subtechnique  INTEGER DEFAULT 0,
                parent_id        TEXT,
                url              TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS capec_entries (
                capec_id                TEXT PRIMARY KEY,
                name                    TEXT NOT NULL,
                description             TEXT,
                extended_description    TEXT,
                likelihood_of_attack    TEXT,
                typical_severity        TEXT,
                prerequisites           TEXT,
                mitigations             TEXT,
                related_technique_ids   TEXT,
                status                  TEXT
            )
        """)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS attck_fts USING fts5(
                technique_id, name, description, detection,
                content='attck_techniques', content_rowid='rowid'
            )
        """)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS capec_fts USING fts5(
                capec_id, name, description,
                content='capec_entries', content_rowid='rowid'
            )
        """)


# Run ATT&CK/CAPEC schema init
init_attck_capec_schema()


# ─────────────────────────────────────────────
# OWASP API SECURITY SCHEMA MIGRATION (idempotent)
# ─────────────────────────────────────────────

def init_owasp_api_schema() -> None:
    """Initialize OWASP API Security Top 10 tables."""
    with db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS owasp_api_top10 (
                api_id                   TEXT PRIMARY KEY,
                name                     TEXT NOT NULL,
                description              TEXT,
                risk_factors            TEXT,
                related_attck_techniques TEXT
            )
        """)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS owasp_api_fts USING fts5(
                api_id, name, description
            )
        """)


# Run OWASP API schema init
init_owasp_api_schema()


# ─────────────────────────────────────────────
# RFC INDEXING FUNCTION (can be called from scripts)
# ─────────────────────────────────────────────

def add_rfc_to_db(rfc_number: int, topic_tag: str = None) -> dict:
    """Add an RFC to the database. Reusable from scripts or MCP tools.
    Does not import MCP - safe for standalone scripts.
    """
    import logging
    logger = logging.getLogger("agy.rfc")

    with db_connection() as conn:
        # Check if already exists
        existing = conn.execute(
            "SELECT rfc_number FROM rfc_documents WHERE rfc_number = ?",
            (rfc_number,),
        ).fetchone()
        if existing:
            return {"error": f"RFC {rfc_number} already indexed", "success": False}

        # Fetch RFC text using shared function
        raw_text = fetch_rfc_text(rfc_number)
        if raw_text.startswith("[ERROR]"):
            return {"error": raw_text[8:], "success": False}

        # Clean pagination using shared function
        cleaned_text = clean_rfc_pagination(raw_text, rfc_number)
        status = extract_rfc_status(cleaned_text)

        # Extract title using shared function
        title = extract_rfc_title(cleaned_text, rfc_number)

        # Insert into rfc_documents (with topic_tag)
        conn.execute(
            "INSERT INTO rfc_documents (rfc_number, title, status, fetched_at, full_text, topic_tag) VALUES (?, ?, ?, ?, ?, ?)",
            (rfc_number, title, status, datetime.now(timezone.utc).isoformat(), cleaned_text, topic_tag)
        )

        # Parse and insert sections using shared function
        sections = parse_rfc_sections(cleaned_text)
        for section_num, section_title, content in sections:
            conn.execute(
                "INSERT INTO rfc_sections (rfc_number, section_number, section_title, content) VALUES (?, ?, ?, ?)",
                (rfc_number, section_num, section_title, content)
            )

    return {
        "success": True,
        "rfc_number": rfc_number,
        "title": title,
        "sections_indexed": len(sections),
    }


# ─────────────────────────────────────────────
# RFC PARSING FUNCTIONS (shared by build_rfc_index.py and rfc_kb.py)
# ─────────────────────────────────────────────

def fetch_rfc_text(rfc_number: int) -> str:
    """Fetch raw RFC text from rfc-editor.org. Returns the full text unchanged."""
    import urllib.request
    url = f"https://www.rfc-editor.org/rfc/rfc{rfc_number}.txt"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AGY-BugBounty-MCP/1.0 (bug bounty research)"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR] {e}"


def extract_rfc_title(text: str, rfc_number: int) -> str:
    """Extract the RFC title from header. Works with both old and new RFC formats.
    Handles multi-line wrapped titles (center-aligned)."""
    lines = text.splitlines()
    skip_keywords = ("Obsoletes:", "Updates:", "Category:", "INTERNET", "RFC", "Copyright", "Status", "Table of", "Network Working Group")
    skip_affiliations = ("@", "Labs", "Inc.", "University", "BV", "B.V", "Equinix", "Independent", "Fastly", "Instituut", "ISC", "Tech", "NIC", "ICANN", "Provisions", "Institute", "Center", "College", "Corporation", "Systems", "Company", "Microsoft", "Salesforce", "Ping Identity", "Cisco", "Google", "Amazon", "Facebook", "Mozilla", "Akamai", "Cloudflare", "Verisign", "Ericsson", "Nokia", "Huawei", "Apple", "IBM", "Oracle", "Red Hat", "Intel", "ARM", "Qualcomm", "Broadcom", "Texas Instruments", "Analog Devices", "NXP", "STMicroelectronics", "Renesas", "Infineon", "Cypress", "Microchip", "Silicon Labs", "Dialog", "ON Semiconductor", "Maxim", "Linear", "Intersil", "Fairchild", "Vishay", "ROHM", "Toshiba", "Panasonic", "Sony", "Samsung", "LG", "HTC", "Motorola", "Lenovo", "Dell", "HP", "HPE", "Fujitsu", "NEC", "Hitachi", "Mitsubishi", "Fujifilm", "Canon", "Ricoh", "Xerox", "Lexmark", "Brother", "Epson", "Seiko", "Citizen", "Star", "Bixolon", "Zebra", "SATO", "TSC", "Godex", "Argox", "Postek", "Gainscha", "Syble", "Xprinter", "Munbyn", "Phomemo", "Nelko", "Rolllo", "Munbyn", "Phomemo", "Nelko", "Rolllo")
    stop_keywords = ("Abstract", "Status of This Memo", "Table of Contents", "Copyright Notice", "Internet-Draft", "Acknowledgments", "Authors' Addresses")
    
    # Find the first indented title line (after header metadata)
    title_lines = []
    title_started = False
    in_header = True  # Track if we're still in the RFC header block
    
    for line in lines[:60]:  # Search in first 60 lines
        stripped = line.strip()
        
        # Skip empty lines - but track header exit
        if not stripped:
            if title_started:
                # Blank line after title = end of title
                break
            if in_header:
                # Multiple blank lines in header - might be transitioning to title area
                continue
            continue
        
        # Check if this line is a stop keyword (Abstract, etc.)
        if any(stripped.startswith(k) for k in stop_keywords):
            if title_started:
                break
            continue
        
        # Detect header metadata lines (they have specific patterns)
        is_header_metadata = (
            stripped.startswith("Internet Engineering Task Force") or
            stripped.startswith("Request for Comments:") or
            stripped.startswith("Category:") or
            stripped.startswith("ISSN:") or
            stripped.startswith("Obsoletes:") or
            stripped.startswith("Updates:") or
            any(stripped.startswith(k) for k in skip_keywords)
        )
        
        if is_header_metadata:
            in_header = True
            continue
        
        # Must be indented (has leading whitespace) - title lines are center-aligned with spaces
        if len(line) == len(stripped):  # no leading whitespace
            if title_started:
                break
            continue
        
        # Skip affiliation lines (they appear in header, typically after metadata)
        # Affiliation lines are usually short and contain known org names
        if any(a in stripped for a in skip_affiliations):
            if title_started:
                break
            in_header = True
            continue
        
        # Skip lines starting with digits (section numbers, dates)
        if stripped[0].isdigit():
            if title_started:
                break
            continue
        
        # Skip date/month lines
        month_words = ["January", "February", "March", "April", "May", "June",
                       "July", "August", "September", "October", "November", "December"]
        if any(m in stripped for m in month_words) and len(stripped.split()) <= 3:
            if title_started:
                break
            continue
        
        # Skip boilerplate Status text fragments
        if stripped.startswith("This document "):
            if title_started:
                break
            continue
        if "internet community" in stripped.lower():
            if title_started:
                break
            continue
        
        # Check if this looks like a continuation of header (author names like "M. Jones")
        # These are typically short lines with initials and surname
        if len(stripped.split()) <= 3 and all(part[0].isupper() for part in stripped.split() if part):
            # Could be author names - if we haven't started title yet, skip
            if not title_started and in_header:
                continue
        
        # This looks like a title line
        title_started = True
        in_header = False
        title_lines.append(stripped)
    
    if title_lines:
        return " ".join(title_lines)
    
    return f"RFC {rfc_number}"


def extract_rfc_status(text: str) -> str:
    """Extract obsoletes/obsoleted-by info from RFC header if present."""
    status_parts = []
    for line in text.splitlines()[:50]:
        match = re.search(r"Obsoletes[:\s]+(.+)", line, re.IGNORECASE)
        if match:
            status_parts.append(f"obsoletes:{match.group(1).strip()}")
    return "; ".join(status_parts)


def clean_rfc_pagination(text: str, rfc_number: int) -> str:
    """Remove form-feed characters and page header/footer artifacts."""
    lines = text.splitlines()
    cleaned_lines = []
    
    # Build patterns for this specific RFC
    rfc_pattern = re.compile(r"^\s*RFC\s*" + str(rfc_number) + r"\s+.*$", re.IGNORECASE)
    page_pattern = re.compile(r"\[Page\s+\d+\]")
    
    for line in lines:
        # Remove form feed characters
        if "\f" in line:
            line = line.replace("\f", "")
        # Remove RFC header lines (standalone lines with RFC number and date)
        if rfc_pattern.match(line):
            continue
        # Remove [Page N] markers anywhere in the line (pagination artifact)
        line = page_pattern.sub("", line)
        cleaned_lines.append(line)
    
    return "\n".join(cleaned_lines)


def parse_rfc_sections(text: str) -> list:
    """Parse RFC sections into (section_number, section_title, content) tuples."""
    sections = []
    lines = text.splitlines()
    current_section = None
    current_title = ""
    current_content = []

    section_pattern = re.compile(r"^(\d+\.[\d.]*)\s{2,}(.+)$")

    for line in lines:
        match = section_pattern.match(line)
        if match:
            if current_section is not None:
                sections.append((current_section, current_title, "\n".join(current_content).strip()))
            current_section = match.group(1)
            current_title = match.group(2).strip()
            current_content = []
        elif current_section is not None:
            current_content.append(line)

    if current_section is not None:
        sections.append((current_section, current_title, "\n".join(current_content).strip()))

    return sections
