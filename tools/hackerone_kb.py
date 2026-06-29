"""
AGY Bug Bounty MCP - HackerOne Hacktivity Knowledge Base
Official HackerOne API v1 integration for fetching disclosed reports (Hacktivity).
"""
import os
import time
import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from contextlib import contextmanager

import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

from .db import get_connection, db_connection

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import mcp for tool registration
from mcp_instance import mcp

# HackerOne API Configuration
HACKERONE_API_BASE = "https://api.hackerone.com/v1"
HACKTIVITY_ENDPOINT = f"{HACKERONE_API_BASE}/hackers/hacktivity"

# Get credentials from environment
HACKERONE_USERNAME = os.getenv("HACKERONE_API_USERNAME")
HACKERONE_TOKEN = os.getenv("HACKERONE_API_TOKEN")
if not HACKERONE_USERNAME or not HACKERONE_TOKEN:
    logger.warning("HackerOne API credentials not found in .env")


@dataclass
class HackerOneReport:
    """Data class for HackerOne report from Hacktivity."""
    report_id: str
    title: str
    url: str
    program: str
    severity_rating: Optional[str]
    cwe: Optional[str]
    cve_ids: Optional[str]
    total_awarded_amount: Optional[float]
    disclosed_at: Optional[str]
    votes: int
    hacktivity_summary: Optional[str]


def _fetch_hacktivity_page(
    query_string: Optional[str] = None,
    page_number: int = 1,
    page_size: int = 25
) -> Dict[str, Any]:
    """
    Fetch a single page of Hacktivity results from HackerOne API.
    
    Args:
        query_string: Lucene query string for filtering (e.g., "severity_rating:critical AND disclosed_at:>=2026-01-01")
        page_number: Page number (1-indexed)
        page_size: Number of results per page (max 100)
    
    Returns:
        Parsed JSON response from API
    """
    if not HACKERONE_USERNAME or not HACKERONE_TOKEN:
        raise ValueError("HackerOne API credentials not configured in .env")
    
    params = {
        "page[number]": page_number,
        "page[size]": min(page_size, 100),
    }
    if query_string:
        params["queryString"] = query_string
    
    headers = {
        "Accept": "application/json",
        "User-Agent": "AGY-BugBounty-MCP/1.0"
    }
    
    auth = HTTPBasicAuth(HACKERONE_USERNAME, HACKERONE_TOKEN)
    
    response = requests.get(
        HACKTIVITY_ENDPOINT,
        params=params,
        headers=headers,
        auth=auth,
        timeout=30
    )
    
    if response.status_code == 429:
        # Rate limited - wait and retry
        retry_after = int(response.headers.get("Retry-After", "60"))
        logger.warning(f"Rate limited, waiting {retry_after} seconds")
        time.sleep(retry_after)
        response = requests.get(
            HACKTIVITY_ENDPOINT,
            params=params,
            headers=headers,
            auth=auth,
            timeout=30
        )
    
    response.raise_for_status()
    return response.json()


def _parse_hacktivity_item(item: Dict[str, Any]) -> Optional[HackerOneReport]:
    """Parse a single Hacktivity item from API response into HackerOneReport."""
    try:
        attributes = item.get("attributes", {})
        relationships = item.get("relationships", {})
        
        # Only process disclosed reports
        if not attributes.get("disclosed"):
            return None
        
        # Extract report ID (API returns integer ID)
        report_id = str(item.get("id", ""))
        if not report_id:
            return None
        
        # Get program name from relationships
        program = ""
        if "program" in relationships:
            program_data = relationships["program"].get("data", {})
            if program_data:
                program = program_data.get("attributes", {}).get("name", "")
        
        # Get CWE - direct field in attributes
        cwe = attributes.get("cwe")
        
        # Get CVE IDs
        cve_ids = None
        cve_list = attributes.get("cve_ids", [])
        if cve_list and isinstance(cve_list, list):
            cve_ids = ", ".join(cve_list)
        
        # Get hacktivity summary from report_generated_content
        hacktivity_summary = None
        rgc = attributes.get("report_generated_content", {})
        if rgc and isinstance(rgc, dict):
            hacktivity_summary = rgc.get("hacktivity_summary")
        
        # Parse disclosed_at
        disclosed_at = attributes.get("disclosed_at")
        
        # Get total awarded amount
        total_awarded = attributes.get("total_awarded_amount")
        if total_awarded is not None:
            try:
                total_awarded = float(total_awarded)
            except (ValueError, TypeError):
                total_awarded = None
        
        # Get votes - field might be 'votes' or 'vote_count'
        votes = attributes.get("votes", attributes.get("vote_count", 0))
        
        return HackerOneReport(
            report_id=report_id,
            title=attributes.get("title", ""),
            url=attributes.get("url", ""),
            program=program,
            severity_rating=attributes.get("severity_rating"),
            cwe=cwe,
            cve_ids=cve_ids,
            total_awarded_amount=total_awarded,
            disclosed_at=disclosed_at,
            votes=votes,
            hacktivity_summary=hacktivity_summary
        )
    except Exception as e:
        logger.error(f"Error parsing Hacktivity item: {e}")
        return None


def _fetch_hacktivity(
    query_string: Optional[str] = None,
    max_pages: int = 5
) -> List[HackerOneReport]:
    """
    Fetch Hacktivity reports with pagination.
    
    Args:
        query_string: Lucene query string for filtering
        max_pages: Maximum number of pages to fetch
    
    Returns:
        List of HackerOneReport objects
    """
    all_reports = []
    
    for page in range(1, max_pages + 1):
        logger.info(f"Fetching Hacktivity page {page}...")
        
        try:
            data = _fetch_hacktivity_page(query_string, page)
        except requests.exceptions.HTTPError as e:
            status_code = getattr(e.response, 'status_code', None) if e.response is not None else None
            if status_code == 401:
                logger.error("Authentication failed - check HACKERONE_API_USERNAME and HACKERONE_API_TOKEN")
            elif status_code == 403:
                logger.error("Access forbidden - API token may not have hacktivity read permission")
            raise
        
        items = data.get("data", [])
        if not items:
            logger.info(f"No more items on page {page}, stopping")
            break
        
        for item in items:
            report = _parse_hacktivity_item(item)
            if report:
                all_reports.append(report)
        
        # Check if there's a next page
        links = data.get("links", {})
        if not links.get("next"):
            logger.info("No next page, stopping")
            break
        
        # Be nice to the API - 1 second delay between requests
        if page < max_pages:
            time.sleep(1)
    
    logger.info(f"Fetched {len(all_reports)} reports from Hacktivity")
    return all_reports


def _init_hackerone_tables() -> None:
    """Initialize the hackerone_reports table and FTS5 index."""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Main reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hackerone_reports (
                report_id       TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                url             TEXT,
                program         TEXT,
                severity_rating TEXT,
                cwe             TEXT,
                cve_ids         TEXT,
                total_awarded_amount REAL,
                disclosed_at    TEXT,
                votes           INTEGER DEFAULT 0,
                hacktivity_summary TEXT,
                raw_json        TEXT,
                synced_at       TEXT DEFAULT (datetime('now')),
                updated_at      TEXT DEFAULT (datetime('now'))
            );
        """)
        
        # FTS5 virtual table for full-text search
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS hackerone_reports_fts USING fts5(
                title,
                hacktivity_summary,
                cwe,
                content='hackerone_reports',
                content_rowid='rowid'
            );
        """)
        
        # Triggers to keep FTS5 in sync
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS hackerone_reports_fts_insert
            AFTER INSERT ON hackerone_reports
            BEGIN
                INSERT INTO hackerone_reports_fts(rowid, title, hacktivity_summary, cwe)
                VALUES (new.rowid, new.title, new.hacktivity_summary, new.cwe);
            END;
        """)
        
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS hackerone_reports_fts_delete
            AFTER DELETE ON hackerone_reports
            BEGIN
                INSERT INTO hackerone_reports_fts(hackerone_reports_fts, rowid, title, hacktivity_summary, cwe)
                VALUES ('delete', old.rowid, old.title, old.hacktivity_summary, old.cwe);
            END;
        """)
        
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS hackerone_reports_fts_update
            AFTER UPDATE ON hackerone_reports
            BEGIN
                INSERT INTO hackerone_reports_fts(hackerone_reports_fts, rowid, title, hacktivity_summary, cwe)
                VALUES ('delete', old.rowid, old.title, old.hacktivity_summary, old.cwe);
                INSERT INTO hackerone_reports_fts(rowid, title, hacktivity_summary, cwe)
                VALUES (new.rowid, new.title, new.hacktivity_summary, new.cwe);
            END;
        """)
        
        # Sync metadata table for watermark tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key   TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT DEFAULT (datetime('now'))
            );
        """)
        
        # Indexes for common queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_hackerone_severity ON hackerone_reports(severity_rating);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_hackerone_cwe ON hackerone_reports(cwe);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_hackerone_disclosed ON hackerone_reports(disclosed_at);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_hackerone_program ON hackerone_reports(program);
        """)
        
        conn.commit()
        logger.info("HackerOne tables and FTS5 initialized")


def _upsert_report(report: HackerOneReport) -> bool:
    """Upsert a single report into the database. Returns True if inserted/updated."""
    with db_connection() as conn:
        cursor = conn.cursor()
        
        raw_json = json.dumps(asdict(report), ensure_ascii=False)
        
        cursor.execute("""
            INSERT INTO hackerone_reports (
                report_id, title, url, program, severity_rating, cwe, cve_ids,
                total_awarded_amount, disclosed_at, votes, hacktivity_summary, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(report_id) DO UPDATE SET
                title = excluded.title,
                url = excluded.url,
                program = excluded.program,
                severity_rating = excluded.severity_rating,
                cwe = excluded.cwe,
                cve_ids = excluded.cve_ids,
                total_awarded_amount = excluded.total_awarded_amount,
                disclosed_at = excluded.disclosed_at,
                votes = excluded.votes,
                hacktivity_summary = excluded.hacktivity_summary,
                raw_json = excluded.raw_json,
                updated_at = datetime('now')
        """, (
            report.report_id,
            report.title,
            report.url,
            report.program,
            report.severity_rating,
            report.cwe,
            report.cve_ids,
            report.total_awarded_amount,
            report.disclosed_at,
            report.votes,
            report.hacktivity_summary,
            raw_json
        ))
        
        return cursor.rowcount > 0


def _update_sync_watermark(last_disclosed_at: str) -> None:
    """Update the sync watermark with the latest disclosed_at timestamp."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sync_metadata (key, value)
            VALUES ('hackerone_last_sync', ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value
        """, (last_disclosed_at,))
        conn.commit()


def _get_sync_watermark() -> Optional[str]:
    """Get the last sync watermark."""
    with db_connection() as conn:
        cursor = conn.cursor()
        row = cursor.execute(
            "SELECT value FROM sync_metadata WHERE key = 'hackerone_last_sync'"
        ).fetchone()
        return row["value"] if row else None


@mcp.tool()
def sync_hacktivity(query_string: Optional[str] = None, max_pages: int = 5) -> Dict[str, Any]:
    """
    Sync HackerOne Hacktivity reports to local database (incremental).
    
    Args:
        query_string: Lucene query string for filtering (e.g., "severity_rating:critical AND disclosed_at:>=2026-01-01")
        max_pages: Maximum number of pages to fetch (default 5, 25 per page = 125 reports)
    
    Returns:
        Dict with sync statistics
    """
    _init_hackerone_tables()
    
    # Build query with watermark if not provided
    if query_string is None:
        watermark = _get_sync_watermark()
        if watermark:
            query_string = f"disclosed_at:>={watermark}"
            logger.info(f"Using watermark query: {query_string}")
    
    reports = _fetch_hacktivity(query_string, max_pages)
    
    inserted = 0
    updated = 0
    latest_disclosed = None
    
    for report in reports:
        # Track the most recent disclosed_at
        if report.disclosed_at:
            if latest_disclosed is None or report.disclosed_at > latest_disclosed:
                latest_disclosed = report.disclosed_at
        
        with db_connection() as conn:
            cursor = conn.cursor()
            # Check if exists
            existing = cursor.execute(
                "SELECT 1 FROM hackerone_reports WHERE report_id = ?", 
                (report.report_id,)
            ).fetchone()
            
            _upsert_report(report)
            
            if existing:
                updated += 1
            else:
                inserted += 1
    
    # Update watermark
    if latest_disclosed:
        _update_sync_watermark(latest_disclosed)
    
    result = {
        "success": True,
        "fetched": len(reports),
        "inserted": inserted,
        "updated": updated,
        "watermark": latest_disclosed,
        "query_used": query_string
    }
    
    logger.info(f"Sync complete: {result}")
    return result


@mcp.tool()
def search_hackerone_reports(
    query: str,
    severity: Optional[str] = None,
    cwe: Optional[str] = None,
    min_bounty: Optional[float] = None,
    limit: int = 10
) -> Dict[str, Any]:
    """
    Search HackerOne reports using FTS5 full-text search with optional filters.
    
    Args:
        query: FTS5 search query (searches title, hacktivity_summary, cwe)
        severity: Filter by severity_rating (critical, high, medium, low, info)
        cwe: Filter by CWE ID (e.g., "CWE-79")
        min_bounty: Minimum total awarded amount
        limit: Maximum results to return
    
    Returns:
        Dict with query info and results list
    """
    _init_hackerone_tables()
    
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Build query
        sql = """
            SELECT h.report_id, h.title, h.url, h.program, h.severity_rating,
                   h.cwe, h.cve_ids, h.total_awarded_amount, h.disclosed_at,
                   h.votes, h.hacktivity_summary,
                   snippet(hackerone_reports_fts, -1, '[', ']', '...', 32) as snippet
            FROM hackerone_reports h
            JOIN hackerone_reports_fts f ON h.rowid = f.rowid
            WHERE hackerone_reports_fts MATCH ?
        """
        params = [query]
        
        if severity:
            sql += " AND h.severity_rating = ?"
            params.append(severity.lower())
        
        if cwe:
            sql += " AND h.cwe LIKE ?"
            params.append(f"%{cwe}%")
        
        if min_bounty is not None:
            sql += " AND h.total_awarded_amount >= ?"
            params.append(str(min_bounty))
        
        sql += " ORDER BY h.disclosed_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        
        results = [dict(row) for row in rows]
        
        return {
            "query": query,
            "filters": {
                "severity": severity,
                "cwe": cwe,
                "min_bounty": min_bounty
            },
            "count": len(results),
            "results": results
        }


@mcp.tool()
def get_hackerone_report(report_id: str) -> Dict[str, Any]:
    """
    Get full details of a single HackerOne report by ID.
    
    Args:
        report_id: HackerOne report ID (numeric string)
    
    Returns:
        Dict with full report details or error if not found
    """
    _init_hackerone_tables()
    
    with db_connection() as conn:
        cursor = conn.cursor()
        row = cursor.execute(
            "SELECT * FROM hackerone_reports WHERE report_id = ?", 
            (report_id,)
        ).fetchone()
        
        if not row:
            return {"found": False, "report_id": report_id, "error": "Report not found in local database"}
        
        report = dict(row)
        # Parse raw_json if present
        if report.get("raw_json"):
            try:
                report["raw_data"] = json.loads(report["raw_json"])
            except json.JSONDecodeError:
                report["raw_data"] = None
        
        return {"found": True, **report}


@mcp.tool()
def stats_hackerone_reports() -> Dict[str, Any]:
    """
    Get statistics about synced HackerOne reports.
    
    Returns:
        Dict with various statistics
    """
    _init_hackerone_tables()
    
    with db_connection() as conn:
        cursor = conn.cursor()
        
        # Total count
        total = cursor.execute("SELECT COUNT(*) FROM hackerone_reports").fetchone()[0]
        
        # By severity
        severity_stats = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = cursor.execute(
                "SELECT COUNT(*) FROM hackerone_reports WHERE lower(severity_rating) = ?",
                (sev,)
            ).fetchone()[0]
            severity_stats[sev] = count
        
        # By program (top 10)
        programs = cursor.execute("""
            SELECT program, COUNT(*) as count 
            FROM hackerone_reports 
            WHERE program IS NOT NULL AND program != ''
            GROUP BY program 
            ORDER BY count DESC 
            LIMIT 10
        """).fetchall()
        
        # Top CWEs
        cwes = cursor.execute("""
            SELECT cwe, COUNT(*) as count 
            FROM hackerone_reports 
            WHERE cwe IS NOT NULL AND cwe != ''
            GROUP BY cwe 
            ORDER BY count DESC 
            LIMIT 10
        """).fetchall()
        
        # Date range
        date_range = cursor.execute("""
            SELECT MIN(disclosed_at), MAX(disclosed_at) 
            FROM hackerone_reports 
            WHERE disclosed_at IS NOT NULL
        """).fetchone()
        
        # Watermark
        watermark = _get_sync_watermark()
        
        return {
            "total_reports": total,
            "by_severity": severity_stats,
            "top_programs": [dict(p) for p in programs],
            "top_cwes": [dict(c) for c in cwes],
            "date_range": {
                "earliest": date_range[0] if date_range else None,
                "latest": date_range[1] if date_range else None
            },
            "last_sync_watermark": watermark
        }


# Convenience function for manual testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # Test API connection
        print("Testing HackerOne API connection...")
        try:
            result = sync_hacktivity(query_string="severity_rating:critical AND disclosed_at:>=2026-01-01", max_pages=1)
            print(f"Sync result: {result}")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        print("Usage: python -m tools.hackerone_kb test")