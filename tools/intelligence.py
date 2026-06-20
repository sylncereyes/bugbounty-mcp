"""
AGY Bug Bounty MCP - CVE & Exploit Intelligence Module
Integrates vulnx (ProjectDiscovery), searchsploit (ExploitDB), and
msfconsole (Metasploit Framework) for vulnerability enrichment and
exploit chain analysis.

Binary paths (absolute):
    vulnx        → /home/kali/go/bin/vulnx
    searchsploit → /home/kali/.local/bin/searchsploit
    msfconsole   → /home/kali/.local/bin/msfconsole
"""
import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional

from mcp_instance import mcp
from tools.db import db_connection, get_finding
from tools.validators import validate_required_string, validate_cve_id

logger = logging.getLogger("agy")

# ── Binary paths ──────────────────────────────────────────────────────────────
VULNX_BIN = "/home/kali/go/bin/vulnx"
SEARCHSPLOIT_BIN = "/home/kali/.local/bin/searchsploit"
MSFCONSOLE_BIN = "/home/kali/.local/bin/msfconsole"

# ── Subprocess timeout (seconds) ─────────────────────────────────────────────
_SUBPROCESS_TIMEOUT = 30


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═════════════════════════════════════════════════════════════════════════════

async def _run_subprocess(
    cmd: List[str],
    timeout: float = _SUBPROCESS_TIMEOUT,
) -> tuple[int, str, str]:
    """Run a command via asyncio subprocess. Returns (returncode, stdout, stderr).

    Never raises — returns returncode=-1 on timeout or OS errors.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return (
            proc.returncode or 0,
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()  # type: ignore[possibly-undefined]
        except Exception:
            pass
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"Binary not found: {e}"
    except Exception as e:
        return -1, "", f"Subprocess error: {e}"


def _parse_json_output(raw: str) -> Any:
    """Try to parse JSON from raw stdout that may contain ANSI or banner lines."""
    # Strip ANSI escape codes
    ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    cleaned = ansi_re.sub("", raw)

    # Try full string first
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Try to find JSON array or object boundaries
    for start_char, end_char in [("[", "]"), ("{", "}")]:
        start = cleaned.find(start_char)
        end = cleaned.rfind(end_char)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(cleaned[start : end + 1])
            except json.JSONDecodeError:
                continue

    # Try line-delimited JSON (vulnx outputs one JSON object per line)
    results = []
    for line in cleaned.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if results:
        return results

    return None


def _add_exploitability_labels(cve: dict) -> List[str]:
    """Build human-readable exploitability labels from vulnx boolean fields."""
    labels = []
    if cve.get("is_kev"):
        labels.append("Actively exploited in wild (CISA KEV)")
    if cve.get("is_poc"):
        labels.append("PoC available")
    if cve.get("is_template"):
        labels.append("Nuclei template ready")
    if cve.get("is_remote"):
        labels.append("Remotely exploitable")
    return labels


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 1 — vulnx_exploitable
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def vulnx_exploitable(
    technology: str,
    version: str = "",
    min_cvss: float = 7.0,
    remote_only: bool = True,
) -> dict:
    """Search ProjectDiscovery vulnx for exploitable CVEs with PoC or KEV status.

    Queries vulnx for CVEs matching a technology/product, filtered by
    minimum CVSS score and exploitability signals (PoC available, CISA KEV,
    remotely exploitable). Returns enriched results with human-readable
    exploitability labels for each CVE.
    """
    err = validate_required_string(technology, "technology")
    if err:
        return {"error": err}
    if version:
        err = validate_required_string(version, "version")
        if err:
            return {"error": err}

    # Build query: technology name + exploitability filter
    query_parts = [technology]
    if version:
        query_parts.append(version)

    query = " ".join(query_parts)

    cmd = [
        VULNX_BIN, "search",
        "--json",
        "--poc", "true",
        "--kev",
        "--cvss-score", f">={min_cvss}",
        "--limit", "20",
        query,
    ]

    if remote_only:
        cmd.insert(cmd.index("--json"), "--remote-exploit")

    # Build human-readable filter description
    filter_applied = f"poc:true, kev:true, cvss>={min_cvss}"
    if remote_only:
        filter_applied += ", remote_exploit:true"

    rc, stdout, stderr = await _run_subprocess(cmd)
    if rc != 0 and not stdout.strip():
        return {
            "technology": technology,
            "version": version,
            "filter_applied": filter_applied,
            "total": 0,
            "exploitable_cves": [],
            "error": stderr.strip() or f"vulnx exited with code {rc}",
        }

    parsed = _parse_json_output(stdout)
    if parsed is None:
        return {
            "technology": technology,
            "version": version,
            "filter_applied": filter_applied,
            "total": 0,
            "exploitable_cves": [],
            "error": "Failed to parse vulnx JSON output",
        }

    # Normalize to list
    cves = parsed if isinstance(parsed, list) else [parsed]

    # Enrich each CVE with exploitability labels
    for cve in cves:
        cve["exploitability_labels"] = _add_exploitability_labels(cve)

    return {
        "technology": technology,
        "version": version,
        "filter_applied": filter_applied,
        "total": len(cves),
        "exploitable_cves": cves,
    }


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 2 — searchsploit_query
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def searchsploit_query(
    query: str,
    cve_id: str = "",
    type_filter: str = "webapps",
) -> dict:
    """Search ExploitDB via searchsploit for public exploits matching a technology or CVE.

    Looks up known exploits by technology name + version string, or
    directly by CVE ID. Results include full filesystem paths to exploit
    source files under /usr/share/exploitdb/.
    """
    if cve_id:
        err = validate_cve_id(cve_id, "cve_id")
        if err:
            return {"error": err}
    else:
        err = validate_required_string(query, "query")
        if err:
            return {"error": err}

    if cve_id:
        cmd = [SEARCHSPLOIT_BIN, "--json", "--cve", cve_id]
    else:
        # Split query into individual search terms for searchsploit
        cmd = [SEARCHSPLOIT_BIN, "--json"] + query.split()

    rc, stdout, stderr = await _run_subprocess(cmd)

    # searchsploit returns exit code 2 on no results but still outputs JSON
    parsed = _parse_json_output(stdout)

    if parsed is None:
        return {
            "query": cve_id or query,
            "total": 0,
            "exploits": [],
            "suggestion": "try broader query",
            "error": stderr.strip() or "Failed to parse searchsploit output",
        }

    # searchsploit JSON structure: {"RESULTS_EXPLOIT": [...], "RESULTS_SHELLCODE": [...]}
    exploits_raw = []
    if isinstance(parsed, dict):
        exploits_raw = parsed.get("RESULTS_EXPLOIT", [])
    elif isinstance(parsed, list):
        exploits_raw = parsed

    # Filter by type if specified
    if type_filter and exploits_raw:
        exploits_raw = [
            e for e in exploits_raw
            if type_filter.lower() in (e.get("Type", "") or "").lower()
               or type_filter.lower() in (e.get("Path", "") or "").lower()
        ]

    # Enrich with full filesystem path
    exploits = []
    for e in exploits_raw:
        entry = {
            "Title": e.get("Title", ""),
            "Path": e.get("Path", ""),
            "full_path": f"/usr/share/exploitdb/{e.get('Path', '')}" if e.get("Path") else "",
            "Type": e.get("Type", ""),
            "Date": e.get("Date Published", e.get("Date", "")),
            "CVE": _extract_cve_from_exploit(e),
        }
        exploits.append(entry)

    if not exploits:
        return {
            "query": cve_id or query,
            "total": 0,
            "exploits": [],
            "suggestion": "try broader query",
        }

    return {
        "query": cve_id or query,
        "total": len(exploits),
        "exploits": exploits,
    }


def _extract_cve_from_exploit(exploit: dict) -> str:
    """Try to extract a CVE ID from exploit metadata or title."""
    # Some searchsploit entries have 'Codes' field with CVE references
    codes = exploit.get("Codes", "")
    if codes:
        match = re.search(r"(CVE-\d{4}-\d+)", str(codes), re.IGNORECASE)
        if match:
            return match.group(1).upper()
    # Fallback: search in title
    title = exploit.get("Title", "")
    match = re.search(r"(CVE-\d{4}-\d+)", title, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 3 — msf_module_search
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def msf_module_search(
    query: str,
    module_type: str = "exploit",
) -> dict:
    """Search Metasploit Framework for exploit/auxiliary/post modules matching a query.

    Runs msfconsole in non-interactive mode to search for modules, then
    filters results to only excellent and great ranked modules (reliable
    for bug bounty, avoids noisy/unstable exploits).
    """
    err = validate_required_string(query, "query")
    if err:
        return {"error": err}
    # module_type is a known-safe enum — still reject empty / shell metachars
    err = validate_required_string(module_type, "module_type", allow_shell_metachars=True)
    if err:
        return {"error": err}

    search_cmd = f"search type:{module_type} {query}; exit"
    cmd = [
        MSFCONSOLE_BIN,
        "-q",                # quiet mode (suppress banner)
        "-x", search_cmd,
        "--no-readline",
    ]

    rc, stdout, stderr = await _run_subprocess(cmd, timeout=60)

    if rc == -1:
        return {
            "query": query,
            "module_type": module_type,
            "total": 0,
            "modules": [],
            "error": stderr.strip(),
        }

    modules = _parse_msf_search_output(stdout)

    # Filter to excellent and great rank only (reliable for bug bounty)
    modules = [m for m in modules if m.get("rank", "").lower() in ("excellent", "great")]

    return {
        "query": query,
        "module_type": module_type,
        "total": len(modules),
        "modules": modules,
    }


def _parse_msf_search_output(raw: str) -> List[dict]:
    """Parse msfconsole 'search' output into structured module dicts.

    Expected line format (whitespace-separated columns):
      #  Name                         Disclosure Date  Rank       Check  Description
      0  exploit/linux/http/foo       2023-01-15       excellent  Yes    Some description
    """
    # Strip ANSI codes
    ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    cleaned = ansi_re.sub("", raw)

    modules = []
    # Match lines starting with a number (module index)
    line_re = re.compile(
        r"^\s*\d+\s+"                       # index number
        r"((?:exploit|auxiliary|post|payload|encoder|nop|evasion)/\S+)"  # module path
        r"\s+"
        r"(\d{4}-\d{2}-\d{2})?\s*"          # optional disclosure date
        r"(excellent|great|good|normal|average|low|manual)?\s*"  # rank
        r"(Yes|No)?\s*"                     # check support
        r"(.*)",                            # description
        re.IGNORECASE,
    )

    for line in cleaned.splitlines():
        m = line_re.match(line)
        if m:
            modules.append({
                "name": m.group(1).strip(),
                "disclosure_date": (m.group(2) or "").strip(),
                "rank": (m.group(3) or "").strip().lower(),
                "check": (m.group(4) or "").strip(),
                "description": (m.group(5) or "").strip(),
            })

    return modules


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 4 — exploit_chain
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def exploit_chain(
    technology: str,
    version: str = "",
    min_cvss: float = 7.0,
) -> dict:
    """Build a unified exploit intelligence chain by querying vulnx, searchsploit, and Metasploit in parallel.

    Cross-references CVEs from vulnx against public exploits in ExploitDB
    and Metasploit modules. Each CVE is tagged as 'attack_ready' if at
    least one actionable exploit (searchsploit or Metasploit excellent/great)
    is available. Returns a prioritised summary for bug bounty triage.
    """
    err = validate_required_string(technology, "technology")
    if err:
        return {"error": err}
    if version:
        err = validate_required_string(version, "version")
        if err:
            return {"error": err}

    search_term = f"{technology} {version}".strip()

    # Run all three tools in parallel
    vulnx_task = vulnx_exploitable(technology, version, min_cvss)
    searchsploit_task = searchsploit_query(search_term)
    msf_task = msf_module_search(technology)

    vulnx_result, searchsploit_result, msf_result = await asyncio.gather(
        vulnx_task, searchsploit_task, msf_task,
        return_exceptions=True,
    )

    # Handle exceptions from gather
    if isinstance(vulnx_result, Exception):
        vulnx_result = {"total": 0, "exploitable_cves": [], "error": str(vulnx_result)}
    if isinstance(searchsploit_result, Exception):
        searchsploit_result = {"total": 0, "exploits": [], "error": str(searchsploit_result)}
    if isinstance(msf_result, Exception):
        msf_result = {"total": 0, "modules": [], "error": str(msf_result)}

    # Index searchsploit exploits by CVE for fast lookup
    sploit_by_cve: Dict[str, List[dict]] = {}
    sploit_by_keyword: List[dict] = []
    for exp in searchsploit_result.get("exploits", []):
        cve = exp.get("CVE", "")
        if cve:
            sploit_by_cve.setdefault(cve.upper(), []).append(exp)
        sploit_by_keyword.append(exp)

    # Index msf modules by name keywords for matching
    msf_modules = msf_result.get("modules", [])

    # Build chains: enrich each vulnx CVE with cross-referenced exploit data
    chains = []
    attack_ready_count = 0

    for cve in vulnx_result.get("exploitable_cves", []):
        cve_id = (cve.get("cve_id") or cve.get("id") or "").upper()

        # Cross-reference with searchsploit by CVE ID
        matched_exploits = sploit_by_cve.get(cve_id, [])
        # Also try keyword match against title if no CVE match
        if not matched_exploits and cve_id:
            matched_exploits = [
                e for e in sploit_by_keyword
                if cve_id.lower() in (e.get("Title", "") or "").lower()
            ]

        # Cross-reference with msf modules by CVE ID or technology keyword
        matched_msf = [
            m for m in msf_modules
            if cve_id.lower() in m.get("name", "").lower()
               or cve_id.lower() in m.get("description", "").lower()
               or technology.lower() in m.get("name", "").lower()
        ]

        attack_ready = bool(matched_exploits or matched_msf)
        if attack_ready:
            attack_ready_count += 1

        chain_entry = {
            "cve_id": cve_id,
            "cvss_score": cve.get("cvss_score") or cve.get("cvss", {}).get("score"),
            "severity": cve.get("severity", ""),
            "exploitability_labels": cve.get("exploitability_labels", []),
            "attack_ready": attack_ready,
            "searchsploit_exploits": matched_exploits,
            "msf_modules": matched_msf,
            "vulnx_detail": {
                k: v for k, v in cve.items()
                if k not in ("exploitability_labels",)
            },
        }
        chains.append(chain_entry)

    total_cves = len(chains)

    return {
        "technology": technology,
        "version": version,
        "summary": {
            "total_cves": total_cves,
            "attack_ready_count": attack_ready_count,
            "has_msf_module": len(msf_modules) > 0,
            "has_searchsploit": searchsploit_result.get("total", 0) > 0,
        },
        "chains": chains,
        "raw_sources": {
            "vulnx_total": vulnx_result.get("total", 0),
            "searchsploit_total": searchsploit_result.get("total", 0),
            "msf_total": msf_result.get("total", 0),
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 5 — vulnx_enrich_finding
# ═════════════════════════════════════════════════════════════════════════════

def _ensure_intelligence_columns() -> None:
    """Add intelligence enrichment columns to findings table if they don't exist yet.

    Uses ALTER TABLE with try/except per column — safe to call repeatedly.
    """
    new_columns = [
        ("cve_reference", "TEXT"),
        ("poc_url", "TEXT"),
        ("kev_status", "TEXT"),
        ("msf_module", "TEXT"),
        ("searchsploit_path", "TEXT"),
    ]
    with db_connection() as conn:
        for col_name, col_type in new_columns:
            try:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")
            except Exception:
                # Column already exists — safe to ignore
                pass


@mcp.tool()
async def vulnx_enrich_finding(
    cve_id: str,
    finding_id: int = 0,
) -> dict:
    """Enrich a CVE with full intelligence from vulnx and searchsploit, optionally updating a stored finding.

    Fetches detailed CVE information from ProjectDiscovery vulnx and
    cross-references with ExploitDB. If finding_id is provided, the
    corresponding database record is updated with CVE reference, CVSS
    score, PoC URL, KEV status, Metasploit module path, and
    searchsploit exploit path.
    """
    err = validate_cve_id(cve_id, "cve_id")
    if err:
        return {"error": err}

    cve_id_clean = cve_id.strip().upper()

    # Run vulnx id and searchsploit in parallel
    vulnx_cmd = [VULNX_BIN, "id", cve_id_clean, "--json"]
    searchsploit_cmd = [SEARCHSPLOIT_BIN, "--json", "--cve", cve_id_clean.replace("CVE-", "")]

    (vrc, vstdout, vstderr), (src, sstdout, sstderr) = await asyncio.gather(
        _run_subprocess(vulnx_cmd),
        _run_subprocess(searchsploit_cmd),
    )

    # Parse vulnx output
    vulnx_data = _parse_json_output(vstdout) if vstdout.strip() else None
    if isinstance(vulnx_data, list) and vulnx_data:
        vulnx_data = vulnx_data[0]  # `vulnx id` returns list with single item

    # Parse searchsploit output
    searchsploit_data = _parse_json_output(sstdout) if sstdout.strip() else None
    searchsploit_exploits = []
    if isinstance(searchsploit_data, dict):
        for e in searchsploit_data.get("RESULTS_EXPLOIT", []):
            searchsploit_exploits.append({
                "Title": e.get("Title", ""),
                "Path": e.get("Path", ""),
                "full_path": f"/usr/share/exploitdb/{e.get('Path', '')}" if e.get("Path") else "",
                "Type": e.get("Type", ""),
            })

    # Build enrichment result
    result: Dict[str, Any] = {
        "cve_id": cve_id_clean,
        "vulnx_detail": vulnx_data or {},
        "searchsploit_results": searchsploit_exploits,
        "db_updated": False,
    }

    if vulnx_data:
        result["exploitability_labels"] = _add_exploitability_labels(vulnx_data)

    # Extract key fields for DB update
    cvss_score = None
    poc_url = ""
    kev_status = "false"

    if vulnx_data:
        # CVSS score — vulnx may store it in different structures
        cvss_score = vulnx_data.get("cvss_score") or (
            vulnx_data.get("cvss", {}).get("score") if isinstance(vulnx_data.get("cvss"), dict) else None
        )
        # PoC URL
        poc_refs = vulnx_data.get("poc", []) or vulnx_data.get("references", [])
        if isinstance(poc_refs, list) and poc_refs:
            poc_url = poc_refs[0] if isinstance(poc_refs[0], str) else str(poc_refs[0])
        # KEV status
        kev_status = "true" if vulnx_data.get("is_kev") else "false"

    # First searchsploit path
    searchsploit_path = searchsploit_exploits[0]["full_path"] if searchsploit_exploits else ""

    # Update DB finding if requested
    if finding_id > 0:
        # Verify finding exists
        existing = get_finding(finding_id)
        if not existing:
            result["error"] = f"Finding ID {finding_id} not found in database"
            return result

        _ensure_intelligence_columns()

        try:
            with db_connection() as conn:
                conn.execute(
                    """
                    UPDATE findings SET
                        cve_reference    = ?,
                        cvss_score       = COALESCE(?, cvss_score),
                        poc_url          = ?,
                        kev_status       = ?,
                        msf_module       = ?,
                        searchsploit_path = ?,
                        updated_at       = datetime('now')
                    WHERE id = ?
                    """,
                    (
                        cve_id_clean,
                        cvss_score,
                        poc_url,
                        kev_status,
                        "",  # msf_module left empty — use msf_module_search separately
                        searchsploit_path,
                        finding_id,
                    ),
                )
            result["db_updated"] = True
        except Exception as e:
            logger.error("Failed to update finding %d: %s", finding_id, e)
            result["error"] = f"DB update failed: {e}"
            result["db_updated"] = False

    return result
