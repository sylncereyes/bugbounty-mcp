from mcp_instance import mcp
from tools.db import add_target as db_add_target
from tools.db import get_targets as db_get_targets
from tools.db import delete_target as db_delete_target
from tools.db import get_findings as db_get_findings
from tools.db import save_finding as db_save_finding
from tools.db import update_finding_status as db_update_status
import logging
import asyncio
logger = logging.getLogger("agy")

@mcp.tool()
def add_target(program_name: str, domain: str, scope: list, out_of_scope: list = None, platform: str = None, bounty_range: str = None, notes: str = None) -> dict:
    """Inserts a new target program into the SQLite database."""
    tid = db_add_target(
        program_name=program_name,
        domain=domain,
        scope=scope,
        out_of_scope=out_of_scope,
        platform=platform,
        bounty_range=bounty_range,
        notes=notes
    )
    return {"status": "success", "target_id": tid, "program_name": program_name}

@mcp.tool()
def list_targets() -> list:
    """Lists all configured targets in the SQLite database."""
    return db_get_targets()

@mcp.tool()
def delete_target(target_id: int) -> dict:
    """Deletes target program and associated issues."""
    success = db_delete_target(target_id)
    return {"status": "success" if success else "failed", "target_id": target_id}

@mcp.tool()
def list_findings(target_id: int, severity: str = None, status: str = None, owasp_category: str = None) -> list:
    """Queries vulnerability findings with optional filters."""
    return db_get_findings(target_id, severity, status, owasp_category)

_VALID_SEVERITIES = frozenset({'Critical', 'High', 'Medium', 'Low', 'Informational'})

@mcp.tool()
def save_finding_tool(target_id: int, title: str, vulnerability_type: str, owasp_category: str, severity: str, url: str = None, parameter: str = None, payload: str = None, description: str = None, evidence: str = None) -> dict:
    """Manually insert vulnerability findings into target database. Severity must be: Critical, High, Medium, Low, or Informational."""
    if severity not in _VALID_SEVERITIES:
        return {"status": "error", "error": f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"}
    fid = db_save_finding(
        target_id=target_id,
        title=title,
        vulnerability_type=vulnerability_type,
        owasp_category=owasp_category,
        severity=severity,
        url=url,
        parameter=parameter,
        payload=payload,
        description=description,
        evidence=evidence
    )
    return {"status": "success", "finding_id": fid}

@mcp.tool()
def update_finding_status_tool(finding_id: int, status: str) -> dict:
    """Update status state for an existing finding entry. Valid statuses: new, reported, accepted, rejected, duplicate, fixed."""
    try:
        success = db_update_status(finding_id, status)
        return {"status": "success" if success else "failed", "finding_id": finding_id}
    except ValueError as e:
        return {"status": "error", "error": str(e), "finding_id": finding_id}

async def _recon_domain_impl(domain: str) -> dict:
    """Helper implementation for DNS probes and basic WHOIS lookup on target domain."""
    dns_records = {}
    whois_info = "Not resolved"
    
    _dns_available = True
    try:
        import dns.resolver
    except ImportError:
        _dns_available = False
        dns_records["error"] = "dnspython library is not installed. DNS lookup was skipped."

    if _dns_available:
        for r_type in ["A", "MX", "TXT", "CNAME"]:
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, domain, r_type)
                dns_records[r_type] = [str(r) for r in answers]
            except Exception:
                pass
        
    try:
        import whois
        w = await asyncio.to_thread(whois.whois, domain)
        whois_info = f"Registrar: {w.registrar}, Creation Date: {w.creation_date}"
    except ImportError:
        whois_info = "Error: python-whois library is not installed. WHOIS lookup was skipped."
    except Exception:
        pass

    return {
        "domain": domain,
        "dns_records": dns_records,
        "whois": whois_info
    }

@mcp.tool()
async def recon_domain(domain: str, target_id: int) -> dict:
    """Performs DNS probes and basic WHOIS lookup on target domain."""
    # FIX MINOR-3: target_id was previously ignored — add optional scope guard
    if True:
        from tools.db import is_in_scope
        if not is_in_scope(target_id, f"https://{domain}"):
            return {"error": f"Domain {domain} is out of scope for target {target_id}. Scan aborted."}
    return await _recon_domain_impl(domain)

@mcp.tool()
async def dns_lookup(domain: str, record_type: str = "A") -> dict:
    """Quick CNAME / A lookup on domain."""
    records = []
    try:
        import dns.resolver
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, record_type)
        records = [str(r) for r in answers]
    except ImportError:
        return {"error": "dnspython library is not installed. DNS lookup could not run."}
    except Exception as e:
        return {"error": str(e)}
    return {"domain": domain, "type": record_type, "records": records}

@mcp.tool()
async def whois_lookup(domain: str) -> dict:
    """Retrieves whois info on target domain."""
    res = await _recon_domain_impl(domain)
    return {"domain": domain, "whois": res.get("whois", "")}

@mcp.tool()
def cvss_calculator(vector: str) -> dict:
    """Calculates CVSS Base score from provided Vector string."""
    try:
        from cvss import CVSS3
        c = CVSS3(vector)
        return {
            "vector": vector,
            "base_score": c.base_score,
            "severity": c.severities()[0]
        }
    except Exception as e:
        return {"error": f"Failed to compute: {str(e)}"}
