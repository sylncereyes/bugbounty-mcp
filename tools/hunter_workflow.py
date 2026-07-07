"""Bug Bounty Hunter Workflow Orchestration"""
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")

HUNTER_WORKFLOW = {
    "step_1": ["recon", "dns_lookup", "subdomain_brute"],
    "step_2": ["port_scanner", "security_headers_check"],
    "step_3": ["sqli_test", "xss_test", "csti_fuzz"],
    "step_4": ["waf_detect", "jwt_advanced"],
    "step_5": ["impact_scoring", "generate_report"],
}

@mcp.tool()
def hunter_workflow(target: str, scope: list = None) -> dict:
    """Execute automated bug bounty workflow."""
    workflow = []
    
    if scope is None:
        scope = ["*.target.com", "target.com"]
    else:
        scope = list(scope)
    
    workflow = [
        f"recon_domain(target='{target}')",
        f"port_scan(target='{target}')",
        f"security_headers_check(url='https://{target}')",
        f"sqli_test(url='https://{target}/search')",
        f"xss_test(url='https://{target}/profile')",
        f"csti_fuzz(url='https://{target}/search')",
        f"impact_scoring(vuln_type='rce', target='{target}')",
    ]
    
    return {
        "workflow": workflow,
        "steps": len(workflow),
        "target": target,
        "scope": scope,
        "success": True
    }

@mcp.tool()
def scope_filter(asset: str, program_rules: list = None) -> dict:
    """Check if asset is in-scope for bug bounty program."""
    if program_rules is None:
        program_rules = ["*.domain.com", "domain.com"]
    else:
        program_rules = list(program_rules)
    
    in_scope = any(asset.endswith(rule.replace("*", "")) or asset == rule.replace("*.", "") for rule in program_rules)
    
    return {
        "asset": asset,
        "in_scope": in_scope,
        "rules": program_rules,
        "success": True
    }

@mcp.tool()
def bounty_calculator(impact_score: int, bug_type: str) -> dict:
    """Predict bounty reward based on impact."""
    reward_ranges = {
        "critical": {"rce": (5000, 100000), "auth_bypass": (3000, 50000)},
        "high": {"sqli": (1000, 10000), "xss": (500, 3000)},
        "medium": {"idor": (300, 1500), "info_disclose": (100, 1000)},
        "low": {"subdomain_takeover": (100, 500), "misconfig": (50, 300)},
    }
    
    impact_level = "medium"
    if impact_score >= 90:
        impact_level = "critical"
    elif impact_score >= 70:
        impact_level = "high"
    elif impact_score >= 50:
        impact_level = "medium"
    else:
        impact_level = "low"
    
    range_info = reward_ranges.get(impact_level, {}).get(bug_type, (0, 0))
    
    return {
        "impact_score": impact_score,
        "impact_level": impact_level,
        "predicted_range": f"${range_info[0]}-${range_info[1]}" if range_info[0] > 0 else "Unknown",
        "success": True
    }