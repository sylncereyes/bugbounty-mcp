"""StealthVision-MCP - Mode Selector for Multi-Purpose Security Operations
Allows switching between Bug Hunter, Pentester, and CTF Player modes.
"""
import json
from mcp_instance import mcp
from tools.db import get_connection
import logging

logger = logging.getLogger("stealthvision")

# Current mode state
_CURRENT_MODE = "hunter"  # Default mode

# Mode-specific tool lists
MODE_TOOLSETS = {
    "hunter": [
        # Recon
        "recon", "dns_lookup", "whois_lookup", "port_scanner",
        # Vulnerability Testing
        "a01_access_control", "a02_misconfiguration", "a03_supply_chain",
        "a04_cryptography", "a05_injection", "a06_insecure_design",
        "a07_authentication", "a08_integrity", "a09_logging", "a10_exceptions",
        "owasp_wstg", "owasp_api_top10",
        # Intelligence
        "vulnx_enrich_finding", "vulnx_exploitable", "msf_module_search", "searchsploit_query",
        # Reporting
        "generate_report", "export_findings_csv",
        # Knowledge Base
        "search_attck", "search_cve", "search_exploits", "search_hacktricks",
        "rag_search", "rag_context_inject", "rag_get_exploits",
        "hunter_workflow", "scope_filter", "bounty_calculator",
        "nmap_scan", "nmap_service_scan",
    ],
    "pentest": [
        # All hunter tools + additional
        "recon", "dns_lookup", "whois_lookup", "network_scan",
        "a01_access_control", "a02_misconfiguration", "a03_supply_chain",
        "a04_cryptography", "a05_injection", "a06_insecure_design",
        "a07_authentication", "a08_integrity", "a09_logging", "a10_exceptions",
        "owasp_wstg", "owasp_api_top10",
        "vulnx_enrich_finding", "vulnx_exploitable",
        "generate_report", "export_findings_csv",
        "search_attck", "search_cve", "search_exploits", "search_hacktricks",
        # Internal pentest focused
        "internal_network_scan", "ldap_enum", "smb_scan",
        "ad_enumeration", "internal_pivot", "lateral_movement_check", "priv_esc_chains",
        "kerberos_attack", "bloodhound_collector",
        "credential_dumper", "trust_mapper",
    ],
    "ctf": [
        # Focused tools for CTF challenges
        "recon", "dns_lookup",
        "a05_injection", "a01_access_control",
        "search_hacktricks", "search_attck",
        "crypto_solver", "stego_helper", "forensics_extract",
        "reverse_helper", "binary_analyzer",
    ]
}


@mcp.tool()
def mode(mode_name: str) -> dict:
    """
    Switch StealthVision-MCP to specific operational mode.
    
    Args:
        mode_name: One of "hunter", "pentest", or "ctf"
    
    Returns:
        Current mode status and available tools for that mode
    """
    global _CURRENT_MODE
    
    valid_modes = ["hunter", "pentest", "ctf"]
    
    if mode_name not in valid_modes:
        return {
            "error": f"Invalid mode '{mode_name}'",
            "valid_modes": valid_modes,
            "current_mode": _CURRENT_MODE
        }
    
    _CURRENT_MODE = mode_name
    
    return {
        "status": "mode_changed",
        "current_mode": _CURRENT_MODE,
        "tools_count": len(MODE_TOOLSETS[mode_name]),
        "tools_available": MODE_TOOLSETS[mode_name],
        "message": f"Switched to {_CURRENT_MODE} mode - persona and toolset adjusted"
    }


@mcp.tool()
def get_current_mode() -> dict:
    """Get current operational mode and available tools."""
    return {
        "current_mode": _CURRENT_MODE,
        "tools_available": MODE_TOOLSETS[_CURRENT_MODE],
        "total_tools": len(MODE_TOOLSETS[_CURRENT_MODE])
    }


@mcp.tool()
def list_modes() -> dict:
    """List all available modes and their toolsets."""
    return {
        "modes": {
            mode: {"tool_count": len(tools)}
            for mode, tools in MODE_TOOLSETS.items()
        },
        "default_mode": _CURRENT_MODE
    }