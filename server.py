"""StealthVision-MCP Server - Main Entry Point
OWASP Top 10 2025 Vulnerability Assessment Platform

Usage:
    python server.py                    # stdio transport (for Claude Desktop)
    python server.py --transport sse    # SSE transport (for web/remote)

Claude Desktop config (claude_desktop_config.json):
    {
        "mcpServers": {
            "stealthvision": {
                "command": "python",
                "args": ["/path/to/bugbounty-mcp/server.py"],
                "env": {
                    "SHODAN_API_KEY": "...",
                    "GITHUB_TOKEN": "..."
                }
            }
        }
    }
"""
import sys
import os
import importlib

# Ensure the project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

# ─── Import the shared FastMCP instance (+ Universal System Prompt) ──────────
from mcp_instance import mcp, _SYSTEM_PROMPT

# ─── Import all tool modules (each registers its tools via @mcp.tool()) ───────
_TOOL_MODULES = [
    "tools.a01_access_control",
    "tools.a02_misconfiguration",
    "tools.a03_supply_chain",
    "tools.a04_cryptography",
    "tools.a05_injection",
    "tools.a06_insecure_design",
    "tools.a07_authentication",
    "tools.a08_integrity",
    "tools.a09_logging",
    "tools.a10_exceptions",
    "tools.recon",
    "tools.reporting",
    "tools.intelligence",
    "tools.hunter",
    "tools.knowledge_base",
    "tools.owasp_wstg",
    "tools.owasp_api_top10",
    "tools.cve_kb",
    "tools.cwe_kb",
    "tools.htb_kb",
    "tools.thm_kb",
    "tools.patt_kb",
    "tools.lolbins_kb",
    "tools.attck_capec_kb",
    "tools.exploitdb_kb",
    "tools.nuclei_kb",
    "tools.hacktricks_kb",
    "tools.seclists_kb",
    "tools.portswigger_kb",
    "tools.portswigger_notes_kb",
    "tools.rfc_kb",
    "tools.rag_engine",
    "tools.api_testing",
    "tools.cloud_testing",
    "tools.git_testing",
    "tools.container_testing",
    "tools.mode_selector",
    "tools.js_analysis",
    "tools.jwt_advanced",
    "tools.oob_testing",
    "tools.impact_scoring",
    "tools.subdomain_brute",
    "tools.graphql_mutation",
    "tools.port_scanner",
    "tools.csti_chains",
    "tools.waf_bypass",
    "tools.graphql_introspect",
    "tools.ad_enumeration",
    "tools.internal_pivot",
    "tools.priv_esc",
    "tools.crypto_solver",
    "tools.stego_helper",
    "tools.forensics_extract",
    "tools.binary_analyzer",
    "tools.hunter_workflow",
    "tools.kerberos_attacks",
    "tools.nmap_scanner",
    "tools.credential_dumper",
    "tools.smb_pwn",
]

_loaded = []
_failed = []

for module_name in _TOOL_MODULES:
    try:
        importlib.import_module(module_name)
        _loaded.append(module_name)
    except Exception as e:
        _failed.append((module_name, str(e)))
        # Don't crash - continue loading other modules
        print(f"[WARN] Failed to load {module_name}: {e}", file=sys.stderr)

if __name__ == "__main__":
    import argparse
    from config import VERIFY_SSL

    parser = argparse.ArgumentParser(
        description="StealthVision-MCP Server - OWASP Top 10 2025"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport type: stdio (default) or sse (HTTP/SSE for remote)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for SSE transport (default: 127.0.0.1; use 0.0.0.0 for remote access — NOT recommended without auth)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE transport (default: 8000)",
    )
    args = parser.parse_args()

    print(f"[StealthVision] Loaded {len(_loaded)}/58 tool modules", file=sys.stderr)
    if _failed:
        for mod, err in _failed:
            print(f"[StealthVision] FAILED: {mod} - {err}", file=sys.stderr)

    # ── Confirm Universal System Prompt injection ──────────────────────────────
    print(
        f"[StealthVision] ✅ Universal Bug Bounty System Prompt ACTIVE "
        f"({len(_SYSTEM_PROMPT):,} chars) — "
        "all connected MCP clients will adopt the **StealthVision** persona.",
        file=sys.stderr,
    )

    if not VERIFY_SSL:
        print("[StealthVision] WARNING: SSL verification is disabled (VERIFY_SSL=false)", file=sys.stderr)

    if args.transport == "sse":
        print(f"[StealthVision] Starting SSE server on {args.host}:{args.port}", file=sys.stderr)
        # mcp>=1.27 removed host/port kwargs from .run() — they're set on settings.
        # See mcp.server.fastmcp.run_sse_async: it reads self.settings.host/port.
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="sse")
    else:
        print("[StealthVision] Starting stdio server...", file=sys.stderr)
        mcp.run(transport="stdio")
