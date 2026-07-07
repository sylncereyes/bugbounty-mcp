#!/usr/bin/env python3
"""
External Tool Wrappers
Wrappers for CLI tools like subfinder, httpx, nuclei, katana to integrate with MCP.
"""
import asyncio
import json
import logging
import os
import subprocess
from typing import Optional, List, Dict
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")

# ─── Tool Paths ───────────────────────────────────────────────────────────────

def _get_tool_path(tool_name: str) -> str:
    """Get path to external tool."""
    import shutil
    # Check common locations
    for base in [os.path.expanduser('~/.local/bin'), os.path.expanduser('~/go/bin'), '/usr/bin', '/usr/local/bin']:
        path = os.path.join(base, tool_name)
        if os.path.exists(path):
            return path
    # Use shutil.which as fallback
    return shutil.which(tool_name) or tool_name

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 1 - active_recon
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def active_recon(domain: str, timeout: int = 60) -> dict:
    """
    Run active reconnaissance using multiple tools.
    
    Uses:
    - httpx: HTTP probing and endpoint discovery
    - subfinder: subdomain enumeration
    - naabu: port scanning
    
    Returns discovered assets for verification.
    """
    import os
    
    results = {
        "domain": domain,
        "subdomains": [],
        "alive_hosts": [],
        "open_ports": [],
        "errors": []
    }
    
    # Run subfinder
    subfinder_path = _get_tool_path('subfinder')
    if subfinder_path:
        try:
            proc = await asyncio.create_subprocess_shell(
                f"{subfinder_path} -d {domain} -silent -timeout {timeout}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            results["subdomains"] = [s.strip() for s in stdout.decode().strip().split('\n') if s.strip()]
        except asyncio.TimeoutError:
            results["errors"].append("subfinder timed out")
        except Exception as e:
            results["errors"].append(f"subfinder error: {str(e)}")
    
    # Run httpx on discovered subdomains
    httpx_path = _get_tool_path('httpx')
    if httpx_path and results["subdomains"]:
        try:
            subdomains_input = '\n'.join(results["subdomains"])
            proc = await asyncio.create_subprocess_shell(
                f"echo '{subdomains_input}' | {httpx_path} -silent -status-code -timeout 10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            alive = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    alive.append({"url": parts[0], "status": parts[1] if len(parts) > 1 else "unknown"})
            results["alive_hosts"] = alive
        except asyncio.TimeoutError:
            results["errors"].append("httpx timed out")
        except Exception as e:
            results["errors"].append(f"httpx error: {str(e)}")
    
    # Run naabu for port scanning
    naabu_path = _get_tool_path('naabu')
    if naabu_path and results["subdomains"]:
        try:
            subdomains_input = '\n'.join(results["subdomains"][:20])  # Limit to 20 for speed
            proc = await asyncio.create_subprocess_shell(
                f"echo '{subdomains_input}' | {naabu_path} -silent -p -",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            ports = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    ports.append(line.strip())
            results["open_ports"] = ports[:20]
        except asyncio.TimeoutError:
            results["errors"].append("naabu timed out")
        except Exception as e:
            results["errors"].append(f"naabu error: {str(e)}")
    
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 2 - nuclei_scan
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def nuclei_scan(target: str, templates: Optional[str] = None, 
                       severity: Optional[str] = None,
                       timeout: int = 300) -> dict:
    """
    Run nuclei scanner on a target.
    
    Parameters:
        target: URL or domain to scan
        templates: Template filter (e.g., 'cves,misconfigurations') or None for all
        severity: Filter by severity (low,medium,high,critical) or None for all
    
    Returns nuclei findings.
    """
    nuclei_path = _get_tool_path('nuclei')
    
    if not nuclei_path:
        return {"error": "nuclei not found in PATH"}
    
    cmd = f"{nuclei_path} -u {target} -json -silent"
    if templates:
        cmd += f" -t {templates}"
    if severity:
        cmd += f" -severity {severity}"
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        
        findings = []
        for line in stdout.decode().strip().split('\n'):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template_id": finding.get("template-id"),
                        "severity": finding.get("info", {}).get("severity"),
                        "matched_at": finding.get("matched-at"),
                        "extracted": finding.get("extracted-results", [])[:5],
                    })
                except json.JSONDecodeError:
                    continue
        
        return {
            "status": "success",
            "target": target,
            "findings_count": len(findings),
            "findings": findings[:20],  # Limit results
        }
    except asyncio.TimeoutError:
        return {"error": "nuclei scan timed out", "target": target}
    except Exception as e:
        return {"error": str(e), "target": target}

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL 3 - katana_crawler
# ═══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def katana_crawler(url: str, depth: int = 3, 
                          js_timeout: int = 10,
                          timeout: int = 120) -> dict:
    """
    Crawl a target using Katana for endpoint discovery.
    
    Returns discovered URLs with methods.
    """
    katana_path = _get_tool_path('katana')
    
    if not katana_path:
        return {"error": "katana not found in PATH"}
    
    cmd = f"{katana_path} -u {url} -d {depth} -jc -kf all -output json"
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        
        urls = []
        for line in stdout.decode().strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    urls.append({
                        "url": data.get("url"),
                        "method": data.get("method", "GET"),
                        "source": data.get("source"),
                    })
                except json.JSONDecodeError:
                    continue
        
        return {
            "status": "success",
            "target": url,
            "urls_discovered": len(urls),
            "urls": urls[:50],
        }
    except asyncio.TimeoutError:
        return {"error": "katana crawl timed out", "target": url}
    except Exception as e:
        return {"error": str(e), "target": url}