"""StealthVision-MCP - Git Security Testing Module
S3, bucket spillover, .git exposure, credential leaks.
"""
import httpx
from mcp_instance import mcp
from tools.http_utils import get_http_client
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def git_exposure_check(base_url: str) -> dict:
    """
    Check for .git directory exposure and git related leaks.
    
    Args:
        base_url: Target URL to check
    
    Returns:
        Git exposure findings
    """
    client = get_http_client()
    findings = []
    
    git_paths = [
        "/.git/config",
        "/.git/HEAD",
        "/.git/objects/",
        "/.git/logs/",
        "/.git/refs/heads/",
    ]
    
    for path in git_paths:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            resp = client.get(url, timeout=5.0)
            if resp.status_code == 200 and ("git" in resp.text.lower() or "ref:" in resp.text):
                findings.append({
                    "type": "git_exposed",
                    "path": path,
                    "severity": "critical",
                    "finding": "Git directory accessible - source code leak risk"
                })
        except:
            pass
    
    return {
        "base_url": base_url,
        "findings": findings,
        "count": len(findings)
    }


@mcp.tool()
def git_s3_bucket_check(domain: str) -> dict:
    """
    Check for Git-related S3 bucket spillover.
    
    Args:
        domain: Target domain
    
    Returns:
        Git+S3 exposure findings
    """
    client = get_http_client()
    findings = []
    
    # Git credential patterns
    patterns = [
        f"{domain}/.git/config",
        f"{domain}/.git-credentials",
        f"{domain}/.env",
    ]
    
    for pattern in patterns:
        s3_url = f"http://{pattern}.s3.amazonaws.com"
        try:
            resp = client.get(s3_url, timeout=5.0)
            if resp.status_code == 200 and len(resp.text) > 0:
                findings.append({
                    "type": "s3_git_credentials",
                    "bucket": pattern,
                    "severity": "critical"
                })
        except:
            pass
    
    return {
        "domain": domain,
        "findings": findings,
        "count": len(findings)
    }