"""StealthVision-MCP - Git Security Testing Module"""
import httpx
from mcp_instance import mcp
import logging

logger = logging.getLogger("stealthvision")


def _get_client():
    return httpx.Client(timeout=30.0, verify=True, follow_redirects=False)


@mcp.tool()
def git_exposure_check(base_url: str) -> dict:
    """Check for .git directory exposure."""
    client = _get_client()
    findings = []
    
    for path in ["/.git/config", "/.git/HEAD", "/.git/objects/"]:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            resp = client.get(url, timeout=5.0)
            if resp.status_code == 200 and ("git" in resp.text.lower() or "ref:" in resp.text):
                findings.append({"type": "git_exposed", "path": path, "severity": "critical"})
        except:
            pass
    
    return {"base_url": base_url, "findings": findings, "count": len(findings)}


@mcp.tool()
def git_s3_bucket_check(domain: str) -> dict:
    """Check for Git-related S3 bucket spillover."""
    client = _get_client()
    findings = []
    
    for pattern in [f"{domain}/.git/config", f"{domain}/.git-credentials"]:
        s3_url = f"http://{pattern}.s3.amazonaws.com"
        try:
            resp = client.get(s3_url, timeout=5.0)
            if resp.status_code == 200 and len(resp.text) > 0:
                findings.append({"type": "s3_git_credentials", "bucket": pattern})
        except:
            pass
    
    return {"domain": domain, "findings": findings, "count": len(findings)}