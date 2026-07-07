"""Git Security Testing Module"""
import httpx
from mcp_instance import mcp
from tools.http_utils import secure_request_sync, get_sync_client
from tools.db import is_in_scope
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def git_exposure_check(base_url: str, target_id: int) -> dict:
    """Check for .git directory exposure."""
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "findings": [], "count": 0}
    
    findings = []
    client = get_sync_client()
    
    try:
        for path in [".git/config", ".git/HEAD", ".git/objects/"]:
            url = f"{base_url.rstrip('/')}/{path}"
            try:
                resp = secure_request_sync(
                    client, "GET",
                    url,
                    target_id,
                    timeout=5.0
                )
                if resp.status_code == 200 and ("git" in resp.text.lower() or "ref:" in resp.text):
                    findings.append({"type": "git_exposed", "path": path, "severity": "critical"})
            except Exception as e:
                logger.debug("Git path check failed for %s: %s", path, e)
    finally:
        client.close()
    
    return {"base_url": base_url, "findings": findings, "count": len(findings)}


@mcp.tool()
def git_s3_bucket_check(domain: str, target_id: int) -> dict:
    """Check for Git-related S3 bucket spillover."""
    if not is_in_scope(target_id, domain):
        return {"error": f"Domain {domain} is out of scope for target {target_id}. Scan aborted.", "findings": [], "count": 0}
    
    findings = []
    client = get_sync_client()
    
    try:
        for pattern in [f"{domain}/.git/config", f"{domain}/.git-credentials"]:
            s3_url = f"http://{pattern}.s3.amazonaws.com"
            try:
                resp = secure_request_sync(
                    client, "GET",
                    s3_url,
                    target_id,
                    timeout=5.0
                )
                if resp.status_code == 200 and len(resp.text) > 0:
                    findings.append({"type": "s3_git_credentials", "bucket": pattern})
            except Exception as e:
                logger.debug("S3 git check failed for %s: %s", pattern, e)
    finally:
        client.close()
    
    return {"domain": domain, "findings": findings, "count": len(findings)}