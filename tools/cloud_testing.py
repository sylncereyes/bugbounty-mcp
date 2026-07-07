"""Cloud Security Testing Module"""
import httpx
from mcp_instance import mcp
from tools.http_utils import secure_request_sync, get_sync_client, assert_safe_target_sync
from tools.db import is_in_scope
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def cloud_metadata_check(base_url: str, target_id: int) -> dict:
    """Check for cloud metadata service exposure (AWS/GCP/Azure)."""
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "findings": [], "count": 0}
    
    findings = []
    client = get_sync_client()
    
    try:
        resp = secure_request_sync(
            client, "GET",
            "http://169.254.169.254/latest/meta-data/",
            target_id,
            timeout=3.0
        )
        if "EC2" in resp.text or "instance-id" in resp.text:
            findings.append({"type": "aws_metadata_exposed", "severity": "critical"})
    except Exception as e:
        logger.debug("AWS metadata check failed: %s", e)
    
    try:
        headers = {"Metadata-Flavor": "Google"}
        resp = secure_request_sync(
            client, "GET",
            "http://metadata.google.internal/computeMetadata/v1/",
            target_id,
            headers=headers,
            timeout=3.0
        )
        if "project-id" in resp.text:
            findings.append({"type": "gcp_metadata_exposed", "severity": "critical"})
    except Exception as e:
        logger.debug("GCP metadata check failed: %s", e)
    finally:
        client.close()
    
    return {"base_url": base_url, "findings": findings, "count": len(findings)}


@mcp.tool()
def cloud_storage_check(domain: str, target_id: int, service: str = "auto") -> dict:
    """Check for exposed cloud storage buckets."""
    if not is_in_scope(target_id, domain):
        return {"error": f"Domain {domain} is out of scope for target {target_id}. Scan aborted.", "findings": [], "count": 0}
    
    findings = []
    client = get_sync_client()
    
    try:
        for prefix in [domain, domain.replace('.', '-')]:
            s3_url = f"http://{prefix}.s3.amazonaws.com"
            try:
                resp = secure_request_sync(
                    client, "GET",
                    s3_url,
                    target_id,
                    timeout=5.0
                )
                if resp.status_code == 200:
                    findings.append({"type": "s3_bucket_exposed", "bucket": f"{prefix}.s3.amazonaws.com"})
            except Exception as e:
                logger.debug("S3 bucket check failed for %s: %s", prefix, e)
    finally:
        client.close()
    
    return {"domain": domain, "findings": findings, "count": len(findings)}