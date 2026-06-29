"""StealthVision-MCP - Cloud Security Testing Module"""
import httpx
from mcp_instance import mcp
import logging

logger = logging.getLogger("stealthvision")


def _get_client():
    return httpx.Client(timeout=30.0, verify=True, follow_redirects=False)


@mcp.tool()
def cloud_metadata_check(base_url: str) -> dict:
    """Check for cloud metadata service exposure (AWS/GCP/Azure)."""
    client = _get_client()
    findings = []
    
    try:
        resp = client.get("http://169.254.169.254/latest/meta-data/", timeout=3.0)
        if "EC2" in resp.text or "instance-id" in resp.text:
            findings.append({"type": "aws_metadata_exposed", "severity": "critical"})
    except:
        pass
    
    try:
        headers = {"Metadata-Flavor": "Google"}
        resp = client.get("http://metadata.google.internal/computeMetadata/v1/", headers=headers, timeout=3.0)
        if "project-id" in resp.text:
            findings.append({"type": "gcp_metadata_exposed", "severity": "critical"})
    except:
        pass
    
    return {"base_url": base_url, "findings": findings, "count": len(findings)}


@mcp.tool()
def cloud_storage_check(domain: str, service: str = "auto") -> dict:
    """Check for exposed cloud storage buckets."""
    client = _get_client()
    findings = []
    
    for prefix in [domain, domain.replace('.', '-')]:
        s3_url = f"http://{prefix}.s3.amazonaws.com"
        try:
            resp = client.get(s3_url, timeout=5.0)
            if resp.status_code == 200:
                findings.append({"type": "s3_bucket_exposed", "bucket": f"{prefix}.s3.amazonaws.com"})
        except:
            pass
    
    return {"domain": domain, "findings": findings, "count": len(findings)}