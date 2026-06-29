"""StealthVision-MCP - Cloud Security Testing Module
AWS, GCP, Azure misconfiguration and security checks.
"""
import httpx
from mcp_instance import mcp
from tools.http_utils import get_http_client
import logging

logger = logging.getLogger("stealthvision")


@mcp.tool()
def cloud_metadata_check(base_url: str) -> dict:
    """
    Check for cloud metadata service exposure (AWS/GCP/Azure).
    
    Args:
        base_url: Target URL to test
    
    Returns:
        Metadata service exposure findings
    """
    client = get_http_client()
    findings = []
    
    # AWS metadata
    aws_endpoints = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/",
    ]
    
    for endpoint in aws_endpoints:
        try:
            resp = client.get(endpoint, timeout=3.0)
            if "EC2" in resp.text or "instance-id" in resp.text:
                findings.append({
                    "type": "aws_metadata_exposed",
                    "url": endpoint,
                    "severity": "critical",
                    "finding": "AWS metadata service accessible - IMDSv1 vulnerability"
                })
        except:
            pass
    
    # GCP metadata
    gcp_endpoints = [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/computeMetadata/v1/",
    ]
    
    for endpoint in gcp_endpoints:
        try:
            headers = {"Metadata-Flavor": "Google"}
            resp = client.get(endpoint, headers=headers, timeout=3.0)
            if "project-id" in resp.text or "metadata" in resp.text:
                findings.append({
                    "type": "gcp_metadata_exposed",
                    "url": endpoint,
                    "severity": "critical",
                    "finding": "GCP metadata service accessible"
                })
        except:
            pass
    
    return {
        "base_url": base_url,
        "findings": findings,
        "count": len(findings)
    }


@mcp.tool()
def cloud_storage_check(domain: str, service: str = "auto") -> dict:
    """
    Check for exposed cloud storage buckets (S3, GCS, Azure Blob).
    
    Args:
        domain: Target domain name
        service: "s3", "gcs", "azure", or "auto"
    
    Returns:
        Bucket exposure findings
    """
    findings = []
    client = get_http_client()
    
    # Common bucket naming patterns
    prefixes = [
        f"{domain}",
        f"{domain.replace('.', '-')}",
        f"{domain.replace('.', '')}",
        f"assets.{domain}",
        f"static.{domain}",
    ]
    
    if service in ["s3", "auto"]:
        for prefix in prefixes:
            s3_url = f"http://{prefix}.s3.amazonaws.com"
            try:
                resp = client.get(s3_url, timeout=5.0)
                if resp.status_code == 200:
                    findings.append({
                        "type": "s3_bucket_exposed",
                        "bucket": f"{prefix}.s3.amazonaws.com",
                        "severity": "high"
                    })
            except:
                pass
    
    if service in ["gcs", "auto"]:
        for prefix in prefixes:
            gcs_url = f"http://{prefix}.appspot.com"
            try:
                resp = client.get(gcs_url, timeout=5.0)
                if "NoSuchBucket" not in resp.text and resp.status_code == 200:
                    findings.append({
                        "type": "gcs_bucket_exposed",
                        "bucket": f"{prefix}.appspot.com",
                        "severity": "high"
                    })
            except:
                pass
    
    return {
        "domain": domain,
        "findings": findings,
        "count": len(findings)
    }