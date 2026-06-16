import re
import os
import tldextract
import urllib.parse
from mcp_instance import mcp
from tools.db import save_finding, is_in_scope
from tools.http_utils import get_client, delay
import logging
logger = logging.getLogger("agy")

@mcp.tool()
async def detect_vulnerable_js_libs(url: str, target_id: int = None) -> dict:
    """Fetch the page HTML, extract JS script URLs and check if they match known vulnerable versions."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    libs_found = []
    vulnerable_count = 0
    
    # Simple dictionary of regex patterns to match libraries and their vulnerable range
    # Example: jQuery < 3.5.0
    vulnerable_patterns = [
        {"name": "jquery", "regex": r"jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)", "vuln_max": (3, 5, 0), "cve": "CVE-2020-11022"},
        {"name": "angular", "regex": r"angular[.-]([0-9]+\.[0-9]+\.[0-9]+)", "vuln_max": (1, 8, 0), "cve": "CVE-2022-25869"},
        {"name": "bootstrap", "regex": r"bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)", "vuln_max": (3, 4, 1), "cve": "CVE-2019-8331"},
        {"name": "lodash", "regex": r"lodash[.-]([0-9]+\.[0-9]+\.[0-9]+)", "vuln_max": (4, 17, 21), "cve": "CVE-2021-23337"}
    ]

    async with get_client() as client:
        try:
            res = await client.get(url)
            html = res.text
        except Exception as e:
            return {"error": f"Failed to retrieve page: {str(e)}"}
            
    # Parse HTML for script tags using regex
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
    
    for script_url in scripts:
        full_script_url = urllib.parse.urljoin(url, script_url)
        for lib in vulnerable_patterns:
            match = re.search(lib["regex"], script_url.lower())
            if match:
                ver_str = match.group(1)
                try:
                    ver = tuple(map(int, ver_str.split(".")))
                    is_vuln = ver < lib["vuln_max"]
                except ValueError:
                    is_vuln = False
                    
                if is_vuln:
                    vulnerable_count += 1
                    libs_found.append({
                        "name": lib["name"],
                        "version": ver_str,
                        "vulnerable": True,
                        "cve": lib["cve"],
                        "url": full_script_url
                    })
                else:
                    libs_found.append({
                        "name": lib["name"],
                        "version": ver_str,
                        "vulnerable": False,
                        "cve": None,
                        "url": full_script_url
                    })

    vulnerable = vulnerable_count > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Outdated Vulnerable JavaScript Library",
            vulnerability_type="Software Supply Chain Failure",
            owasp_category="A03:2025 - Software Supply Chain Failures",
            severity="Medium",
            url=url,
            description=f"Detected outdated/vulnerable JS library on target URL.",
            evidence=str(libs_found)
        )

    return {
        "libs_found": libs_found,
        "vulnerable_count": vulnerable_count,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def check_package_json_exposure(base_url: str, target_id: int = None) -> dict:
    """Checks for exposed dependency files like package.json, composer.json, etc."""
    if target_id is not None and not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    files = ["/package.json", "/composer.json", "/requirements.txt", "/package-lock.json"]
    exposed_files = []
    vulnerable_packages = []
    
    async with get_client() as client:
        for f in files:
            await delay()
            target = base_url.rstrip("/") + f
            try:
                res = await client.get(target)
                if res.status_code == 200:
                    exposed_files.append(f)
                    # Simple parse check for package.json dependencies
                    if f == "/package.json":
                        data = res.json()
                        deps = data.get("dependencies", {})
                        # Flag log4j, lodash < 4.17.21, etc.
                        for dep, ver in deps.items():
                            if dep == "lodash" and "4.17.21" not in ver:
                                vulnerable_packages.append({
                                    "name": dep,
                                    "version": ver,
                                    "cve": "CVE-2021-23337",
                                    "severity": "Medium"
                                })
            except Exception as e:
                logger.debug("Package file check failed for %s: %s", f, e)
                
    vulnerable = len(exposed_files) > 0 or len(vulnerable_packages) > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Exposed Dependency Files (Supply Chain)",
            vulnerability_type="Supply Chain Exposure",
            owasp_category="A03:2025 - Software Supply Chain Failures",
            severity="Medium",
            url=base_url,
            description="Exposed build/dependency manifest files.",
            evidence=f"Exposed files: {exposed_files}\nVulnerable packages: {vulnerable_packages}"
        )

    return {
        "exposed_files": exposed_files,
        "vulnerable_packages": vulnerable_packages,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def scan_github_secrets(repo_url: str = None, target_domain: str = None, target_id: int = None) -> dict:
    """Check public github repository or search results for secrets using GITHUB_TOKEN."""
    github_token = os.getenv("GITHUB_TOKEN")
    secrets_found = []
    
    if not github_token:
        return {
            "error": "GITHUB_TOKEN env variable not set. Unable to search GitHub API.",
            "secrets_found": [],
            "total": 0
        }
        
    query = ""
    if repo_url:
        parts = [p for p in repo_url.replace("http://", "").replace("https://", "").split("/") if p]
        if len(parts) >= 3 and "github.com" in parts[0]:
            repo = f"{parts[1]}/{parts[2]}"
            query = f"API_KEY repo:{repo}"
        else:
            query = "API_KEY"
    elif target_domain:
        query = f'"{target_domain}" API_KEY'
    else:
        return {"error": "Must provide either repo_url or target_domain", "secrets_found": [], "total": 0}

    async with get_client() as client:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {github_token}"
        }
        try:
            url = f"https://api.github.com/search/code?q={urllib.parse.quote(query)}"
            res = await client.get(url, headers=headers)
            if res.status_code == 200:
                items = res.json().get("items", [])
                for item in items:
                    secrets_found.append({
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "html_url": item.get("html_url"),
                        "repository": item.get("repository", {}).get("full_name")
                    })
            else:
                return {"error": f"GitHub API returned status {res.status_code}", "secrets_found": [], "total": 0}
        except Exception as e:
            return {"error": f"GitHub search failed: {str(e)}", "secrets_found": [], "total": 0}

    vulnerable = len(secrets_found) > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Exposed Secrets on GitHub",
            vulnerability_type="Information Disclosure",
            owasp_category="A03:2025 - Software Supply Chain Failures",
            severity="High",
            url=repo_url or f"https://github.com/search?q={query}",
            description="Exposed API keys, secrets, or tokens found on GitHub code search.",
            evidence=str(secrets_found)
        )

    return {
        "secrets_found": secrets_found,
        "total": len(secrets_found)
    }

@mcp.tool()
async def check_cdn_integrity(url: str, target_id: int = None) -> dict:
    """Verifies if CDN-delivered JS files are utilizing Subresource Integrity (SRI) checks."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    cdn_resources = []
    missing_sri_count = 0
    
    async with get_client() as client:
        try:
            res = await client.get(url)
            html = res.text
        except Exception as e:
            return {"error": f"Failed to fetch url: {str(e)}"}
            
    # Regex to find script tags with src containing cdn-like domains
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html)
    cdn_domains = ["cdnjs", "jsdelivr", "unpkg", "bootstrapcdn", "google-analytics"]
    
    for script_tag in scripts:
        if any(d in script_tag for d in cdn_domains):
            # Check if tag has integrity attribute
            # We must inspect the full tag
            tag_match = re.search(rf'<script[^>]+src=["\']{re.escape(script_tag)}["\'][^>]*>', html)
            has_sri = False
            if tag_match:
                tag_content = tag_match.group(0)
                if "integrity=" in tag_content:
                    has_sri = True
            if not has_sri:
                missing_sri_count += 1
            cdn_resources.append({
                "url": script_tag,
                "has_sri": has_sri,
                "tag_type": "script"
            })
            
    vulnerable = missing_sri_count > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Missing Subresource Integrity (SRI) on CDN Resources",
            vulnerability_type="Missing SRI",
            owasp_category="A03:2025 - Software Supply Chain Failures",
            severity="Low",
            url=url,
            description="CDN scripts are loaded without integrity hashes, allowing potential code injection.",
            evidence=str(cdn_resources)
        )

    return {
        "cdn_resources": cdn_resources,
        "missing_sri_count": missing_sri_count,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def check_dependency_confusion(domain: str, target_id: int = None) -> dict:
    """Checks if internal package names are published on npm public registry."""
    # We query registry.npmjs.org for target packages to check if they are public.
    packages_checked = []
    vulnerable = []
    
    # We will simulate with some mock checks for domain internal naming convention
    # e.g., if company name is target, they might have @target/internal-auth
    prefix = tldextract.extract(domain).domain
    test_packages = [f"@{prefix}/auth", f"@{prefix}/core", f"@{prefix}/utils"]
    
    async with get_client() as client:
        for pkg in test_packages:
            await delay()
            try:
                res = await client.get(f"https://registry.npmjs.org/{pkg}")
                # If package does not exist (404), it might be vulnerable to registration
                if res.status_code == 404:
                    vulnerable.append({
                        "name": pkg,
                        "status": "Available on npm public registry - potential dependency confusion"
                    })
                packages_checked.append(pkg)
            except Exception as e:
                logger.debug("Dependency confusion check failed for %s: %s", pkg, e)
                
    vuln = len(vulnerable) > 0
    if vuln and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Potential Dependency Confusion Risk",
            vulnerability_type="Dependency Confusion",
            owasp_category="A03:2025 - Software Supply Chain Failures",
            severity="High",
            url=domain,
            description="Internal scoped package namespace does not exist on public npm registry, enabling potential registration.",
            evidence=str(vulnerable)
        )

    return {
        "packages_checked": packages_checked,
        "vulnerable": vulnerable,
        "risk": "High" if vuln else "None"
    }
