import re
import asyncio
from mcp_instance import mcp
from config import DEFAULT_TIMEOUT
from tools.db import save_finding, is_in_scope
from tools.http_utils import secure_request, get_client, delay, tls_connect
import logging
logger = logging.getLogger("agy")

@mcp.tool()
async def security_headers_check(url: str, target_id: int) -> dict:
    """Check for missing/misconfigured security headers."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}

    headers_to_check = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "Referrer-Policy": "Referrer leaks protection",
        "Permissions-Policy": "Feature control",
        "X-XSS-Protection": "Legacy XSS protection"
    }
    missing = []
    present = {}

    # FIX BUG-01: initialize before block so it's always defined
    resp_headers = {}
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url, target_id=target_id)
            resp_headers = res.headers
        except Exception as e:
            return {"error": f"Failed to connect: {str(e)}"}

    for h, desc in headers_to_check.items():
        val = resp_headers.get(h)
        if val:
            present[h] = val
        else:
            missing.append(h)

    vulnerable = len(missing) > 0
    score = int((len(present) / len(headers_to_check)) * 100)

    # Check server banners
    server = resp_headers.get("Server")
    powered_by = resp_headers.get("X-Powered-By")
    disclosure = []
    if server:
        disclosure.append(f"Server: {server}")
    if powered_by:
        disclosure.append(f"X-Powered-By: {powered_by}")

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Missing Security Headers",
            vulnerability_type="Security Misconfiguration",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="Low",
            url=url,
            description=f"Missing security headers: {', '.join(missing)}. Exposure: {', '.join(disclosure)}",
            evidence=f"Present headers: {present}\nMissing: {missing}"
        )

    return {
        "score": score,
        "missing": missing,
        "present": present,
        "disclosure": disclosure,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def tls_ssl_check(hostname: str, target_id: int, port: int = 443) -> dict:
    """Analyze TLS/SSL settings for weaknesses."""
    # FIX BUG-MEDIUM-2: tambah scope check yang sebelumnya hilang
    if not is_in_scope(target_id, f"https://{hostname}:{port}"):
        return {"error": f"Host {hostname} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}

    issues = []
    vulnerable = False

    # FIX BUG-02: initialize before try so return dict never hits UnboundLocalError
    version = "Unknown"
    cipher  = None
    cert    = None

    try:
        # FIX BUG-MEDIUM-1: gunakan asyncio.to_thread() agar tidak blocking event loop
        version, cipher, cert = await asyncio.to_thread(tls_connect, hostname, port)

        # Check for weak protocols
        if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            issues.append(f"Weak TLS/SSL version supported: {version}")
            vulnerable = True

        # Check for weak ciphers
        if cipher and any(w in cipher[0].upper() for w in ["RC4", "3DES", "DES", "MD5", "NULL"]):
            issues.append(f"Weak cipher suite supported: {cipher[0]}")
            vulnerable = True
    except Exception as e:
        issues.append(f"TLS connection failed/untrusted certificate: {str(e)}")
        vulnerable = True

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Weak TLS/SSL Configuration",
            vulnerability_type="TLS Misconfiguration",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="Medium",
            url=f"https://{hostname}:{port}",
            description=f"Weak TLS/SSL protocols, weak ciphers, or certificate trust issues were detected on {hostname}.",
            evidence=str(issues)
        )

    return {
        "vulnerable": vulnerable,
        "protocol_version": version,
        "cipher": str(cipher),
        "issues": issues
    }

@mcp.tool()
async def exposed_files_check(base_url: str, target_id: int) -> dict:
    """Checks for exposed configuration files and sensitive directories."""
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}

    files = [
        "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php", "/web.config",
        "/.htaccess", "/robots.txt", "/sitemap.xml", "/backup.zip", "/database.sql",
        "/.DS_Store", "/phpinfo.php", "/package.json", "/composer.json"
    ]
    exposed = []
    async with get_client(follow_redirects=False) as client:
        for f in files:
            await delay()
            target = base_url.rstrip("/") + f
            try:
                res = await secure_request(client, "GET", target, target_id=target_id)
                if res.status_code == 200:
                    snippet = res.text[:200]
                    # Check for pattern matches for .env
                    is_sensitive = False
                    if ".env" in f and any(k in res.text for k in ["DB_", "API_", "KEY", "SECRET", "PASSWORD"]):
                        is_sensitive = True
                    elif ".git/config" in f and ("[core]" in res.text or "repositoryformatversion" in res.text):
                        is_sensitive = True
                    elif "wp-config" in f and ("DB_NAME" in res.text or "define(" in res.text):
                        is_sensitive = True
                    elif "phpinfo.php" in f and ("phpinfo()" in res.text or "PHP Version" in res.text):
                        is_sensitive = True
                        
                    exposed.append({
                        "path": f,
                        "status_code": res.status_code,
                        "sensitive": is_sensitive,
                        "snippet": snippet
                    })
            except Exception as e:
                logger.debug("Exposed file check failed for %s: %s", f, e)
                
    critical_count = sum(1 for e in exposed if e["sensitive"])
    vulnerable = critical_count > 0
    
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Exposed Sensitive Files",
            vulnerability_type="Information Disclosure",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="High" if critical_count > 0 else "Low",
            url=base_url,
            description="Sensitive or configuration files are publicly accessible at the target.",
            evidence=str(exposed)
        )

    return {
        "exposed_files": exposed,
        "critical_count": critical_count,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def cookie_security_check(url: str, target_id: int) -> dict:
    """Checks Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}

    cookies_issues = []
    vulnerable = False
    
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url, target_id=target_id)
            cookies = res.headers.get_list("Set-Cookie")
        except Exception as e:
            return {"error": f"Connection failed: {str(e)}"}
            
    for cookie_str in cookies:
        name = cookie_str.split("=")[0]
        issues = []
        if "secure" not in cookie_str.lower():
            issues.append("Missing Secure flag")
        if "httponly" not in cookie_str.lower():
            issues.append("Missing HttpOnly flag")
        if "samesite" not in cookie_str.lower():
            issues.append("Missing SameSite attribute")
            
        if issues:
            vulnerable = True
            cookies_issues.append({
                "cookie": name,
                "issues": issues,
                "raw": cookie_str
            })

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Insecure Cookie Attributes",
            vulnerability_type="Cookie Misconfiguration",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="Medium",
            url=url,
            description="One or more cookies are transmitted without HttpOnly, Secure, or SameSite flags.",
            evidence=str(cookies_issues)
        )

    return {
        "vulnerable": vulnerable,
        "vulnerable_cookies": cookies_issues
    }

@mcp.tool()
async def directory_listing_check(url: str, target_id: int, paths: list = None) -> dict:
    """Checks if directory listing (indexing) is enabled on common paths."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}

    if not paths:
        paths = ["/", "/images/", "/static/", "/uploads/", "/files/", "/assets/", "/backup/", "/logs/"]
        
    enabled_paths = []
    vulnerable = False
    
    async with get_client(follow_redirects=True) as client:
        for p in paths:
            await delay()
            target = url.rstrip("/") + p
            try:
                res = await secure_request(client, "GET", target, target_id=target_id)
                body = res.text
                if res.status_code == 200 and any(k in body for k in ["Index of /", "Directory listing for", "Parent Directory"]):
                    enabled_paths.append(p)
                    vulnerable = True
            except Exception as e:
                logger.debug("Directory listing check failed for %s: %s", p, e)

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Directory Listing Enabled",
            vulnerability_type="Directory Listing",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="Medium",
            url=url,
            description=f"Directory listing is enabled on: {', '.join(enabled_paths)}",
            evidence=str(enabled_paths)
        )

    return {
        "vulnerable": vulnerable,
        "listing_enabled": enabled_paths,
        "total_checked": len(paths)
    }

@mcp.tool()
async def default_credentials_check(url: str, target_id: int, service_type: str = "web") -> dict:
    """Checks for default credentials on administrative panels."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}

    creds = {
        "web": [("admin", "admin"), ("admin", "password"), ("admin", "123456")],
        "wordpress": [("admin", "admin"), ("admin", "password")],
        "phpmyadmin": [("root", ""), ("root", "root"), ("admin", "admin")],
        "jenkins": [("admin", "admin"), ("admin", "password")]
    }
    
    test_creds = creds.get(service_type, creds["web"])
    successful = []
    vulnerable = False
    
    # We will simulate form POST attempts for mock testing or try basic auth
    async with get_client() as client:
        for user, pwd in test_creds:
            await delay()
            try:
                # Try Basic Auth first
                res = await secure_request(client, "GET", url, target_id=target_id, auth=(user, pwd))
                if res.status_code in [200, 302] and "unauthorized" not in res.text.lower() and "login" not in res.text.lower():
                    successful.append((user, pwd))
                    vulnerable = True
            except Exception as e:
                logger.debug("Default credentials check failed: %s", e)

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Default Credentials Vulnerability",
            vulnerability_type="Default Credentials",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="Critical",
            url=url,
            description=f"Admin panel allowed access with default credentials: {successful}",
            evidence=str(successful)
        )

    return {
        "vulnerable": vulnerable,
        "successful_creds": successful,
        "tried_count": len(test_creds)
    }

@mcp.tool()
async def subdomain_takeover_check(domain: str, target_id: int) -> dict:
    """Checks for potential subdomain takeover via dangling CNAME pointers."""
    takeover_fingerprints = {
        "GitHub Pages": "There isn't a GitHub Pages site here",
        "Heroku": "No such app",
        "Netlify": "Not Found - Request ID",
        "AWS S3": "NoSuchBucket",
        "Azure": "This Azure website is not available",
        "Shopify": "Sorry, this shop is currently unavailable"
    }
    vulnerable = False
    matched = ""
    cname = ""
    
    try:
        import dns.resolver
    except ImportError:
        return {
            "vulnerable": False,
            "error": "dns.resolver (dnspython) library is not installed. Subdomain takeover check could not run.",
            "cname": "",
            "fingerprint_matched": ""
        }

    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target)
    except Exception as e:
        logger.debug("CNAME resolution failed for %s: %s", domain, e)
        
    if cname:
        async with get_client() as client:
            try:
                res = await secure_request(client, "GET", f"http://{domain}", target_id=target_id)
                body = res.text
                for service, fp in takeover_fingerprints.items():
                    if fp in body:
                        vulnerable = True
                        matched = service
                        break
            except Exception as e:
                logger.debug("Subdomain takeover check failed for %s: %s", domain, e)

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Potential Subdomain Takeover",
            vulnerability_type="Subdomain Takeover",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="High",
            url=f"http://{domain}",
            description=f"Dangling CNAME pointer ({cname}) detected for domain {domain}.",
            evidence=f"CNAME: {cname}\nFingerprint matched: {matched}"
        )

    return {
        "vulnerable": vulnerable,
        "cname": cname,
        "fingerprint_matched": matched
    }

@mcp.tool()
async def admin_panel_discovery(base_url: str, target_id: int) -> dict:
    """Scans for administrative control panels."""
    if not is_in_scope(target_id, base_url):
        return {"error": f"URL {base_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}

    admin_paths = [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/cms", "/manager", "/panel", "/cpanel", "/webadmin"
    ]
    found = []
    
    async with get_client(follow_redirects=False) as client:
        for path in admin_paths:
            await delay()
            target = base_url.rstrip("/") + path
            try:
                res = await secure_request(client, "GET", target, target_id=target_id)
                if res.status_code in [200, 301, 302, 401, 403]:
                    has_form = "password" in res.text.lower() or "login" in res.text.lower()
                    found.append({
                        "url": target,
                        "status": res.status_code,
                        "has_login_form": has_form
                    })
            except Exception as e:
                logger.debug("Admin panel check failed for %s: %s", path, e)

    vulnerable = len(found) > 0
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Exposed Admin Panel",
            vulnerability_type="Information Disclosure",
            owasp_category="A02:2025 - Security Misconfiguration",
            severity="Medium",
            url=base_url,
            description="Exposed administrator or login panel discovered.",
            evidence=str(found)
        )

    return {
        "vulnerable": vulnerable,
        "found_panels": found,
        "count": len(found)
    }
