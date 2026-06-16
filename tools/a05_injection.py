import re
import asyncio
import time as _time
import logging
from mcp_instance import mcp
from tools.db import save_finding, is_in_scope
from tools.http_utils import get_client, delay

logger = logging.getLogger("agy")

@mcp.tool()
async def sqli_test(url: str, params: dict, method: str = "GET", target_id: int = None) -> dict:
    """Tests specified parameters for SQL Injection vulnerabilities."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        {"payload": "' OR '1'='1", "type": "Boolean"},
        {"payload": "1' ORDER BY 1--", "type": "Error"},
        {"payload": "' AND SLEEP(3)--", "type": "Time-MySQL"},
        {"payload": "'; WAITFOR DELAY '0:0:3'--", "type": "Time-MSSQL"},
        {"payload": "1 UNION SELECT NULL, NULL--", "type": "Union"}
    ]
    vulnerable = False
    vulnerable_params = []
    
    async with get_client() as client:
        for p_name, p_val in params.items():
            for p in payloads:
                test_params = params.copy()
                test_params[p_name] = f"{p_val}{p['payload']}"
                
                try:
                    await delay()
                    if method.upper() == "GET":
                        start = _time.monotonic()
                        res = await client.get(url, params=test_params)
                        elapsed = _time.monotonic() - start
                    else:
                        start = _time.monotonic()
                        res = await client.post(url, data=test_params)
                        elapsed = _time.monotonic() - start
                        
                    body = res.text.lower()
                    
                    # 1. Error SQL check
                    errors = ["sql syntax", "mysql_fetch", "ora-00933", "sqlite3.operationalerror", "postgre"]
                    evidence = ""
                    found = False
                    for err in errors:
                        if err in body:
                            evidence = f"Database error encountered: {err}"
                            found = True
                            
                    # 2. Time based SQL check (types: Time-MySQL, Time-MSSQL)
                    if p["type"].startswith("Time") and elapsed >= 3.0:
                        evidence = f"Time-based response delay: {elapsed:.2f}s"
                        found = True
                        
                    if found:
                        vulnerable = True
                        vulnerable_params.append({
                            "param": p_name,
                            "payload": p["payload"],
                            "type": p["type"],
                            "evidence": evidence
                        })
                        break
                except Exception as e:
                    logger.debug("SQLi test error for %s: %s", p_name, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="SQL Injection Vulnerability",
            vulnerability_type="SQL Injection",
            owasp_category="A05:2025 - Injection",
            severity="High",
            url=url,
            parameter=vulnerable_params[0]["param"],
            payload=vulnerable_params[0]["payload"],
            description="Input is appended directly into an SQL query without validation.",
            evidence=str(vulnerable_params)
        )

    return {
        "vulnerable": vulnerable,
        "vulnerable_params": vulnerable_params,
        "db_type": "Unknown"
    }

@mcp.tool()
async def xss_test(url: str, params: dict, method: str = "GET", target_id: int = None) -> dict:
    """Tests specified parameters for Reflected XSS vulnerabilities."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)"
    ]
    vulnerable = False
    vulnerable_params = []
    
    async with get_client() as client:
        for p_name, p_val in params.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[p_name] = payload
                
                try:
                    await delay()
                    if method.upper() == "GET":
                        res = await client.get(url, params=test_params)
                    else:
                        res = await client.post(url, data=test_params)
                        
                    if payload in res.text:
                        vulnerable = True
                        vulnerable_params.append({
                            "param": p_name,
                            "payload": payload,
                            "reflected": True,
                            "context": "HTML Body"
                        })
                        break
                except Exception as e:
                    logger.debug("XSS test error for %s: %s", p_name, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Reflected XSS Vulnerability",
            vulnerability_type="Cross-Site Scripting (XSS)",
            owasp_category="A05:2025 - Injection",
            severity="High",
            url=url,
            parameter=vulnerable_params[0]["param"],
            payload=vulnerable_params[0]["payload"],
            description="User input is reflected in response without sanitization.",
            evidence=str(vulnerable_params)
        )

    return {
        "vulnerable": vulnerable,
        "vulnerable_params": vulnerable_params,
        "xss_type": "Reflected XSS"
    }

@mcp.tool()
async def command_injection_test(url: str, params: dict, method: str = "GET", target_id: int = None) -> dict:
    """Tests parameters for OS Command Injection."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        "; id",
        "| id",
        "&& id",
        "|| id",
        "; whoami",
        "& sleep 5"
    ]
    vulnerable = False
    vulnerable_params = []
    
    async with get_client() as client:
        for p_name, p_val in params.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[p_name] = f"{p_val}{payload}"
                
                try:
                    await delay()
                    start = _time.monotonic()
                    if method.upper() == "GET":
                        res = await client.get(url, params=test_params)
                    else:
                        res = await client.post(url, data=test_params)
                    elapsed = _time.monotonic() - start
                    
                    body = res.text.lower()
                    evidence = ""
                    found = False
                    if any(indicator in body for indicator in ["uid=", "groups=", "root:", "www-data"]):
                        evidence = "Command output detected in response"
                        found = True
                    elif "sleep" in payload and elapsed >= 5.0:
                        evidence = f"Response delayed by {elapsed:.2f}s"
                        found = True

                    if found:
                        vulnerable = True
                        vulnerable_params.append({
                            "param": p_name,
                            "payload": payload,
                            "evidence": evidence
                        })
                        break
                except Exception as e:
                    logger.debug("Command injection test error for %s: %s", p_name, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Command Injection Vulnerability",
            vulnerability_type="OS Command Injection",
            owasp_category="A05:2025 - Injection",
            severity="Critical",
            url=url,
            parameter=vulnerable_params[0]["param"],
            payload=vulnerable_params[0]["payload"],
            description="User input allows execution of arbitrary operating system commands.",
            evidence=str(vulnerable_params)
        )

    return {
        "vulnerable": vulnerable,
        "vulnerable_params": vulnerable_params,
        "severity": "Critical" if vulnerable else "None"
    }

@mcp.tool()
async def ssrf_test(url: str, params: dict, ssrf_payload: str = None, method: str = "GET", target_id: int = None) -> dict:
    """Tests parameters for Server-Side Request Forgery."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:80/",
        "http://127.0.0.1/",
        "file:///etc/passwd"
    ]
    if ssrf_payload:
        payloads = [ssrf_payload]
        
    vulnerable = False
    vulnerable_params = []
    
    async with get_client() as client:
        for p_name, p_val in params.items():
            for p in payloads:
                test_params = params.copy()
                test_params[p_name] = p
                
                try:
                    await delay()
                    if method.upper() == "GET":
                        res = await client.get(url, params=test_params)
                    else:
                        res = await client.post(url, data=test_params)
                        
                    body = res.text
                    evidence = ""
                    if "AMI-ID" in body.upper() or "root:x:" in body or "local-ipv4" in body:
                        evidence = "Internal server metadata or passwd file reflected"
                        vulnerable = True
                        
                    if vulnerable:
                        vulnerable_params.append({
                            "param": p_name,
                            "payload": p,
                            "evidence": evidence
                        })
                        break
                except Exception as e:
                    logger.debug("SSRF test error for %s: %s", p_name, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="SSRF Vulnerability",
            vulnerability_type="Server-Side Request Forgery (SSRF)",
            owasp_category="A05:2025 - Injection",
            severity="High",
            url=url,
            parameter=vulnerable_params[0]["param"],
            payload=vulnerable_params[0]["payload"],
            description="The server fetches remote or local resources specified by the user input.",
            evidence=str(vulnerable_params)
        )

    return {
        "vulnerable": vulnerable,
        "vulnerable_params": vulnerable_params,
        "severity": "High" if vulnerable else "None"
    }

@mcp.tool()
async def ssti_test(url: str, params: dict, method: str = "GET", target_id: int = None) -> dict:
    """Tests parameters for Server-Side Template Injection."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        {"payload": "{{7*7}}", "expected": "49"},
        {"payload": "${7*7}", "expected": "49"},
        {"payload": "<%= 7*7 %>", "expected": "49"}
    ]
    vulnerable = False
    vulnerable_params = []
    engine = "Unknown"
    
    async with get_client() as client:
        for p_name, p_val in params.items():
            for p in payloads:
                test_params = params.copy()
                test_params[p_name] = p["payload"]
                
                try:
                    await delay()
                    if method.upper() == "GET":
                        res = await client.get(url, params=test_params)
                    else:
                        res = await client.post(url, data=test_params)
                        
                    if p["expected"] in res.text and p["payload"] not in res.text:
                        vulnerable = True
                        vulnerable_params.append({
                            "param": p_name,
                            "payload": p["payload"],
                            "output": p["expected"]
                        })
                        if "{{" in p["payload"]:
                            engine = "Jinja2/Twig"
                        else:
                            engine = "Java/FreeMarker"
                        break
                except Exception as e:
                    logger.debug("SSTI test error for %s: %s", p_name, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="SSTI Vulnerability",
            vulnerability_type="Server-Side Template Injection (SSTI)",
            owasp_category="A05:2025 - Injection",
            severity="High",
            url=url,
            parameter=vulnerable_params[0]["param"],
            payload=vulnerable_params[0]["payload"],
            description=f"Server-Side Template Injection ({engine}) detected.",
            evidence=str(vulnerable_params)
        )

    return {
        "vulnerable": vulnerable,
        "template_engine": engine,
        "vulnerable_params": vulnerable_params,
        "severity": "High" if vulnerable else "None"
    }

@mcp.tool()
async def xxe_test(url: str, content_type: str = "application/xml", target_id: int = None) -> dict:
    """Tests if XML parses handles external entities securely (XXE)."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    # Simple XML body post to verify XXE
    payload = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    vulnerable = False
    evidence = ""
    
    async with get_client() as client:
        try:
            res = await client.post(url, content=payload, headers={"Content-Type": content_type})
            if "root:x:" in res.text:
                vulnerable = True
                evidence = "Passwd file contents returned in response body"
        except Exception as e:
            logger.debug("XXE test error: %s", e)
            
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="XML External Entity Injection (XXE)",
            vulnerability_type="XXE",
            owasp_category="A05:2025 - Injection",
            severity="High",
            url=url,
            description="Application processes XML documents referencing external system entities.",
            evidence=evidence
        )

    return {
        "vulnerable": vulnerable,
        "xxe_type": "Reflected XXE" if vulnerable else "None",
        "evidence": evidence,
        "severity": "High" if vulnerable else "None"
    }

@mcp.tool()
async def host_header_injection_test(url: str, target_id: int = None) -> dict:
    """Tests if Host header injection can cause redirection or caching issues."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    vulnerable = False
    reflected_in = []
    
    async with get_client() as client:
        try:
            # Send evil.com host header
            res = await client.get(url, headers={"Host": "evil.com"})
            if "evil.com" in res.text or res.headers.get("Location", "").startswith("https://evil.com"):
                vulnerable = True
                reflected_in.append("Response Body/Header Redirect")
        except Exception as e:
            logger.debug("Host header injection test error: %s", e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Host Header Injection",
            vulnerability_type="Host Header Injection",
            owasp_category="A05:2025 - Injection",
            severity="Medium",
            url=url,
            description="The server trusts and reflects the client provided Host header.",
            evidence=str(reflected_in)
        )

    return {
        "vulnerable": vulnerable,
        "reflected_in": reflected_in,
        "attack_vector": "Host Header",
        "payloads_tested": ["evil.com"]
    }

@mcp.tool()
async def crlf_injection_test(url: str, params: dict = None, target_id: int = None) -> dict:
    """Checks for CRLF injection leading to header injection or response splitting."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    payloads = [
        "%0d%0aSet-Cookie:crlfinjection=1",
        "\r\nSet-Cookie:crlfinjection=1"
    ]
    vulnerable = False
    vulnerable_vectors = []
    
    async with get_client() as client:
        # Check path CRLF injection first
        for p in payloads:
            target = f"{url.rstrip('/')}/{p}"
            try:
                await delay()
                res = await client.get(target)
                if res.headers.get("Set-Cookie") and "crlfinjection" in res.headers.get("Set-Cookie"):
                    vulnerable = True
                    vulnerable_vectors.append("Path Injection")
                    break
            except Exception as e:
                logger.debug("CRLF injection test error: %s", e)
                
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="CRLF Injection",
            vulnerability_type="CRLF Injection",
            owasp_category="A05:2025 - Injection",
            severity="Medium",
            url=url,
            description="Carriage Return Line Feed sequences can be injected into HTTP headers.",
            evidence=str(vulnerable_vectors)
        )

    return {
        "vulnerable": vulnerable,
        "vulnerable_vectors": vulnerable_vectors,
        "injected_headers": ["Set-Cookie: crlfinjection=1"],
        "severity": "Medium" if vulnerable else "None"
    }

@mcp.tool()
async def nosql_injection_test(url: str, params: dict, target_id: int = None) -> dict:
    """Tests parameters for NoSQL (MongoDB) Injection."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    vulnerable = False
    vulnerable_params = []
    
    # NoSQL operator injection payloads
    nosql_payloads = [
        {"payload": {"$ne": ""}, "type": "Operator Injection"},
        {"payload": {"$gt": ""}, "type": "Operator Injection"},
        {"payload": {"$regex": ".*"}, "type": "Regex Injection"},
    ]
    # String-based NoSQL payloads
    string_payloads = [
        {"payload": "' || '1'=='1", "type": "String OR"},
        {"payload": "{$gt: \"\"}", "type": "JSON Operator"},
    ]
    
    async with get_client() as client:
        # Establish baseline lengths to avoid false positives
        baseline_post_len = None
        try:
            res_base_post = await client.post(url, json=params)
            baseline_post_len = len(res_base_post.text)
        except Exception:
            pass

        baseline_get_len = None
        try:
            res_base_get = await client.get(url, params=params)
            baseline_get_len = len(res_base_get.text)
        except Exception:
            pass

        for p_name, p_val in params.items():
            # Test operator-based injection via JSON body
            for np in nosql_payloads:
                test_data = params.copy()
                test_data[p_name] = np["payload"]
                try:
                    await delay()
                    res = await client.post(url, json=test_data)
                    significant_diff = baseline_post_len is not None and abs(len(res.text) - baseline_post_len) > 200
                    if res.status_code == 200 and significant_diff:
                        vulnerable = True
                        vulnerable_params.append({
                            "param": p_name,
                            "payload": str(np["payload"]),
                            "type": np["type"],
                            "evidence": f"HTTP {res.status_code}, diff from baseline: {len(res.text) - baseline_post_len} bytes"
                        })
                        break
                except Exception as e:
                    logger.debug("NoSQL test error for %s: %s", p_name, e)
            
            # Test string-based injection via query params
            for sp in string_payloads:
                test_params = params.copy()
                test_params[p_name] = sp["payload"]
                try:
                    await delay()
                    res = await client.get(url, params=test_params)
                    body = res.text.lower()
                    significant_diff = baseline_get_len is not None and abs(len(res.text) - baseline_get_len) > 200
                    if res.status_code == 200 and "error" not in body and significant_diff:
                        vulnerable = True
                        vulnerable_params.append({
                            "param": p_name,
                            "payload": sp["payload"],
                            "type": sp["type"],
                            "evidence": f"HTTP {res.status_code}, diff from baseline: {len(res.text) - baseline_get_len} bytes"
                        })
                        break
                except Exception as e:
                    logger.debug("NoSQL string test error for %s: %s", p_name, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="NoSQL Injection Vulnerability",
            vulnerability_type="NoSQL Injection",
            owasp_category="A05:2025 - Injection",
            severity="High",
            url=url,
            parameter=vulnerable_params[0]["param"],
            payload=vulnerable_params[0]["payload"],
            description="NoSQL operator or string injection detected — input is passed into database queries without sanitization.",
            evidence=str(vulnerable_params)
        )

    return {
        "vulnerable": vulnerable,
        "vulnerable_params": vulnerable_params,
        "db_type": "NoSQL (MongoDB)",
        "evidence": str(vulnerable_params) if vulnerable else "NoSQL Injection not detected."
    }
