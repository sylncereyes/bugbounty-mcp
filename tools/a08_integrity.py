import httpx
import base64
import re
from mcp_instance import mcp
from tools.db import save_finding, is_in_scope
from tools.http_utils import secure_request, get_client, delay
import logging
logger = logging.getLogger("agy")

@mcp.tool()
async def check_insecure_deserialization(url: str, target_id: int, params: dict = None)) ->:
    """Checks parameters or cookies for signs of serialized objects (PHP, Python pickle, Java, etc.)."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    detected_type = "None"
    serialized_found = []
    
    # Signatures:
    # PHP: O:8:"stdClass"
    # Python pickle base64 starts with gASV
    # Java Serialization starts with rO0AB
    
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url)
            cookies = res.headers.get_list("Set-Cookie")
            for c in cookies:
                cookie_val = c.split(";")[0].split("=", 1)
                if len(cookie_val) == 2:
                    val = cookie_val[1]
                    if val.startswith("rO0AB"):
                        detected_type = "Java Serialization"
                        serialized_found.append({"location": f"Cookie {cookie_val[0]}", "type": detected_type})
                    elif val.startswith("gASV"):
                        detected_type = "Python Pickle"
                        serialized_found.append({"location": f"Cookie {cookie_val[0]}", "type": detected_type})
                    else:
                        # Try decoding base64
                        try:
                            dec = base64.b64decode(val).decode("utf-8", errors="ignore")
                            if re.search(r"[aO]:\d+:", dec):
                                detected_type = "PHP Serialization"
                                serialized_found.append({"location": f"Cookie {cookie_val[0]}", "type": detected_type})
                        except Exception as e:
                            logger.debug("Base64 decode error for cookie: %s", e)
        except Exception as e:
            logger.debug("Error checking deserialization at %s: %s", url, e)

    vulnerable = len(serialized_found) > 0
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Insecure Deserialization Indicator Found",
            vulnerability_type="Insecure Deserialization",
            owasp_category="A08:2025 - Software and Data Integrity Failures",
            severity="High",
            url=url,
            description=f"Exposed serial data structure ({detected_type}) detected in parameters/cookies.",
            evidence=str(serialized_found)
        )

    return {
        "detected_type": detected_type,
        "potentially_vulnerable": vulnerable,
        "serialized_objects_found": serialized_found,
        "evidence": str(serialized_found)
    }

@mcp.tool()
async def cache_poisoning_test(url: str, target_id: int)) ->:
    """Checks for cache poisoning potential via unkeyed header reflection."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    vulnerable = False
    poisonable_headers = []
    
    headers_to_try = {
        "X-Forwarded-Host": "poisoned-domain.com",
        "X-Original-URL": "/poisoned-path"
    }
    
    async with get_client() as client:
        for h, val in headers_to_try.items():
            try:
                res = await secure_request(client, "GET", url, headers={h: val})
                if val in res.text or val in str(res.headers):
                    vulnerable = True
                    poisonable_headers.append(h)
            except Exception as e:
                logger.debug("Error testing cache poisoning header %s at %s: %s", h, url, e)
            await delay()

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Potential Web Cache Poisoning / Reflection",
            vulnerability_type="Cache Poisoning",
            owasp_category="A08:2025 - Software and Data Integrity Failures",
            severity="Medium",
            url=url,
            description="The web server reflects unkeyed HTTP header inputs in cached responses.",
            evidence=f"Reflected headers: {poisonable_headers}"
        )

    return {
        "vulnerable": vulnerable,
        "cache_headers": {},
        "poisonable_headers": poisonable_headers,
        "deception_vulnerable": False
    }

@mcp.tool()
async def parameter_tampering_test(url: str, params: dict, target_id: int, method: str = "GET")) ->:
    """Tampering with parameters (e.g. changing role, price, or ID) to check for server side validation."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    tampered = []
    vulnerable = False
    
    async with get_client() as client:
        for p_name, p_val in params.items():
            # Tamper numeric values
            if str(p_val).isdigit():
                tampered_val = int(p_val) + 1
            elif p_val in ["user", "member", "guest"]:
                tampered_val = "admin"
            else:
                tampered_val = f"{p_val}_tampered"
                
            test_params = params.copy()
            test_params[p_name] = tampered_val
            
            try:
                if method.upper() == "GET":
                    res = await secure_request(client, "GET", url, params=test_params)
                else:
                    res = await secure_request(client, "POST", url, data=test_params)
                    
                # If we get HTTP 200 without error indication, indicate tampered parameter accepted
                if res.status_code == 200 and "error" not in res.text.lower() and "unauthorized" not in res.text.lower():
                    vulnerable = True
                    tampered.append({
                        "param": p_name,
                        "original": p_val,
                        "modified": tampered_val,
                        "result": "Accepted with HTTP 200"
                    })
            except Exception as e:
                logger.debug("Error tampering param %s at %s: %s", p_name, url, e)
            await delay()

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Parameter Tampering Vulnerability",
            vulnerability_type="Parameter Tampering",
            owasp_category="A08:2025 - Software and Data Integrity Failures",
            severity="High",
            url=url,
            description="The backend does not validate inputs or integrity on critical parameter values.",
            evidence=str(tampered)
        )

    return {
        "vulnerable": vulnerable,
        "tampered_params": tampered,
        "findings": tampered
    }

@mcp.tool()
async def check_saml_vulnerabilities(url: str, target_id: int, saml_response: str = None)) ->:
    """Performs integrity check on SAML assertion signatures for XML Signature Wrapping (XSW) or weak sigs."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    
    import xml.etree.ElementTree as ET

    issues = []
    xsw_vulnerable = False
    signature_present = True
    
    if not saml_response:
        return {
            "signature_present": False,
            "encrypted": False,
            "xsw_vulnerable": False,
            "issues": ["No SAML response provided for testing"],
            "vulnerable": False
        }

    try:
        decoded_xml = base64.b64decode(saml_response).decode('utf-8', errors='ignore')
        root = ET.fromstring(decoded_xml)
        
        signatures = root.findall(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        if not signatures:
            issues.append("SAML response is missing an XML Signature entirely")
            signature_present = False
        else:
            sig_methods = root.findall(".//{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")
            for sm in sig_methods:
                alg = sm.get("Algorithm", "")
                if "sha1" in alg.lower():
                    issues.append("SAML Signature algorithm uses weak SHA-1 hash")
            
            assertions = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
            if len(assertions) > 1:
                xsw_vulnerable = True
                issues.append("Multiple SAML Assertions detected in a single response, indicating potential XSW vulnerability")

    except Exception as e:
        issues.append(f"Failed to parse or analyze SAML XML: {str(e)}")
        signature_present = False

    vulnerable = len(issues) > 0 or xsw_vulnerable
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Weak SAML Configuration / XSW Vulnerability",
            vulnerability_type="SAML Integrity Failure",
            owasp_category="A08:2025 - Software and Data Integrity Failures",
            severity="High",
            url=url,
            description="The SAML response configuration has security flaws (e.g. missing signature, weak algorithm, or multiple assertions indicating XSW).",
            evidence=str(issues)
        )

    return {
        "signature_present": signature_present,
        "xsw_vulnerable": xsw_vulnerable,
        "issues": issues,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def mass_assignment_test(url: str, target_id: int, method: str = "POST", data: dict = None, extra_fields: dict = None)) ->:
    """Checks if adding privileged attributes (like isAdmin, role) updates server data."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    test_fields = extra_fields or {"isAdmin": True, "role": "admin", "is_admin": 1}
    vulnerable = False
    accepted = []
    
    if not data:
        data = {"username": "test_register", "email": "test@example.com"}
        
    merged_data = data.copy()
    merged_data.update(test_fields)
    
    async with get_client() as client:
        try:
            if method.upper() == "POST":
                res = await secure_request(client, "POST", url, json=merged_data)
            else:
                res = await secure_request(client, "PUT", url, json=merged_data)
                
            body = res.text
            # If privileged fields are reflected back as true/admin, indicate potential mass assignment
            for k in test_fields.keys():
                if f'"{k}":' in body or f"'{k}':" in body:
                    vulnerable = True
                    accepted.append(k)
        except Exception as e:
            logger.debug("Error testing mass assignment at %s: %s", url, e)

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Mass Assignment Vulnerability",
            vulnerability_type="Mass Assignment",
            owasp_category="A08:2025 - Software and Data Integrity Failures",
            severity="High",
            url=url,
            description="The endpoint accepts administrative parameters without server-side validation.",
            evidence=str(accepted)
        )

    return {
        "vulnerable": vulnerable,
        "accepted_fields": accepted,
        "response_diff": {},
        "severity": "High" if vulnerable else "None"
    }

@mcp.tool()
async def http_request_smuggling_check(url: str, target_id: int)) ->:
    """Probes for HTTP request smuggling indicators via conflicting headers.
    
    LIMITATION: This test uses httpx which normalizes HTTP headers. True CL.TE/TE.CL
    smuggling detection requires raw socket connections. Results should be verified
    with dedicated tools (Burp Suite, smuggler.py, or raw socket scripts)."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    potentially_vulnerable = False
    tests = []
    
    # Try sending CL.TE conflict
    headers = {
        "Transfer-Encoding": "chunked",
        "Content-Length": "4",
    }
    
    async with get_client() as client:
        try:
            res = await secure_request(client, "POST", url, headers=headers, content="0\r\n\r\n", follow_redirects=False)
            tests.append({"type": "CL.TE", "response": res.status_code, "timeout": False})
        except httpx.ReadTimeout:
            potentially_vulnerable = True
            tests.append({"type": "CL.TE", "response": None, "timeout": True})
        except Exception as e:
            tests.append({"type": "CL.TE", "error": str(e), "timeout": False})
            
    if potentially_vulnerable:
        save_finding(
            target_id=target_id,
            title="Potential HTTP Request Smuggling",
            vulnerability_type="HTTP Request Smuggling",
            owasp_category="A08:2025 - Software and Data Integrity Failures",
            severity="High",
            url=url,
            description="Conflicting Content-Length and Transfer-Encoding headers triggered request parser timeout, signaling potential Request Smuggling.",
            evidence=str(tests)
        )

    return {
        "potentially_vulnerable": potentially_vulnerable,
        "tests": tests,
        "limitation": "httpx normalizes Content-Length and Transfer-Encoding headers. True CL.TE/TE.CL detection requires raw socket connections (e.g., socket.socket or h11 library). This test can only detect timeout-based indicators.",
        "notes": "Verify manually using Burp Suite, smuggler.py, or raw socket scripts for definitive results."
    }
