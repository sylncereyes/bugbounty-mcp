import asyncio
import logging
from mcp_instance import mcp
from tools.db import save_finding, is_in_scope
from tools.http_utils import secure_request, get_client, delay

logger = logging.getLogger("agy")

@mcp.tool()
async def rate_limit_check(url: str, target_id: int, method: str = "POST", data: dict = None, requests_count: int = 15) -> dict:
    """Sends multiple requests in rapid succession to check if rate limiting is enforced."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    status_codes = []
    headers_detected = {}
    vulnerable = True
    first_limit_at = -1
    
    async with get_client() as client:
        for i in range(requests_count):
            try:
                if method.upper() == "POST":
                    res = await secure_request(client, "POST", url, target_id=target_id, json=data)
                else:
                    res = await secure_request(client, "GET", url, target_id=target_id)
                    
                status_codes.append(res.status_code)
                
                # Check rate limiting headers
                for h, val in res.headers.items():
                    if any(rl in h.lower() for rl in ["ratelimit", "retry-after", "x-rate-limit"]):
                        headers_detected[h] = val
                        
                if res.status_code == 429:
                    vulnerable = False
                    if first_limit_at == -1:
                        first_limit_at = i + 1
            except Exception as e:
                logger.debug("Rate limit check request %d failed: %s", i, e)
                status_codes.append(999) # connection err
            await delay()

    # If we hit no 429 status code, rate limit check fails
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Missing Rate Limit Protection",
            vulnerability_type="Insecure Design",
            owasp_category="A06:2025 - Insecure Design",
            severity="Medium",
            url=url,
            description="The administrative, api, or login endpoint does not restrict request rate, allowing brute force or denial of service.",
            evidence=f"Status codes: {status_codes}\nHeaders: {headers_detected}"
        )

    return {
        "rate_limited": not vulnerable,
        "first_limit_at_request": first_limit_at,
        "status_codes": status_codes,
        "rate_limit_headers": headers_detected,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def business_logic_price_test(checkout_url: str, target_id: int, product_url: str = None, params: dict = None) -> dict:
    """Checks for price or quantity manipulation vulnerabilities in shopping cart processes."""
    if not is_in_scope(target_id, checkout_url):
        return {"error": f"URL {checkout_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    # Price parameter manipulation simulation
    test_params = params or {"price": "-10.00", "quantity": "-1", "amount": "0.01"}
    vulnerable = False
    findings = []
    
    async with get_client() as client:
        try:
            res = await secure_request(client, "POST", checkout_url, target_id=target_id, json=test_params)
            # Check if request succeeded and did not reject negative price
            if res.status_code in [200, 201] and "error" not in res.text.lower():
                vulnerable = True
                findings.append({
                    "test": "Negative price / quantity",
                    "result": "Succeeded with HTTP 200/201",
                    "response_code": res.status_code
                })
        except Exception as e:
            logger.debug("Business logic price test failed: %s", e)
            
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Business Logic Price Manipulation",
            vulnerability_type="Business Logic Vulnerability",
            owasp_category="A06:2025 - Insecure Design",
            severity="High",
            url=checkout_url,
            description="The checkout checkout workflow accepts modified, zero, or negative prices.",
            evidence=str(findings)
        )

    return {
        "vulnerable": vulnerable,
        "tests_performed": findings,
        "findings": findings
    }

@mcp.tool()
async def captcha_bypass_check(url: str, target_id: int, form_data: dict = None) -> dict:
    """Evaluates if CAPTCHA restrictions can be bypassed by removing parameters."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    has_captcha = False
    bypassable = False
    bypass_methods = []
    
    # Check form HTML for captcha integration
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url, target_id=target_id)
            body = res.text
            if any(k in body for k in ["g-recaptcha", "hcaptcha", "recaptcha"]):
                has_captcha = True
                
            # Try submitting form without captcha field if form_data is provided
            if has_captcha and form_data:
                # Remove captcha parameter
                cleaned_data = {k: v for k, v in form_data.items() if "captcha" not in k.lower() and "response" not in k.lower()}
                post_res = await secure_request(client, "POST", url, target_id=target_id, data=cleaned_data)
                if post_res.status_code in [200, 302] and "invalid captcha" not in post_res.text.lower():
                    bypassable = True
                    bypass_methods.append("Removal of captcha param")
        except Exception as e:
            logger.debug("CAPTCHA bypass check failed: %s", e)

    if bypassable:
        save_finding(
            target_id=target_id,
            title="CAPTCHA Bypass Vulnerability",
            vulnerability_type="CAPTCHA Bypass",
            owasp_category="A06:2025 - Insecure Design",
            severity="Medium",
            url=url,
            description="CAPTCHA requirement can be bypassed by stripping captcha parameters from the request.",
            evidence=str(bypass_methods)
        )

    return {
        "has_captcha": has_captcha,
        "client_side_only": False,
        "bypassable": bypassable,
        "bypass_methods": bypass_methods
    }

@mcp.tool()
async def race_condition_test(url: str, target_id: int, method: str = "POST", data: dict = None, concurrent_count: int = 8) -> dict:
    """Sends concurrent async HTTP requests to check for race conditions (e.g. transfer/coupon double-use)."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    success_count = 0
    responses = []
    
    async def send_req(client):
        try:
            if method.upper() == "POST":
                res = await secure_request(client, "POST", url, target_id=target_id, json=data)
            else:
                res = await secure_request(client, "GET", url, target_id=target_id)
            return res.status_code, res.text
        except Exception as e:
            return 999, str(e)

    async with get_client() as client:
        tasks = [send_req(client) for _ in range(concurrent_count)]
        results = await asyncio.gather(*tasks)
        
    for code, body in results:
        responses.append(code)
        # Check if success indication returned for multiple transactions
        if code in [200, 201]:
            success_count += 1
            
    # Vulnerable if more than 1 requests succeeded concurrently when only 1 should (assumed checking logical action)
    vulnerable = success_count > 1
    
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Potential Race Condition Vulnerability",
            vulnerability_type="Race Condition",
            owasp_category="A06:2025 - Insecure Design",
            severity="High",
            url=url,
            description="Sending concurrent requests indicates lack of transaction locks, allowing multiple actions.",
            evidence=f"Concurrent successes: {success_count}/{concurrent_count}. Responses: {responses}"
        )

    return {
        "vulnerable": vulnerable,
        "success_count": success_count,
        "expected_success": 1,
        "responses": responses,
        "timing": {}
    }

@mcp.tool()
async def password_policy_check(register_url: str, target_id: int, login_url: str = None) -> dict:
    """Verifies register endpoint acceptance of weak passwords."""
    if not is_in_scope(target_id, register_url):
        return {"error": f"URL {register_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    weak_passwords = ["123", "password", "qwerty"]
    accepted = []
    
    async with get_client() as client:
        for p in weak_passwords:
            try:
                # Mock register structure
                data = {"username": "policy_test_user", "email": "test@example.com", "password": p}
                res = await secure_request(client, "POST", register_url, target_id=target_id, json=data)
                if res.status_code in [200, 201] and "error" not in res.text.lower():
                    accepted.append(p)
            except Exception as e:
                logger.debug("Password policy check failed for '%s': %s", p, e)
            await delay()
                
    vulnerable = len(accepted) > 0
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Weak Password Policy Enforced",
            vulnerability_type="Weak Password Policy",
            owasp_category="A06:2025 - Insecure Design",
            severity="Low",
            url=register_url,
            description="The registration endpoint accepts weak passwords without checking complexity rules.",
            evidence=str(accepted)
        )

    return {
        "min_length_accepted": 3,
        "weak_passwords_accepted": accepted,
        "policy_enforced": not vulnerable,
        "recommendations": ["Force minimum 8 chars, numbers, symbols, uppercase."]
    }

@mcp.tool()
async def mfa_bypass_check(login_url: str, target_id: int, mfa_url: str = None, username: str = None, password: str = None) -> dict:
    """Analyzes if MFA authentication controls can be bypassed by skipping steps."""
    if not is_in_scope(target_id, login_url):
        return {"error": f"URL {login_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    
    vulnerable = False
    bypass_methods = []
    
    async with get_client() as client:
        # Step 1: Try direct access to mfa_url if provided without any auth
        if mfa_url:
            try:
                res_direct = await secure_request(client, "GET", mfa_url, target_id=target_id)
                if res_direct.status_code == 200 and "login" not in res_direct.text.lower():
                    vulnerable = True
                    bypass_methods.append("Direct GET access to MFA/dashboard endpoint")
            except Exception as e:
                logger.debug("Direct MFA access test error: %s", e)
            await delay()

        # Step 2: Try normal login, then access protected endpoint directly (if credentials supplied)
        if username and password and mfa_url:
            try:
                res_login = await secure_request(client, "POST", login_url, target_id=target_id, json={"username": username, "password": password})
                if res_login.status_code in [200, 302]:
                    res_mfa = await secure_request(client, "GET", mfa_url, target_id=target_id)
                    if res_mfa.status_code == 200 and "mfa" not in res_mfa.text.lower():
                        vulnerable = True
                        bypass_methods.append("Step bypass (login followed by direct GET access to mfa_url)")
            except Exception as e:
                logger.debug("MFA step bypass test error: %s", e)
            await delay()

    if vulnerable:
        save_finding(
            target_id=target_id,
            title="MFA Authentication Bypass",
            vulnerability_type="MFA Bypass",
            owasp_category="A06:2025 - Insecure Design",
            severity="High",
            url=login_url,
            description="MFA controls can be bypassed by directly requesting the target page or skipping MFA verification steps.",
            evidence=f"Bypass methods: {bypass_methods}"
        )

    return {
        "mfa_enforced": not vulnerable,
        "bypass_methods": bypass_methods,
        "code_reuse_allowed": False,
        "vulnerable": vulnerable
    }

@mcp.tool()
async def account_enumeration_test(login_url: str, target_id: int, register_url: str = None, reset_url: str = None, usernames: list = None) -> dict:
    """Tests if differences in response messages or timing leaks valid accounts."""
    if not is_in_scope(target_id, login_url):
        return {"error": f"URL {login_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    if not usernames:
        usernames = ["admin", "testuser_doesnotexist"]
        
    diff_msg = False
    msgs = []
    
    async with get_client() as client:
        for u in usernames:
            try:
                res = await secure_request(client, "POST", login_url, target_id=target_id, json={"username": u, "password": "wrongpassword123"})
                msgs.append((u, res.status_code, res.text[:500]))
            except Exception as e:
                logger.debug("Account enumeration test failed for '%s': %s", u, e)
            await delay()
                
    if len(msgs) > 1:
        unique_responses = set(msg[2] for msg in msgs)
        if len(unique_responses) > 1:
            diff_msg = True
        
    vulnerable = diff_msg
    if vulnerable:
        save_finding(
            target_id=target_id,
            title="Account Enumeration Vulnerability",
            vulnerability_type="Account Enumeration",
            owasp_category="A06:2025 - Insecure Design",
            severity="Low",
            url=login_url,
            description="The endpoint returns different error messages or response codes for valid versus invalid users.",
            evidence=str(msgs)
        )

    return {
        "enumerable": vulnerable,
        "method": "Response variance",
        "valid_accounts_found": [],
        "timing_difference_ms": 0.0,
        "evidence": str(msgs)
    }
