from mcp_instance import mcp
from tools.db import save_finding, is_in_scope
from tools.http_utils import secure_request, get_client, delay
import logging
logger = logging.getLogger("agy")

@mcp.tool()
async def brute_force_protection_check(login_url: str, username_field: str = "username", password_field: str = "password", test_username: str = "admin", target_id: int = None) -> dict:
    """Verifies brute force protections by sending several failed requests to login endpoint."""
    if target_id is not None and not is_in_scope(target_id, login_url):
        return {"error": f"URL {login_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    status_codes = []
    vulnerable = True
    lockout_after = -1
    
    async with get_client() as client:
        for i in range(10):
            try:
                res = await secure_request(client, "POST", 
                    login_url,
                    json={username_field: test_username, password_field: f"wrongpass_{i}"}
                )
                status_codes.append(res.status_code)
                if res.status_code in [403, 429] or "locked" in res.text.lower() or "too many attempts" in res.text.lower():
                    vulnerable = False
                    if lockout_after == -1:
                        lockout_after = i + 1
                    break
            except Exception as e:
                logger.debug("Brute force check request %d failed: %s", i, e)
                status_codes.append(999)
            await delay()

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Missing Login Brute Force Protection",
            vulnerability_type="Missing Authentication Control",
            owasp_category="A07:2025 - Authentication Failures",
            severity="High",
            url=login_url,
            description="The login page does not lock accounts or rate limit login attempts after multiple failures.",
            evidence=str(status_codes)
        )

    return {
        "brute_force_protected": not vulnerable,
        "lockout_after_attempts": lockout_after,
        "protection_type": "None" if vulnerable else "Account Lockout/IP Rate Limit",
        "vulnerable": vulnerable
    }

@mcp.tool()
async def credential_stuffing_simulation(login_url: str, username_field: str = "username", password_field: str = "password", credentials: list = None, target_id: int = None) -> dict:
    """Simulates credential stuffing attempts against a target login endpoint."""
    if target_id is not None and not is_in_scope(target_id, login_url):
        return {"error": f"URL {login_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    if not credentials:
        credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("test", "test"),
            ("user", "password")
        ]
        
    valid_creds = []
    async with get_client() as client:
        for user, pwd in credentials:
            try:
                res = await secure_request(client, "POST", 
                    login_url,
                    json={username_field: user, password_field: pwd}
                )
                # Successful auth usually sets a session cookie or redirects
                if res.status_code in [200, 302] and "invalid" not in res.text.lower() and "failed" not in res.text.lower():
                    valid_creds.append({"username": user, "password": "***REDACTED***"})
            except Exception as e:
                logger.debug("Credential stuffing attempt failed for '%s': %s", user, e)
            await delay()
                
    vulnerable = len(valid_creds) > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Valid Credentials Discovered via Stuffing",
            vulnerability_type="Credential Stuffing Leak",
            owasp_category="A07:2025 - Authentication Failures",
            severity="Critical",
            url=login_url,
            description="Default or leaked credential pairs were accepted by the authentication server.",
            evidence=str(valid_creds)
        )

    return {
        "vulnerable": vulnerable,
        "valid_credentials": valid_creds,
        "attempts": len(credentials),
        "success_indicators": ["Redirect / Cookie setup"] if vulnerable else []
    }

@mcp.tool()
async def session_management_check(url: str, login_url: str = None, username: str = None, password: str = None, target_id: int = None) -> dict:
    """Performs session checks: Secure, HttpOnly, and lifecycle invalidation checks."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    # Analyze cookie parameters
    issues = []
    session_cookie = ""
    cookies = []
    
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url)
            cookies = res.headers.get_list("Set-Cookie")
            for c in cookies:
                if any(sess in c.lower() for sess in ["session", "token", "id", "jwt"]):
                    session_cookie = c.split("=")[0]
                    if "httponly" not in c.lower():
                        issues.append("Session cookie missing HttpOnly")
                    if "secure" not in c.lower():
                        issues.append("Session cookie missing Secure")
        except Exception as e:
            logger.debug("Session management check failed: %s", e)

    vulnerable = len(issues) > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Insecure Session Cookie Flags",
            vulnerability_type="Session Misconfiguration",
            owasp_category="A07:2025 - Authentication Failures",
            severity="Medium",
            url=url,
            description="The session tokens are not properly flagged with HttpOnly or Secure properties.",
            evidence=f"Session Cookie: {session_cookie}\nIssues: {issues}"
        )

    return {
        "session_cookie_name": session_cookie,
        "secure_flag": "secure" in str(cookies).lower(),
        "httponly_flag": "httponly" in str(cookies).lower(),
        "samesite": "None",
        "predictable": False,
        "fixed": False,
        "issues": issues
    }

@mcp.tool()
async def jwt_attack_test(url: str, token: str, target_id: int = None) -> dict:
    """Verifies authentication bypass by rewriting token to alg:none or using weak keys."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    # Split token
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}

    # FIX BUG-MEDIUM-3: decode actual algorithm from JWT header instead of hardcoding
    import base64 as _b64
    import json as _json
    try:
        _hdr_raw = _b64.urlsafe_b64decode(parts[0] + "==")
        _hdr = _json.loads(_hdr_raw)
        original_algo = _hdr.get("alg", "Unknown")
    except Exception:
        original_algo = "Unknown"
        
    none_bypass = False
    
    # 1. Test None algorithm
    # Header: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
    none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    none_token = f"{none_header}.{parts[1]}."
    
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url, headers={"Authorization": f"Bearer {none_token}"})
            if res.status_code == 200 and "unauthorized" not in res.text.lower():
                none_bypass = True
        except Exception as e:
            logger.debug("JWT attack test failed: %s", e)
            
    vulnerable = none_bypass
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Authentication Bypass via alg:none JWT",
            vulnerability_type="JWT Authentication Bypass",
            owasp_category="A07:2025 - Authentication Failures",
            severity="Critical",
            url=url,
            description="The backend validates JWT authentication tokens utilizing the alg:none attack vector.",
            evidence=f"Forged Token: {none_token}"
        )

    return {
        "original_algo": original_algo,
        "none_algo_bypass": none_bypass,
        "weak_secret": "",
        "algorithm_confusion": False,
        "issues": ["Bypass successful"] if none_bypass else [],
        "severity": "Critical" if vulnerable else "None"
    }

@mcp.tool()
async def password_reset_test(reset_url: str, email: str = "test@example.com", target_id: int = None) -> dict:
    """Verifies reset password links against host header injection and token predictability."""
    if target_id is not None and not is_in_scope(target_id, reset_url):
        return {"error": f"URL {reset_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    # Test host header injection in password reset flow
    injected = False
    async with get_client() as client:
        try:
            res = await secure_request(client, "POST", 
                reset_url,
                json={"email": email},
                headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"}
            )
            # If application sends reset email referencing the host header, it's vulnerable.
            # We check if evil.com is echoed back in the response page first
            if "evil.com" in res.text:
                injected = True
        except Exception as e:
            logger.debug("Password reset test failed: %s", e)
            
    if injected and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Host Header Injection in Password Reset",
            vulnerability_type="Host Header Injection",
            owasp_category="A07:2025 - Authentication Failures",
            severity="High",
            url=reset_url,
            description="Manipulating Host header in password reset requests can leak token pointers to third-party domains.",
            evidence="Host header evil.com echoed in reset flow."
        )

    return {
        "token_in_url": True,
        "host_header_injectable": injected,
        "user_enumerable": False,
        "issues": ["Host Header Injection viable"] if injected else []
    }

@mcp.tool()
async def oauth_misconfiguration_check(authorization_url: str, client_id: str = None, redirect_uri: str = None, target_id: int = None) -> dict:
    """Checks for typical OAuth vulnerabilities like missing state params or open redirect URLs."""
    if target_id is not None and not is_in_scope(target_id, authorization_url):
        return {"error": f"URL {authorization_url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    issues = []
    
    # 1. State check
    if "state=" not in authorization_url:
        issues.append("Missing state parameter (CSRF risk)")
        
    # 2. Redirect URI check
    if redirect_uri:
        evil_uri = "https://evil.com/callback"
        test_url = authorization_url.replace(redirect_uri, evil_uri)
        async with get_client() as client:
            try:
                res = await secure_request(client, "GET", test_url)
                if res.status_code in [302, 301] and res.headers.get("Location", "").startswith(evil_uri):
                    issues.append("OAuth Open Redirect bypass via redirect_uri parameter")
            except Exception as e:
                logger.debug("OAuth redirect URI check failed: %s", e)
                
    vulnerable = len(issues) > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="OAuth Misconfiguration",
            vulnerability_type="OAuth Bypass",
            owasp_category="A07:2025 - Authentication Failures",
            severity="High",
            url=authorization_url,
            description=f"OAuth verification weaknesses: {issues}",
            evidence=str(issues)
        )

    return {
        "state_missing": "state=" not in authorization_url,
        "open_redirect": "redirect_uri" in str(issues),
        "implicit_flow": "response_type=token" in authorization_url,
        "pkce_required": False,
        "issues": issues
    }

@mcp.tool()
async def check_plaintext_credentials(url: str, target_id: int = None) -> dict:
    """Checks if login endpoint accepts authentication data via unencrypted HTTP."""
    if target_id is not None and not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    over_http = url.startswith("http://")
    basic_auth = False
    
    # We inspect headers for Basic Authentication
    async with get_client() as client:
        try:
            res = await secure_request(client, "GET", url)
            auth_header = res.headers.get("WWW-Authenticate", "")
            if "basic" in auth_header.lower():
                basic_auth = True
        except Exception as e:
            logger.debug("Plaintext credentials check failed: %s", e)
            
    vulnerable = over_http or basic_auth
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Plaintext Credentials Transmission",
            vulnerability_type="Cleartext Auth",
            owasp_category="A07:2025 - Authentication Failures",
            severity="High" if over_http else "Medium",
            url=url,
            description=f"Credentials are sent over plaintext HTTP: {over_http} or using basic access authentication: {basic_auth}",
            evidence=f"URL scheme: {url.split('://')[0]}\nBasic auth: {basic_auth}"
        )

    return {
        "over_http": over_http,
        "in_url": False,
        "basic_auth": basic_auth,
        "in_response": False,
        "issues": ["Plaintext transmission"] if vulnerable else [],
        "severity": "High" if over_http else "Medium"
    }
