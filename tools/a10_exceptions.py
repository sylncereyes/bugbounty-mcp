import time
from mcp_instance import mcp
from tools.db import save_finding, is_in_scope
from tools.http_utils import secure_request, get_client, delay
import logging
logger = logging.getLogger("agy")

@mcp.tool()
async def error_handling_analysis(url: str, target_id: int)) ->:
    """Sends invalid input structures to check if exception details are handled gracefully or verbose details leakage occurs."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    invalid_inputs = [
        {"id": "A" * 5000},
        {"id": "\x00"},
        {"id": -1}
    ]
    verbose_errors = []
    consistent = True
    first_status = None
    
    async with get_client() as client:
        for inp in invalid_inputs:
            try:
                res = await secure_request(client, "GET", url, params=inp)
                if first_status is None:
                    first_status = res.status_code
                elif first_status != res.status_code:
                    consistent = False
                    
                body = res.text.lower()
                if any(x in body for x in ["exception", "stack trace", "traceback", "fatal error"]):
                    verbose_errors.append({"input": inp, "status": res.status_code, "evidence": "Exception keywords detected"})
            except Exception as e:
                verbose_errors.append({"input": inp, "status": 999, "evidence": str(e)})
            await delay()

    vulnerable = len(verbose_errors) > 0
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Verbose Exception Disclosures",
            vulnerability_type="Verbose Exception Handling",
            owasp_category="A10:2025 - Mishandling of Exceptional Conditions",
            severity="Medium",
            url=url,
            description="The application displays internal stack trace or raw exception outputs upon receiving malformed input structures.",
            evidence=str(verbose_errors)
        )

    return {
        "consistent_errors": consistent,
        "verbose_errors": verbose_errors,
        "stack_traces_exposed": [v for v in verbose_errors if "Exception" in v["evidence"]],
        "recommendations": ["Catch all unhandled exceptions globally and present simple generic error notices to frontend users."]
    }

@mcp.tool()
async def timing_attack_check(url: str, params: dict, valid_value: str, invalid_value: str, param_name: str, target_id: int)) ->:
    """Measures response delay differences when sending valid vs invalid inputs to check for timing leaks."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    valid_times = []
    invalid_times = []
    
    async with get_client() as client:
        # 1. Test valid values
        for _ in range(5):
            test_params = params.copy()
            test_params[param_name] = valid_value
            try:
                start = time.time()
                await secure_request(client, "GET", url, params=test_params)
                valid_times.append(time.time() - start)
            except Exception as e:
                logger.debug("Error during valid timing test at %s: %s", url, e)
            await delay()
                
        # 2. Test invalid values
        for _ in range(5):
            test_params = params.copy()
            test_params[param_name] = invalid_value
            try:
                start = time.time()
                await secure_request(client, "GET", url, params=test_params)
                invalid_times.append(time.time() - start)
            except Exception as e:
                logger.debug("Error during invalid timing test at %s: %s", url, e)
            await delay()
                
    if not valid_times or not invalid_times:
        return {"error": "Failed to collect sufficient timing statistics due to request errors."}
        
    avg_valid = sum(valid_times) / len(valid_times)
    avg_invalid = sum(invalid_times) / len(invalid_times)
    diff = abs(avg_valid - avg_invalid) * 1000  # in ms
    
    # Timing difference > 100ms indicates potential vulnerability
    vulnerable = diff > 100
    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Timing Attack Information Disclosure",
            vulnerability_type="Timing Leak",
            owasp_category="A10:2025 - Mishandling of Exceptional Conditions",
            severity="Medium",
            url=url,
            description="A significant response timing variance indicates execution flow differences based on input value validity.",
            evidence=f"Avg Valid: {avg_valid*1000:.2f}ms, Avg Invalid: {avg_invalid*1000:.2f}ms, Diff: {diff:.2f}ms"
        )

    return {
        "vulnerable": vulnerable,
        "avg_valid_time_ms": avg_valid * 1000,
        "avg_invalid_time_ms": avg_invalid * 1000,
        "timing_difference_ms": diff,
        "severity": "Medium" if vulnerable else "None"
    }

@mcp.tool()
async def check_fail_open(url: str, auth_data: dict, target_id: int)) ->:
    """Attempts login authentication by forcing malformed payload configurations (null/empty values) to check for fail-open authorization logic."""
    if not is_in_scope(target_id, url):
        return {"error": f"URL {url} is out of scope for target {target_id}. Scan aborted.", "vulnerable": False}
    vulnerable = False
    status_code = None
    
    # Try sending empty password
    test_data = auth_data.copy()
    for k in test_data.keys():
        if "pass" in k.lower():
            test_data[k] = None # or ""
            
    async with get_client() as client:
        try:
            res = await secure_request(client, "POST", url, json=test_data)
            status_code = res.status_code
            if res.status_code == 200 and "unauthorized" not in res.text.lower() and "invalid" not in res.text.lower():
                vulnerable = True
        except Exception as e:
            logger.debug("Error checking fail-open at %s: %s", url, e)

    if vulnerable and target_id is not None:
        save_finding(
            target_id=target_id,
            title="Fail-Open Authentication Vulnerability",
            vulnerability_type="Fail Open Auth",
            owasp_category="A10:2025 - Mishandling of Exceptional Conditions",
            severity="High",
            url=url,
            description="The authentication filter fails open when null/empty credentials are provided, permitting unauthorized logins.",
            evidence="Authenticated with Null password parameter."
        )

    return {
        "vulnerable": vulnerable,
        "status_code": status_code,
        "evidence": "Fail open behavior verified" if vulnerable else "Authorization properly locked"
    }

@mcp.tool()
async def exception_information_disclosure(url: str, target_id: int)) ->:
    """Checks for verbose system framework information leaking out in exceptions."""
    # Simply calls error_handling_analysis
    res = await error_handling_analysis(url, target_id)
    return {
        "exposed": len(res.get("verbose_errors", [])) > 0,
        "details": res.get("verbose_errors", [])
    }
