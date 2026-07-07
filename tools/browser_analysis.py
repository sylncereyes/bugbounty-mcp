#!/usr/bin/env python3
"""
Browser Automation Tools
Uses Playwright/Chromium for target verification and false-positive prevention.
Captures request-response for HTTP-based vulnerability validation.
Supports dynamic browser detection (Chrome, Firefox, Brave, Chromium).
"""
import asyncio
import logging
import os
import shutil
import subprocess
from typing import Optional, List, Dict, Any
from mcp_instance import mcp
from tools.http_utils import validate_scope

logger = logging.getLogger("stealthvision")

# Set Playwright browsers path
os.environ.setdefault('PLAYWRIGHT_BROWSERS_PATH', os.path.expanduser('~/.cache/ms-playwright'))

# ─── Browser Detection Helpers ───────────────────────────────────────────────────

def get_system_browser_map() -> Dict[str, str]:
    """
    Detects installed browsers and returns a map of {browser_type: executable_path}.
    """
    browsers = {
        'chrome': ['google-chrome', 'google-chrome-stable', 'chrome'],
        'firefox': ['firefox', 'firefox-esr'],
        'brave': ['brave-browser', 'brave'],
        'chromium': ['chromium', 'chromium-browser'],
    }
    
    installed = {}
    for b_type, binaries in browsers.items():
        for binary in binaries:
            path = shutil.which(binary)
            if path:
                installed[b_type] = path
                break
    return installed

def detect_default_browser() -> Optional[str]:
    """
    Detects the default browser using xdg-settings (Linux/Kali).
    Returns the browser type (chrome, firefox, etc.) or None.
    """
    try:
        result = subprocess.run(['xdg-settings', 'get', 'default-web-browser'], 
                                capture_output=True, text=True, check=True)
        default = result.stdout.strip().lower()
        if 'chrome' in default: return 'chrome'
        if 'chromium' in default: return 'chromium'
        if 'firefox' in default: return 'firefox'
        if 'brave' in default: return 'brave'
    except Exception:
        pass
    return None

async def launch_dynamic_browser(p, browser_choice: Optional[str] = None, headless: bool = True):
    """
    Launches the best available browser based on choice, default, or installed list.
    Returns (browser_context, browser_name) tuple.
    """
    browser_map = get_system_browser_map()
    
    chosen_browser = None
    chosen_path = None
    
    # 1. Manual choice
    if browser_choice and browser_choice.lower() in browser_map:
        chosen_browser = browser_choice.lower()
        chosen_path = browser_map[chosen_browser]
    
    # 2. Default browser
    if not chosen_browser:
        default = detect_default_browser()
        if default and default in browser_map:
            chosen_browser = default
            chosen_path = browser_map[chosen_browser]
    
    # 3. Fallback: first installed browser
    if not chosen_browser and browser_map:
        chosen_browser = list(browser_map.keys())[0]
        chosen_path = browser_map[chosen_browser]
    
    # Launch based on type
    if chosen_browser == 'firefox':
        if chosen_path:
            browser = await p.firefox.launch(headless=headless, executable_path=chosen_path)
        else:
            browser = await p.firefox.launch(headless=headless)
    else:
        # Chrome/Chromium/Brave use chromium engine
        if chosen_path:
            browser = await p.chromium.launch(headless=headless, executable_path=chosen_path)
        else:
            # Fallback to playwright bundled
            browser = await p.chromium.launch(headless=headless)
    
    return browser, chosen_browser or 'chromium'

def get_available_browsers() -> List[str]:
    """Return list of available browser types."""
    return list(get_system_browser_map().keys())

# ─── Browser Availability Check ────────────────────────────────────────────────

async def _ensure_browser() -> bool:
    """Check if Playwright browser is available."""
    try:
        from playwright.async_api import async_playwright
        return True
    except ImportError:
        return False

def _sync_ensure_browser() -> bool:
    """Sync version for initial checks."""
    try:
        import playwright
        return True
    except ImportError:
        return False

# ══════════════════════════════════════════════════════════════════════════════════
# TOOL 0 - detect_browsers (NEW)
# ═════════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def detect_available_browsers() -> dict:
    """
    Detect installed browsers and default browser on the system.
    
    Returns:
        dict with 'installed', 'default', and 'selected_for_testing' lists
    """
    installed = get_system_browser_map()
    default = detect_default_browser()
    
    # Select best browser for testing
    selected = None
    if default and default in installed:
        selected = default
    elif installed:
        selected = list(installed.keys())[0]
    
    return {
        "installed_browsers": installed,
        "default_browser": default,
        "browser_selected_for_testing": selected,
    }

# ══════════════════════════════════════════════════════════════════════════════════
# TOOL 1 - verify_target_is_web
# ═════════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def verify_target_is_web(url: str, timeout: int = 15, browser: Optional[str] = None, target_id: Optional[int] = None) -> dict:
    """
    Verify if a target is a web application before running HTTP tests.
    
    Checks:
    - HTTP response (not a dead endpoint)
    - Content-Type: text/html (web page)
    - Returns page title, status code, and basic metadata
    
    Uses detected/default browser for accurate testing.
    
    Args:
        url: Target URL to verify
        timeout: Page load timeout in seconds
        browser: Browser choice (chrome, firefox, brave, chromium) or None for auto-detect
        target_id: Target ID for scope validation (raises ValueError if out of scope)
    """
    # Scope validation - FAIL if out of scope
    validate_scope(target_id, url)
    
    if not _sync_ensure_browser():
        return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}
    
    from playwright.async_api import async_playwright
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    try:
        async with async_playwright() as p:
            browser_inst, browser_name = await launch_dynamic_browser(p, browser_choice=browser)
            context = await browser_inst.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = await context.new_page()
            
            response = await page.goto(url, wait_until='domcontentloaded', timeout=timeout * 1000)
            
            if response is None:
                return {
                    "status": "error",
                    "url": url,
                    "error": "No response received - target may be unreachable"
                }
            
            status_code = response.status
            content_type = response.headers.get('content-type', '')
            
            # Get page title
            title = await page.title()
            
            # Get response body (truncated)
            content = await page.content()
            
            # Check if it's actually a web page
            is_web = 'text/html' in content_type or '<html' in content.lower()
            
            # Get all links as indicators (limit to 20 via Python)
            all_links = await page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
            links = all_links[:20]
            
            # Get forms (limit to 10 via Python)
            all_forms = await page.eval_on_selector_all('form', 'els => els.map(e => ({ action: e.action, method: e.method }))')
            forms = all_forms[:10]
            
            await browser_inst.close()
            
            return {
                "status": "success",
                "url": url,
                "is_web_application": is_web,
                "status_code": status_code,
                "content_type": content_type,
                "title": title,
                "content_length": len(content),
                "links_found": len(links),
                "forms_found": len(forms),
                "sample_links": links[:5],
                "sample_forms": forms[:3],
                "browser_used": browser_name,
            }
            
    except Exception as e:
        return {"status": "error", "url": url, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════════════
# TOOL 2 - browse_with_capture
# ═════════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def browse_with_capture(url: str, wait_for_selector: Optional[str] = None,
                             wait_timeout: int = 10, headless: bool = True, 
                             browser: Optional[str] = None) -> dict:
    """
    Surf target with browser and capture full request-response data.
    
    Useful for:
    - Analyzing JS-heavy SPAs
    - Capturing API endpoints called by frontend
    - Verifying dynamic behavior that scanners might miss
    - Reducing false positives by observing actual browser behavior
    
    Uses detected/default browser for accurate client-side behavior.
    """
    if not _sync_ensure_browser():
        return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}
    
    from playwright.async_api import async_playwright
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    captured_requests = []
    captured_responses = []
    
    try:
        async with async_playwright() as p:
            browser_inst, browser_name = await launch_dynamic_browser(p, browser_choice=browser, headless=headless)
            context = await browser_inst.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = await context.new_page()
            
            # Track all requests
            page.on('request', lambda r: captured_requests.append({
                'url': r.url,
                'method': r.method,
                'resource_type': r.resource_type,
                'headers': dict(r.headers),
            }))
            
            # Track all responses
            async def on_response(r):
                try:
                    body = await r.text()
                    body_preview = body[:5000] if len(body) > 5000 else body
                except Exception:
                    body_preview = "[binary/unreadable]"
                
                captured_responses.append({
                    'url': r.url,
                    'status': r.status,
                    'status_text': r.status_text or '',
                    'headers': dict(r.headers),
                    'body_preview': body_preview,
                })
            page.on('response', lambda r: asyncio.create_task(on_response(r)))
            
            response = await page.goto(url, wait_until='networkidle', timeout=wait_timeout * 1000)
            
            # Wait for specific selector if provided
            if wait_for_selector:
                try:
                    await page.wait_for_selector(wait_for_selector, timeout=5000)
                except Exception:
                    pass
            
            page_title = await page.title()
            final_url = page.url
            
            await browser_inst.close()
            
            return {
                "status": "success",
                "original_url": url,
                "final_url": final_url,
                "page_title": page_title,
                "request_count": len(captured_requests),
                "response_count": len(captured_responses),
                "requests": [r for r in captured_requests if r['resource_type'] in ['xhr', 'fetch', 'doc', 'script']],
                "responses": [r for r in captured_responses if r['status'] >= 400],
                "browser_used": browser_name,
            }
            
    except Exception as e:
        return {"status": "error", "url": url, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════════════
# TOOL 3 - intercept_and_test_endpoint
# ══════════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def intercept_and_test_endpoint(url: str, endpoint_pattern: Optional[str] = None,
                                      post_data: Optional[Dict] = None,
                                      extra_headers: Optional[Dict] = None,
                                      browser: Optional[str] = None) -> dict:
    """
    Intercept specific API endpoint calls while browsing.
    
    Use case:
    - Find hidden API endpoints in JS/frontends
    - Test GraphQL introspection without automated scanners
    - Verify specific endpoint behavior manually
    
    Uses detected/default browser for accurate behavior.
    """
    if not _sync_ensure_browser():
        return {"error": "Playwright not installed"}
    
    from playwright.async_api import async_playwright
    import re
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    intercepted = []
    
    try:
        async with async_playwright() as p:
            browser_inst, browser_name = await launch_dynamic_browser(p, browser_choice=browser, headless=True)
            context = await browser_inst.new_context()
            page = await context.new_page()
            
            if post_data:
                async def handle_route(route):
                    await route.continue_(method='POST', post_data=post_data)
                
                if endpoint_pattern:
                    pattern = re.compile(endpoint_pattern, re.IGNORECASE)
                    await context.route(f"https://{url}/**", handle_route)
            
            async def on_response(r):
                url_match = endpoint_pattern is None or re.search(endpoint_pattern, r.url, re.IGNORECASE)
                if url_match:
                    try:
                        body = await r.text()
                    except Exception:
                        body = "[binary]"
                    
                    intercepted.append({
                        'url': r.url,
                        'method': r.request.method,
                        'status': r.status,
                        'response_headers': dict(r.headers),
                        'body': body[:3000],
                        'request_headers': dict(r.request.headers),
                    })
            
            page.on('response', lambda r: asyncio.create_task(on_response(r)))
            
            await page.goto(url, wait_until='networkidle', timeout=15000)
            
            await browser_inst.close()
            
            return {
                "status": "success",
                "url": url,
                "intercepted_count": len(intercepted),
                "interceptions": intercepted,
                "browser_used": browser_name,
            }
            
    except Exception as e:
        return {"status": "error", "url": url, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════════════
# TOOL 4 - check_xss_in_browser
# ═════════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def check_xss_in_browser(url: str, param: str, payloads: Optional[List[str]] = None,
                               browser: Optional[str] = None, target_id: Optional[int] = None) -> dict:
    """
    Verify XSS vulnerability using real browser execution.
    
    This reduces false positives by:
    - Testing in actual browser context
    - Checking if payloads execute without DOM sanitization
    - Observing actual JavaScript behavior
    
    Uses detected/default browser for engine-specific testing.
    
    Args:
        url: Target URL to test (must include scheme)
        param: Parameter name to test for XSS
        payloads: Custom payloads or None for defaults
        browser: Browser choice or None for auto-detect
        target_id: Target ID for scope validation (raises ValueError if out of scope)
    """
    # Scope validation - FAIL if out of scope
    validate_scope(target_id, url)
    
    if not _sync_ensure_browser():
        return {"error": "Playwright not installed"}
    
    from playwright.async_api import async_playwright
    
    if not url.startswith(('http://', 'https://')):
        return {"error": "URL must include scheme (http:// or https://)"}
    
    default_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
    ]
    
    payloads = payloads or default_payloads
    results = []
    confirmed_xss = False
    
    try:
        async with async_playwright() as p:
            browser_inst, browser_name = await launch_dynamic_browser(p, browser_choice=browser, headless=True)
            context = await browser_inst.new_context()
            
            for payload in payloads:
                page = await context.new_page()
                
                xss_detected = False
                
                test_url = f"{url}?{param}={payload}" if '?' not in url.split('#')[0] else url.replace(f'{param}=', f'{param}={payload}')
                
                try:
                    await page.goto(test_url, wait_until='domcontentloaded', timeout=10000)
                    
                    try:
                        async with page.expect_event('dialog', timeout=2000):
                            pass
                    except Exception:
                        content = await page.content()
                        if payload in content and '<script>' in content.lower():
                            xss_detected = True
                    
                except Exception as e:
                    results.append({"payload": payload, "error": str(e)})
                    await page.close()
                    continue
                
                if xss_detected:
                    confirmed_xss = True
                
                results.append({
                    "payload": payload,
                    "url_tested": test_url,
                    "xss_likely": xss_detected,
                })
                
                await page.close()
            
            await browser_inst.close()
            
            return {
                "status": "success",
                "target": url,
                "parameter": param,
                "confirmed_xss": confirmed_xss,
                "total_payloads_tested": len(payloads),
                "results": results,
                "browser_used": browser_name,
            }
            
    except Exception as e:
        return {"status": "error", "url": url, "error": str(e)}