"""StealthVision-MCP - Advanced Subdomain Brute-force Module"""
import httpx
import concurrent.futures
import logging
from mcp_instance import mcp

logger = logging.getLogger("stealthvision")
from config import USER_AGENT, DEFAULT_TIMEOUT, get_random_user_agent

@mcp.tool()
def subdomain_bruteforce(domain: str, wordlist_path: str = "knowledge_base/seclists/Discovery/DNS/subdomains-top1million-5000.txt", 
                         limit: int = 1000, concurrency: int = 10) -> dict:
    """Brute-force subdomains using SecLists wordlist."""
    try:
        # Load wordlist
        try:
            with open(wordlist_path, 'r') as f:
                words = [w.strip() for w in f if w.strip()][:limit]
        except FileNotFoundError:
            return {"error": f"Wordlist not found: {wordlist_path}", "success": False}
        
        found = []
        ua = get_random_user_agent()
        
        def check_subdomain(sub):
            url = f"https://{sub}.{domain}"
            try:
                client = httpx.Client(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": ua}, follow_redirects=True)
                r = client.head(url)
                if r.status_code < 500:
                    return {"subdomain": f"{sub}.{domain}", "status": r.status_code}
            except Exception:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = list(executor.map(check_subdomain, words))
        
        found = [r for r in results if r]
        
        return {"found": found, "count": len(found), "wordlist_used": wordlist_path, "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}