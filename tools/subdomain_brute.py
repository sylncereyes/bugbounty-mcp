"""Subdomain brute-force module using SecLists wordlist."""
import re
import logging
import concurrent.futures
from mcp_instance import mcp
from tools.db import is_in_scope
from tools.http_utils import secure_request_sync, get_sync_client
from config import get_random_user_agent

logger = logging.getLogger("agy")

@mcp.tool()
def subdomain_bruteforce(domain: str, target_id: int, wordlist_path: str = "knowledge_base/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                         limit: int = 1000, concurrency: int = 10) -> dict:
    """Brute-force subdomains using SecLists wordlist.
    
    Args:
        domain: Target domain to enumerate subdomains for
        target_id: Target ID from database for scope validation
        wordlist_path: Path to subdomain wordlist file
        limit: Maximum number of subdomains to try
        concurrency: Thread pool size for concurrent checks
    
    Returns:
        dict with 'found' list and 'count' of discovered subdomains
    """
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
                with get_sync_client() as client:
                    r = secure_request_sync(client, "GET", url, target_id=target_id, headers={"User-Agent": ua})
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