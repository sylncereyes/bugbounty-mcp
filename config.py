"""
AGY Bug Bounty MCP - Centralized Configuration
All tool modules should import settings from here instead of defining their own.
"""
import os
import logging
from dotenv import load_dotenv

load_dotenv()

# ─── Logging ───────────────────────────────────────────────────────────────────
import random

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    format="[%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("agy")

# ─── HTTP Request Settings ─────────────────────────────────────────────────────
DEFAULT_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "0.5"))
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))

USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.216 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/149.0.7827.45 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/148.0.0.0",
]

def get_random_user_agent():
    """Get random user agent from rotation list."""
    return random.choice(USER_AGENTS)

USER_AGENT = os.getenv("USER_AGENT") or get_random_user_agent()
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() in ("true", "1", "yes")

# ─── API Keys ──────────────────────────────────────────────────────────────────
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
INTERACTSH_SERVER = os.getenv("INTERACTSH_SERVER", "")
INTERACTSH_TOKEN = os.getenv("INTERACTSH_TOKEN", "")

# ─── MCP SSE Authentication ───────────────────────────────────────────────────
# Required when exposing SSE on 0.0.0.0. Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
MCP_API_KEY = os.getenv("MCP_API_KEY", "")

# ─── Paths ─────────────────────────────────────────────────────────────────────
REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")
DB_PATH_ENV = os.getenv("DB_PATH", "database/bugbounty.db")

# ─── Dry-Run Mode ───────────────────────────────────────────────────────────────
# dry_run=True means tools only return payloads that WOULD be sent, without actual execution
DRY_RUN = os.getenv("DRY_RUN", "true").lower() in ("true", "1", "yes")
